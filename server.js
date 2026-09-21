import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

dotenv.config();

const app = express();
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || "15mb" }));

const PORT = process.env.PORT || 3000;
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI;
const DATA_DIR = path.join(process.cwd(), "data");
const TOKEN_FILE = path.join(DATA_DIR, "linkedin-token.json");
const IDEMPOTENCY_FILE = path.join(DATA_DIR, "published-posts.json");

const oauthStates = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

function saveToken(token) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${TOKEN_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(token, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, TOKEN_FILE);
}

function loadToken() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  } catch {
    return null;
  }
}

function loadIdempotencyStore() {
  try {
    return JSON.parse(fs.readFileSync(IDEMPOTENCY_FILE, "utf8"));
  } catch {
    return {};
  }
}

function saveIdempotency(key, value) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const store = loadIdempotencyStore();
  store[key] = value;
  const tmp = `${IDEMPOTENCY_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, IDEMPOTENCY_FILE);
}

function requireApiKey(req, res, next) {
  const expected = process.env.PUBLISH_API_KEY;
  if (!expected || req.headers.authorization !== `Bearer ${expected}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function requireMcpApiKey(req, res, next) {
  const expected = process.env.MCP_API_KEY;
  if (!expected || req.headers.authorization !== `Bearer ${expected}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

async function introspectToken(accessToken) {
  const body = new URLSearchParams({
    client_id: process.env.LINKEDIN_CLIENT_ID,
    client_secret: process.env.LINKEDIN_CLIENT_SECRET,
    token: accessToken
  });

  const response = await fetch("https://www.linkedin.com/oauth/v2/introspectToken", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await response.json().catch(() => ({}));
  return { response, data };
}

async function getLinkedInUser(accessToken) {
  const response = await fetch("https://api.linkedin.com/v2/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

function linkedInHeaders(accessToken, extra = {}) {
  return {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    "X-Restli-Protocol-Version": "2.0.0",
    "LinkedIn-Version": process.env.LINKEDIN_VERSION || "202606",
    ...extra
  };
}

async function publishTextPost(text, idempotencyKey = null) {
  const token = loadToken();
  if (!token?.access_token) throw new Error("LinkedIn is not connected.");
  if (!token.person_urn) throw new Error("LinkedIn member identity is missing. Re-authorize LinkedIn.");

  if (idempotencyKey) {
    const previous = loadIdempotencyStore()[idempotencyKey];
    if (previous?.published) return { ...previous, duplicate_prevented: true };
  }

  const inspection = await introspectToken(token.access_token);
  if (!inspection.response.ok || inspection.data.active !== true) {
    const error = new Error("LinkedIn token is not active");
    error.status = 401;
    error.details = inspection.data;
    throw error;
  }

  const response = await fetch("https://api.linkedin.com/rest/posts", {
    method: "POST",
    headers: linkedInHeaders(token.access_token),
    body: JSON.stringify({
      author: token.person_urn,
      commentary: text,
      visibility: "PUBLIC",
      distribution: {
        feedDistribution: "MAIN_FEED",
        targetEntities: [],
        thirdPartyDistributionChannels: []
      },
      lifecycleState: "PUBLISHED",
      isReshareDisabledByAuthor: false
    })
  });

  const data = await response.text();
  if (!response.ok) {
    const error = new Error("LinkedIn publish failed");
    error.status = response.status;
    error.details = data;
    throw error;
  }

  const result = {
    published: true,
    linkedin_response: data || null,
    post_id: response.headers.get("x-restli-id") || null
  };

  if (idempotencyKey) saveIdempotency(idempotencyKey, result);
  return result;
}

async function uploadImageAndPublish(text, imageBase64, mimeType, altText, idempotencyKey = null) {
  const token = loadToken();
  if (!token?.access_token) throw new Error("LinkedIn is not connected.");
  if (!token.person_urn) throw new Error("LinkedIn member identity is missing. Re-authorize LinkedIn.");

  if (idempotencyKey) {
    const previous = loadIdempotencyStore()[idempotencyKey];
    if (previous?.published) return { ...previous, duplicate_prevented: true };
  }

  const inspection = await introspectToken(token.access_token);
  if (!inspection.response.ok || inspection.data.active !== true) {
    const error = new Error("LinkedIn token is not active");
    error.status = 401;
    error.details = inspection.data;
    throw error;
  }

  const rawBase64 = imageBase64.replace(/^data:[^;]+;base64,/, "");
  const imageBuffer = Buffer.from(rawBase64, "base64");
  if (!imageBuffer.length) throw new Error("Invalid image data.");

  const initResponse = await fetch("https://api.linkedin.com/rest/images?action=initializeUpload", {
    method: "POST",
    headers: linkedInHeaders(token.access_token),
    body: JSON.stringify({ initializeUploadRequest: { owner: token.person_urn } })
  });

  const initData = await initResponse.json().catch(() => ({}));
  if (!initResponse.ok || !initData.value?.uploadUrl || !initData.value?.image) {
    const error = new Error("LinkedIn image upload initialization failed");
    error.status = initResponse.status;
    error.details = initData;
    throw error;
  }

  const uploadResponse = await fetch(initData.value.uploadUrl, {
    method: "PUT",
    headers: { "Content-Type": mimeType || "image/png" },
    body: imageBuffer
  });

  if (!uploadResponse.ok) {
    const body = await uploadResponse.text().catch(() => "");
    const error = new Error("LinkedIn image upload failed");
    error.status = uploadResponse.status;
    error.details = body;
    throw error;
  }

  const imageUrn = initData.value.image;

  const postResponse = await fetch("https://api.linkedin.com/rest/posts", {
    method: "POST",
    headers: linkedInHeaders(token.access_token),
    body: JSON.stringify({
      author: token.person_urn,
      commentary: text,
      visibility: "PUBLIC",
      distribution: {
        feedDistribution: "MAIN_FEED",
        targetEntities: [],
        thirdPartyDistributionChannels: []
      },
      content: {
        media: {
          altText: altText || "Related technical illustration",
          id: imageUrn
        }
      },
      lifecycleState: "PUBLISHED",
      isReshareDisabledByAuthor: false
    })
  });

  const postData = await postResponse.text();
  if (!postResponse.ok) {
    const error = new Error("LinkedIn image post failed");
    error.status = postResponse.status;
    error.details = postData;
    throw error;
  }

  const result = {
    published: true,
    image_uploaded: true,
    image_urn: imageUrn,
    linkedin_response: postData || null,
    post_id: postResponse.headers.get("x-restli-id") || null
  };

  if (idempotencyKey) saveIdempotency(idempotencyKey, result);
  return result;
}

app.get("/", (_req, res) => {
  res.send("LinkedIn OAuth service is running.");
});

app.get("/auth/linkedin", (_req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  oauthStates.set(state, Date.now() + STATE_TTL_MS);
  for (const [key, expiresAt] of oauthStates) {
    if (expiresAt < Date.now()) oauthStates.delete(key);
  }

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,
    scope: "openid profile w_member_social"
  });

  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get("/auth/linkedin/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;
  if (error) return res.status(400).send(`LinkedIn authorization failed: ${error_description || error}`);
  if (!code) return res.status(400).send("Missing authorization code.");

  const stateExpiresAt = state ? oauthStates.get(state) : null;
  if (!stateExpiresAt || stateExpiresAt < Date.now()) {
    return res.status(400).send("Invalid or expired OAuth state. Start authorization again.");
  }
  oauthStates.delete(state);

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: process.env.LINKEDIN_CLIENT_ID,
      client_secret: process.env.LINKEDIN_CLIENT_SECRET,
      redirect_uri: REDIRECT_URI
    });

    const response = await fetch("https://www.linkedin.com/oauth/v2/accessToken", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok || !data.access_token) {
      return res.status(400).json({ error: "Token exchange failed", details: data });
    }

    const inspection = await introspectToken(data.access_token);
    if (!inspection.response.ok || inspection.data.active !== true) {
      return res.status(400).json({ error: "LinkedIn issued a token that is not active" });
    }

    const user = await getLinkedInUser(data.access_token);
    if (!user.response.ok || !user.data.sub) {
      return res.status(400).json({
        error: "Could not determine LinkedIn member ID",
        details: user.data,
        hint: "Enable Sign In with LinkedIn using OpenID Connect and authorize again."
      });
    }

    saveToken({
      access_token: data.access_token,
      expires_in: data.expires_in ?? null,
      obtained_at: Date.now(),
      person_urn: `urn:li:person:${user.data.sub}`,
      linkedin_scope: inspection.data.scope ?? null,
      linkedin_created_at: inspection.data.created_at ?? null,
      linkedin_expires_at: inspection.data.expires_at ?? null
    });

    res.send("<h2>LinkedIn connected successfully.</h2><p>You can close this tab.</p>");
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth callback failed.");
  }
});

app.get("/status", requireApiKey, async (_req, res) => {
  const token = loadToken();
  if (!token?.access_token) return res.json({ connected: false });

  try {
    const inspection = await introspectToken(token.access_token);
    res.json({
      connected: inspection.data.active === true,
      token_status: inspection.data.status ?? "unknown",
      scope: inspection.data.scope ?? token.linkedin_scope ?? null,
      created_at: inspection.data.created_at ?? token.linkedin_created_at ?? null,
      expires_at: inspection.data.expires_at ?? token.linkedin_expires_at ?? null,
      person_urn_configured: Boolean(token.person_urn)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not inspect LinkedIn token." });
  }
});

app.post("/publish", requireApiKey, async (req, res) => {
  const { text, idempotency_key: idempotencyKey } = req.body;
  if (!text || typeof text !== "string") return res.status(400).json({ error: "text is required." });

  try {
    const result = await publishTextPost(text, idempotencyKey || null);
    res.status(201).json(result);
  } catch (err) {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message, details: err.details || null });
  }
});

// ---- MCP ----
const mcpServer = new McpServer({ name: "linkedin-publisher", version: "1.0.0" });

mcpServer.tool(
  "linkedin_status",
  "Check whether the LinkedIn account connected to this service is active.",
  {},
  async () => {
    const token = loadToken();
    if (!token?.access_token) {
      return { content: [{ type: "text", text: JSON.stringify({ connected: false }) }] };
    }

    const inspection = await introspectToken(token.access_token);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          connected: inspection.data.active === true,
          token_status: inspection.data.status ?? "unknown",
          person_urn_configured: Boolean(token.person_urn)
        })
      }]
    };
  }
);

mcpServer.tool(
  "publish_linkedin_post",
  "Publish already-approved text to the authenticated LinkedIn member. Optionally upload an already-generated image supplied as base64 data and attach it to the post. This tool does not generate or rewrite content.",
  {
    text: z.string().min(1).describe("The exact approved LinkedIn post text."),
    idempotency_key: z.string().min(1).describe("Stable unique key for this post; reuse the same key on retries."),
    image_base64: z.string().optional().describe("Optional base64-encoded image, including or excluding a data URL prefix."),
    image_mime_type: z.string().optional().default("image/png").describe("Image MIME type, e.g. image/png or image/jpeg."),
    image_alt_text: z.string().optional().describe("Accessible alt text for the image.")
  },
  async ({ text, idempotency_key, image_base64, image_mime_type, image_alt_text }) => {
    try {
      const result = image_base64
        ? await uploadImageAndPublish(text, image_base64, image_mime_type, image_alt_text, idempotency_key)
        : await publishTextPost(text, idempotency_key);

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    } catch (err) {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify({ error: err.message, details: err.details || null }) }]
      };
    }
  }
);

// Stateless Streamable HTTP MCP endpoint. Each request gets a fresh transport.
app.post("/mcp", requireMcpApiKey, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());

  try {
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP request failed:", err);
    if (!res.headersSent) res.status(500).json({ error: "MCP request failed" });
  }
});

app.listen(PORT, () => {
  console.log(`LinkedIn OAuth + MCP service listening on ${PORT}`);
});
