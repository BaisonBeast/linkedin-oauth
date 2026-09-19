import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI;
const DATA_DIR = path.join(process.cwd(), "data");
const TOKEN_FILE = path.join(DATA_DIR, "linkedin-token.json");

// OAuth state is kept in memory because this is a single-user private service.
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

function requireApiKey(req, res, next) {
  const expected = process.env.PUBLISH_API_KEY;
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

  const response = await fetch(
    "https://www.linkedin.com/oauth/v2/introspectToken",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    }
  );

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

app.get("/", (_req, res) => {
  res.send("LinkedIn OAuth service is running.");
});

app.get("/auth/linkedin", (_req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  oauthStates.set(state, Date.now() + STATE_TTL_MS);

  // Remove expired states.
  for (const [key, expiresAt] of oauthStates) {
    if (expiresAt < Date.now()) oauthStates.delete(key);
  }

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,
    // openid/profile provide the authenticated member ID through /v2/userinfo.
    // w_member_social permits creating posts for that member.
    scope: "openid profile w_member_social"
  });

  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get("/auth/linkedin/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(
      `LinkedIn authorization failed: ${error_description || error}`
    );
  }

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

    const response = await fetch(
      "https://www.linkedin.com/oauth/v2/accessToken",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok || !data.access_token) {
      return res.status(400).json({
        error: "Token exchange failed",
        details: data
      });
    }

    // Immediately verify the token LinkedIn just issued.
    const inspection = await introspectToken(data.access_token);

    if (!inspection.response.ok || inspection.data.active !== true) {
      console.error("New LinkedIn token is not active:", inspection.data);
      return res.status(400).json({
        error: "LinkedIn issued a token that is not active",
        token_status: inspection.data.status || "unknown"
      });
    }

    // Get the authenticated member's OIDC subject. LinkedIn's docs expose
    // this through /v2/userinfo when openid/profile are granted.
    const user = await getLinkedInUser(data.access_token);

    if (!user.response.ok || !user.data.sub) {
      console.error("LinkedIn userinfo failed:", user.data);
      return res.status(400).json({
        error: "Could not determine LinkedIn member ID",
        details: user.data,
        hint: "Enable the 'Sign In with LinkedIn using OpenID Connect' product for this app, then authorize again."
      });
    }

    const personUrn = `urn:li:person:${user.data.sub}`;

    // Replace the old token completely.
    saveToken({
      access_token: data.access_token,
      expires_in: data.expires_in ?? null,
      obtained_at: Date.now(),
      person_urn: personUrn,
      linkedin_scope: inspection.data.scope ?? null,
      linkedin_created_at: inspection.data.created_at ?? null,
      linkedin_expires_at: inspection.data.expires_at ?? null
    });

    res.send(`
      <h2>LinkedIn connected successfully.</h2>
      <p>Token is active and the member identity was verified.</p>
      <p>You can close this tab.</p>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth callback failed.");
  }
});

app.get("/status", requireApiKey, async (_req, res) => {
  const token = loadToken();

  if (!token?.access_token) {
    return res.json({ connected: false });
  }

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
  const token = loadToken();

  if (!token?.access_token) {
    return res.status(409).json({ error: "LinkedIn is not connected." });
  }

  const { text } = req.body;

  if (!text || typeof text !== "string") {
    return res.status(400).json({ error: "text is required." });
  }

  if (!token.person_urn) {
    return res.status(409).json({
      error: "LinkedIn member identity is missing. Re-authorize LinkedIn."
    });
  }

  try {
    // Check the token before attempting to publish so revoked/expired tokens
    // produce a clear diagnostic.
    const inspection = await introspectToken(token.access_token);

    if (!inspection.response.ok || inspection.data.active !== true) {
      return res.status(401).json({
        error: "LinkedIn token is not active",
        token_status: inspection.data.status ?? "unknown"
      });
    }

    const response = await fetch("https://api.linkedin.com/rest/posts", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
        "X-Restli-Protocol-Version": "2.0.0",
        // Use the latest version you have configured/supported by your app.
        "LinkedIn-Version": process.env.LINKEDIN_VERSION || "202606"
      },
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
      return res.status(response.status).json({
        error: "LinkedIn publish failed",
        details: data
      });
    }

    res.status(201).json({
      published: true,
      linkedin_response: data || null,
      post_id: response.headers.get("x-restli-id") || null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Publish request failed." });
  }
});

app.listen(PORT, () => {
  console.log(`LinkedIn OAuth service listening on ${PORT}`);
});
