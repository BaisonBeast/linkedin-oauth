import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI;
const DATA_DIR = path.join(process.cwd(), "data");
const TOKEN_FILE = path.join(DATA_DIR, "linkedin-token.json");

if (!BASE_URL || !REDIRECT_URI || !process.env.LINKEDIN_CLIENT_ID ||
    !process.env.LINKEDIN_CLIENT_SECRET || !process.env.PUBLISH_API_KEY) {
  console.warn("Missing required environment variables.");
}

function saveToken(token) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(token, null, 2), { mode: 0o600 });
}

function loadToken() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  } catch {
    return null;
  }
}

function requireApiKey(req, res, next) {
  if (req.headers.authorization !== `Bearer ${process.env.PUBLISH_API_KEY}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/", (_req, res) => {
  res.send("LinkedIn OAuth service is running.");
});

app.get("/auth/linkedin", (_req, res) => {
  const state = crypto.randomBytes(24).toString("hex");

  // For this small private service, state is returned through a short-lived cookie.
  res.cookie?.("linkedin_oauth_state", state, { httpOnly: true, secure: true, sameSite: "lax" });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,
    scope: "w_member_social"
  });

  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get("/auth/linkedin/callback", async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`LinkedIn authorization failed: ${error_description || error}`);
  }

  if (!code) return res.status(400).send("Missing authorization code.");

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

    const data = await response.json();

    if (!response.ok) {
      return res.status(400).json({ error: "Token exchange failed", details: data });
    }

    saveToken({
      access_token: data.access_token,
      expires_in: data.expires_in,
      obtained_at: Date.now()
    });

    res.send(`
      <h2>LinkedIn connected successfully.</h2>
      <p>You can close this tab.</p>
      <p>The account you authorized can now be used for publishing.</p>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth callback failed.");
  }
});

app.get("/status", requireApiKey, (_req, res) => {
  const token = loadToken();
  res.json({
    connected: Boolean(token?.access_token),
    obtained_at: token?.obtained_at ?? null,
    expires_in: token?.expires_in ?? null
  });
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

  try {
    // LinkedIn's current REST Posts API uses the /rest/posts endpoint.
    // The author is the authenticated member ("me").
    const response = await fetch("https://api.linkedin.com/rest/posts", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
        "X-Restli-Protocol-Version": "2.0.0",
        "LinkedIn-Version": "202601",
        "X-Restli-Method": "CREATE"
      },
      body: JSON.stringify({
        author: "urn:li:person:me",
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

    res.json({ published: true, linkedin_response: data || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Publish request failed." });
  }
});

app.listen(PORT, () => {
  console.log(`LinkedIn OAuth service listening on ${PORT}`);
});
