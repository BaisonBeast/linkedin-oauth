# LinkedIn OAuth Service

Tiny Node/Express service for connecting a personal LinkedIn member account and publishing approved posts.

## Deploy on Render

Create a **Web Service** from this folder.

Build command:
```bash
npm install
```

Start command:
```bash
npm start
```

Add these environment variables in Render:
- `LINKEDIN_CLIENT_ID`
- `LINKEDIN_CLIENT_SECRET`
- `BASE_URL`
- `LINKEDIN_REDIRECT_URI`
- `PUBLISH_API_KEY`

Do not commit `.env` or the LinkedIn Client Secret.

## LinkedIn Developer Portal

After Render gives you a URL such as:
`https://linkedin-oauth-xxxx.onrender.com`

Set:

`BASE_URL=https://linkedin-oauth-xxxx.onrender.com`

`LINKEDIN_REDIRECT_URI=https://linkedin-oauth-xxxx.onrender.com/auth/linkedin/callback`

Then add that exact redirect URL under your LinkedIn app's Auth settings.

Open:
`https://linkedin-oauth-xxxx.onrender.com/auth/linkedin`

Sign in with the **personal LinkedIn account that should publish the posts** and approve the requested permission.

## Test

Check:
`GET /status` with:
`Authorization: Bearer YOUR_PUBLISH_API_KEY`

Publish:
`POST /publish`
with JSON:
`{"text":"Your approved LinkedIn post"}`

and the same Authorization header.

## Important

The service is deliberately small. For production use, replace the local token file with persistent encrypted storage because Render's local filesystem is not durable across all redeploy/restart scenarios.
