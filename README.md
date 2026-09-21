# LinkedIn OAuth + MCP Publisher

This service keeps the existing LinkedIn OAuth flow and `/publish` API, and adds a protected Streamable HTTP MCP endpoint at `/mcp`.

## Responsibilities

ChatGPT remains responsible for finding/reading the article, writing the post, generating the related image, and getting explicit approval.

This server is only responsible for the external LinkedIn action:

- authenticate incoming MCP calls with `MCP_API_KEY`
- use the stored LinkedIn OAuth token
- optionally upload an already-generated image to LinkedIn
- create the approved LinkedIn post
- return the LinkedIn post ID
- prevent duplicate posts when the same `idempotency_key` is retried

## Render environment variables

Keep your existing LinkedIn variables and add:

```env
MCP_API_KEY=<long-random-secret>
```

There is intentionally **no OpenAI API key** in this service.

## MCP endpoint

```text
POST https://YOUR-RENDER-DOMAIN/mcp
Authorization: Bearer <MCP_API_KEY>
Content-Type: application/json
```

The MCP tool is:

`publish_linkedin_post`

Inputs:

- `text` - exact approved post
- `idempotency_key` - stable unique key for the post
- `image_base64` - optional already-generated image
- `image_mime_type` - optional image MIME type
- `image_alt_text` - optional alt text

## Existing endpoints

- `GET /auth/linkedin`
- `GET /auth/linkedin/callback`
- `GET /status` (Bearer `PUBLISH_API_KEY`)
- `POST /publish` (Bearer `PUBLISH_API_KEY`)
- `POST /mcp` (Bearer `MCP_API_KEY`)

## Local run

```bash
npm install
npm start
```

## Important

The service does not call ChatGPT's image generation. The image must already exist before the MCP publish call. LinkedIn's current Images API is used to initialize and upload the image before creating the post.
