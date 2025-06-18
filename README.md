# GitHub OAuth Provider

This github oauth client-provider uses the client's domain name as the client_id and automatically derives the redirect_uri from it (e.g., `https://example.com/callback`), eliminating the need for client registration while maintaining security through domain validation.

[![](https://b.lmpify.com/Initial_prompt)](https://lmpify.com/httpsuithubcomj-uiq7t40)

## Setup

1. Installation:

```
npm i simplerauth-github-provider
```

2. Set environment variables:

   - `GITHUB_CLIENT_ID`: Your GitHub OAuth app client ID
   - `GITHUB_CLIENT_SECRET`: Your GitHub OAuth app client secret

3. Add to your worker:

```typescript
import { handleOAuth, getAccessToken } from "simplerauth-github-provider";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Check if user is authenticated
    const accessToken = getAccessToken(request);
    if (!accessToken) {
      return Response.redirect(
        "/authorize?redirect_to=" + encodeURIComponent(request.url),
      );
    }

    // Your app logic here
    return new Response("Hello authenticated user!");
  },
};
```

## Usage

### Direct Flow

Redirect users to `/authorize?redirect_to=/dashboard` for simple login. See `/demo.ts` for a complete example.

### OAuth Provider Flow

Other apps can use standard OAuth 2.0 flow with your worker as the provider. See [public/provider.html](public/provider.html) for a client example.

## Routes

- `/authorize` - OAuth authorization endpoint
- `/token` - OAuth token endpoint
- `/callback` - GitHub OAuth callback
- `/logout` - Logout and clear session
