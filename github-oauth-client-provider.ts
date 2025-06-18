import { DurableObject } from "cloudflare:workers";

export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  CODES: DurableObjectNamespace<CodeDO>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
}

export class CodeDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    // Set alarm for 10 minutes from now
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Self-delete after 10 minutes
    await this.storage.deleteAll();
  }

  async setAuthData(
    accessToken: string,
    clientId: string,
    redirectUri: string,
  ) {
    await this.storage.put("data", { accessToken, clientId, redirectUri });
  }

  async getAuthData() {
    return this.storage.get<{
      accessToken: string;
      clientId: string;
      redirectUri: string;
    }>("data");
  }
}

/**
 * Handle OAuth requests. Call this from your worker's fetch handler.
 * Handles /authorize, /token, /callback, and /logout routes.
 *
 * @param request - The incoming request
 * @param env - Environment variables with GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET
 * @param scope - GitHub OAuth scope (default: "user:email")
 * @returns Response for OAuth routes, or null if not an OAuth route
 */
export async function handleOAuth(
  request: Request,
  env: Env,
  scope = "user:email",
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return new Response("GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET not set", {
      status: 500,
    });
  }

  if (path === "/token") {
    return handleToken(request, env, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope);
  }

  if (path === "/callback") {
    return handleCallback(request, env);
  }

  if (path === "/logout") {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
        "Set-Cookie":
          "access_token=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
      },
    });
  }

  return null; // Not an OAuth route, let other handlers take over
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");

  // If no client_id, this is a direct login request
  if (!clientId) {
    return handleDirectLogin(request, env, scope);
  }

  // Validate that client_id looks like a domain
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // If no redirect_uri provided, use default pattern
  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  // Validate redirect_uri is HTTPS and on same origin as client_id
  try {
    const redirectUrl = new URL(redirectUri);

    if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
      return new Response("Invalid redirect_uri: must use HTTPS", {
        status: 400,
      });
    }

    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
        { status: 400 },
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", { status: 400 });
  }

  // Only support authorization code flow
  if (responseType !== "code") {
    return new Response("Unsupported response_type", { status: 400 });
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    // User is already authenticated, create auth code and redirect
    return await createAuthCodeAndRedirect(
      env,
      clientId,
      redirectUri,
      state,
      accessToken,
    );
  }

  // User not authenticated, redirect to GitHub OAuth with our callback
  // Store the OAuth provider request details for after GitHub auth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for GitHub OAuth
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const githubState: OAuthState = {
    redirectTo: url.pathname + url.search, // Return to this authorize request after GitHub auth
    codeVerifier,
  };

  const githubStateString = btoa(JSON.stringify(githubState));

  // Build GitHub OAuth URL
  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", githubStateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({ Location: githubUrl.toString() });
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      githubStateString,
    )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString,
    )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function handleDirectLogin(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";

  // Generate PKCE code verifier and challenge
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Create state with redirect info and code verifier
  const state: OAuthState = { redirectTo, codeVerifier };
  const stateString = btoa(JSON.stringify(state));

  // Build GitHub OAuth URL
  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", stateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  return new Response(null, {
    status: 302,
    headers: {
      Location: githubUrl.toString(),
      "Set-Cookie": `oauth_state=${encodeURIComponent(
        stateString,
      )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  accessToken: string,
): Promise<Response> {
  // Generate auth code
  const authCode = generateCodeVerifier(); // Reuse the same random generation

  // Create Durable Object for this auth code
  const id = env.CODES.idFromName(authCode);
  const authCodeDO = env.CODES.get(id);

  await authCodeDO.setAuthData(accessToken, clientId, redirectUri);

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };
  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers,
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id is a valid domain
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    console.log(clientId.toString(), "invalid_client");
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers,
    });
  }

  // Get auth code data from Durable Object
  const id = env.CODES.idFromName(code.toString());
  const authCodeDO = env.CODES.get(id);
  const authData = await authCodeDO.getAuthData();

  // Validate client_id and redirect_uri match
  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Return the access token (just pass through GitHub's token)
  return new Response(
    JSON.stringify({
      access_token: authData?.accessToken,
      token_type: "bearer",
      scope,
    }),
    { headers },
  );
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;
  const providerStateCookie = cookies.provider_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Parse state
  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  // Exchange code for token with GitHub
  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    },
  );

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  // Check if this was part of an OAuth provider flow
  if (providerStateCookie) {
    try {
      const providerState = JSON.parse(atob(providerStateCookie));

      // Create auth code and redirect back to client
      const response = await createAuthCodeAndRedirect(
        env,
        providerState.clientId,
        providerState.redirectUri,
        providerState.state,
        tokenData.access_token,
      );

      // Set access token cookie and clear state cookies
      const headers = new Headers(response.headers);
      headers.append(
        "Set-Cookie",
        "oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
      );
      headers.append(
        "Set-Cookie",
        "provider_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
      );
      headers.append(
        "Set-Cookie",
        `access_token=${tokenData.access_token}; HttpOnly; Secure; SameSite=Lax; Path=/`,
      );

      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Fall through to normal redirect
    }
  }

  // Normal redirect (direct login)
  const headers = new Headers({ Location: state.redirectTo || "/" });
  headers.append(
    "Set-Cookie",
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
  );
  headers.append(
    "Set-Cookie",
    `access_token=${tokenData.access_token}; HttpOnly; Secure; SameSite=Lax; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

/**
 * Extract access token from request cookies.
 * Use this to check if a user is authenticated.
 *
 * @param request - The incoming request
 * @returns Access token string or null if not authenticated
 */
export function getAccessToken(request: Request): string | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
}

// Utility functions
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

function isValidDomain(domain: string): boolean {
  // Basic domain validation - must contain at least one dot and valid characters
  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return (
    domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
  );
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
