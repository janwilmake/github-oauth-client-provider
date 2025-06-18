import {
  handleOAuth,
  getAccessToken,
  Env,
  CodeDO,
} from "./github-oauth-client-provider";

export { CodeDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes first
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) {
      return oauthResponse;
    }

    const url = new URL(request.url);

    if (url.pathname === "/") {
      return handleHome(request);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleHome(request: Request): Promise<Response> {
  const accessToken = getAccessToken(request);

  if (!accessToken) {
    return new Response(
      `
      <html>
        <body>
          <h1>OAuth Demo</h1>
          <p>You are not logged in.</p>
          <a href="/authorize">Login with GitHub (direct flow)</a><br>
          <a href="/provider">Try provider flow example</a>
        </body>
      </html>
    `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }

  // Fetch user info from GitHub
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "User-Agent": "OAuth-Demo",
    },
  });

  if (!userResponse.ok) {
    return new Response(
      `
      <html>
        <body>
          <h1>OAuth Demo</h1>
          <p>Error fetching user info</p>
          <a href="/logout">Logout</a>
        </body>
      </html>
    `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }

  const user = (await userResponse.json()) as any;

  return new Response(
    `
    <html>
      <body>
        <h1>OAuth Demo</h1>
        <p>Welcome, ${user.name || user.login}!</p>
        <img src="${user.avatar_url}" alt="Avatar" width="50" height="50">
        <p>Username: ${user.login}</p>
        <p>Email: ${user.email || "Private"}</p>
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}
