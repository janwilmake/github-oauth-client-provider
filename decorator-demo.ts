import {
  Env,
  CodeDO,
  GitHubUser,
  withSimplerAuth,
} from "./github-oauth-client-provider";

export { CodeDO };

export default {
  fetch: withSimplerAuth(async (request, env, { user }): Promise<Response> => {
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
  }),
} satisfies ExportedHandler<Env>;
