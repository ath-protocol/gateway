/**
 * Mock OAuth2 Provider — A standalone OAuth2 authorization server for E2E testing.
 *
 * Implements the standard OAuth2 authorization code flow with:
 *   - PKCE support (RFC 7636) — code_challenge / code_verifier validation
 *   - Resource Indicators (RFC 8707) — resource parameter pass-through
 *
 * Endpoints:
 *   GET  /authorize  — Authorization endpoint (shows consent page)
 *   POST /token      — Token endpoint (exchanges code for access token)
 *   GET  /userinfo    — Protected resource (returns mock user profile)
 *   GET  /api/repos   — Protected resource (returns mock repos)
 *   GET  /.well-known/oauth-authorization-server — Server metadata
 *
 * This server simulates a provider like GitHub or Tencent Docs so the ATH
 * gateway can be tested end-to-end without real third-party accounts.
 */
import { Hono } from "hono";
import crypto from "node:crypto";

const app = new Hono();

// ── In-memory stores ──────────────────────────────────────────────

/** Registered OAuth clients (pre-seeded for ATH gateway) */
const clients = new Map<string, { client_secret: string; redirect_uris: string[] }>();

/** Authorization codes awaiting exchange */
const codes = new Map<string, {
  client_id: string;
  redirect_uri: string;
  scope: string;
  user_id: string;
  expires_at: number;
  code_challenge?: string;
  code_challenge_method?: string;
  resource?: string;
}>();

/** Issued access tokens */
const tokens = new Map<string, {
  client_id: string;
  user_id: string;
  scope: string;
  expires_at: number;
}>();

// Pre-register the ATH gateway as an OAuth client
const ATH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "ath-gateway-client";
const ATH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "ath-gateway-secret";
clients.set(ATH_CLIENT_ID, {
  client_secret: ATH_CLIENT_SECRET,
  redirect_uris: ["http://localhost:3000/ath/callback", "http://gateway:3000/ath/callback"],
});

// Also allow dynamic client registration
app.post("/clients/register", async (c) => {
  const body = await c.req.json() as {
    client_id?: string;
    client_secret?: string;
    redirect_uris?: string[];
  };
  const clientId = body.client_id || `client_${crypto.randomBytes(8).toString("hex")}`;
  const clientSecret = body.client_secret || crypto.randomBytes(24).toString("hex");
  clients.set(clientId, {
    client_secret: clientSecret,
    redirect_uris: body.redirect_uris || [],
  });
  return c.json({ client_id: clientId, client_secret: clientSecret });
});

/** E2E: register an extra redirect_uri for an existing client (e.g. gateway on a random port). */
app.post("/clients/redirect-uris", async (c) => {
  const body = await c.req.json() as { client_id?: string; redirect_uri?: string };
  if (!body.client_id || !body.redirect_uri) {
    return c.json({ error: "invalid_request", message: "client_id and redirect_uri required" }, 400);
  }
  const client = clients.get(body.client_id);
  if (!client) {
    return c.json({ error: "invalid_client" }, 404);
  }
  if (!client.redirect_uris.includes(body.redirect_uri)) {
    client.redirect_uris.push(body.redirect_uri);
  }
  return c.json({ ok: true, redirect_uris: client.redirect_uris });
});

// ── OAuth2 Authorization Endpoint ─────────────────────────────────

app.get("/authorize", async (c) => {
  const clientId = c.req.query("client_id");
  const redirectUri = c.req.query("redirect_uri");
  const responseType = c.req.query("response_type");
  const scope = c.req.query("scope") || "";
  const state = c.req.query("state") || "";
  const codeChallenge = c.req.query("code_challenge");
  const codeChallengeMethod = c.req.query("code_challenge_method");
  const resource = c.req.query("resource");

  if (responseType !== "code") {
    return c.json({ error: "unsupported_response_type" }, 400);
  }

  const client = clientId ? clients.get(clientId) : undefined;
  if (!client) {
    return c.json({ error: "invalid_client", message: `Unknown client_id: ${clientId}` }, 400);
  }

  // Auto-approve mode (for E2E tests): if ?auto_approve=true, skip the consent page
  const autoApprove = c.req.query("auto_approve") === "true";
  if (autoApprove) {
    const code = crypto.randomBytes(16).toString("hex");
    codes.set(code, {
      client_id: clientId!,
      redirect_uri: redirectUri || client.redirect_uris[0] || "",
      scope,
      user_id: "test-user-001",
      expires_at: Date.now() + 10 * 60 * 1000,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      resource,
    });

    const redirect = new URL(redirectUri || client.redirect_uris[0]);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);
    return c.redirect(redirect.toString());
  }

  // Show consent page
  const html = `<!DOCTYPE html>
<html>
<head><title>Mock OAuth - Authorize</title>
<style>
  body { font-family: sans-serif; background: #1a1a2e; color: #eee; display: flex; justify-content: center; padding-top: 80px; }
  .card { background: #16213e; padding: 2rem; border-radius: 8px; width: 400px; }
  h2 { color: #e94560; margin-bottom: 1rem; }
  .scope { background: #0f3460; padding: 4px 12px; border-radius: 4px; display: inline-block; margin: 4px; }
  .info { background: #0f3460; padding: 8px 12px; border-radius: 4px; margin-top: 8px; font-size: 0.85rem; color: #94a3b8; }
  button { padding: 10px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin-right: 8px; margin-top: 1rem; }
  .approve { background: #065f46; color: white; }
  .deny { background: #991b1b; color: white; }
</style>
</head>
<body>
<div class="card">
  <h2>Mock OAuth Provider</h2>
  <p><strong>${clientId}</strong> wants to access your account.</p>
  <p style="margin-top:1rem;">Requested permissions:</p>
  <div>${scope.split(/[,\s]+/).filter(Boolean).map((s: string) => `<span class="scope">${s}</span>`).join(" ")}</div>
  ${resource ? `<div class="info">Resource: ${resource}</div>` : ""}
  ${codeChallenge ? `<div class="info">PKCE: ${codeChallengeMethod || "plain"}</div>` : ""}
  <form method="POST" action="/authorize/approve">
    <input type="hidden" name="client_id" value="${clientId}">
    <input type="hidden" name="redirect_uri" value="${redirectUri || ""}">
    <input type="hidden" name="scope" value="${scope}">
    <input type="hidden" name="state" value="${state}">
    <input type="hidden" name="code_challenge" value="${codeChallenge || ""}">
    <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod || ""}">
    <input type="hidden" name="resource" value="${resource || ""}">
    <button type="submit" class="approve">Approve</button>
    <button type="submit" name="action" value="deny" class="deny">Deny</button>
  </form>
</div>
</body>
</html>`;

  return c.html(html);
});

// Handle consent form submission
app.post("/authorize/approve", async (c) => {
  const body = await c.req.parseBody();
  const clientId = body["client_id"] as string;
  const redirectUri = body["redirect_uri"] as string;
  const scope = body["scope"] as string;
  const state = body["state"] as string;
  const action = body["action"] as string;
  const codeChallenge = body["code_challenge"] as string;
  const codeChallengeMethod = body["code_challenge_method"] as string;
  const resource = body["resource"] as string;

  const client = clients.get(clientId);
  const finalRedirect = redirectUri || client?.redirect_uris[0] || "";

  if (action === "deny") {
    const redirect = new URL(finalRedirect);
    redirect.searchParams.set("error", "access_denied");
    if (state) redirect.searchParams.set("state", state);
    return c.redirect(redirect.toString());
  }

  // Generate authorization code
  const code = crypto.randomBytes(16).toString("hex");
  codes.set(code, {
    client_id: clientId,
    redirect_uri: finalRedirect,
    scope,
    user_id: "test-user-001",
    expires_at: Date.now() + 10 * 60 * 1000,
    code_challenge: codeChallenge || undefined,
    code_challenge_method: codeChallengeMethod || undefined,
    resource: resource || undefined,
  });

  const redirect = new URL(finalRedirect);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return c.redirect(redirect.toString());
});

// ── OAuth2 Token Endpoint ─────────────────────────────────────────

app.post("/token", async (c) => {
  let grantType: string;
  let code: string;
  let clientId: string;
  let clientSecret: string;
  let redirectUri: string;
  let codeVerifier: string | undefined;

  const contentType = c.req.header("content-type") || "";
  if (contentType.includes("application/json")) {
    const json = await c.req.json() as Record<string, string>;
    grantType = json.grant_type;
    code = json.code;
    clientId = json.client_id;
    clientSecret = json.client_secret;
    redirectUri = json.redirect_uri;
    codeVerifier = json.code_verifier;
  } else {
    const form = await c.req.parseBody();
    grantType = form["grant_type"] as string;
    code = form["code"] as string;
    clientId = form["client_id"] as string;
    clientSecret = form["client_secret"] as string;
    redirectUri = form["redirect_uri"] as string;
    codeVerifier = form["code_verifier"] as string | undefined;
  }

  // Also check Basic auth header
  if (!clientId) {
    const authHeader = c.req.header("authorization") || "";
    if (authHeader.startsWith("Basic ")) {
      const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
      const [id, secret] = decoded.split(":");
      clientId = id;
      clientSecret = secret;
    }
  }

  if (grantType !== "authorization_code") {
    return c.json({ error: "unsupported_grant_type" }, 400);
  }

  // Validate client
  const client = clients.get(clientId);
  if (!client || client.client_secret !== clientSecret) {
    return c.json({ error: "invalid_client" }, 401);
  }

  // Validate code
  const authCode = codes.get(code);
  if (!authCode) {
    return c.json({ error: "invalid_grant", message: "Unknown or expired authorization code" }, 400);
  }

  if (authCode.client_id !== clientId) {
    return c.json({ error: "invalid_grant", message: "Code was not issued to this client" }, 400);
  }

  if (authCode.expires_at < Date.now()) {
    codes.delete(code);
    return c.json({ error: "invalid_grant", message: "Authorization code expired" }, 400);
  }

  // PKCE validation (RFC 7636)
  if (authCode.code_challenge) {
    if (!codeVerifier) {
      return c.json({ error: "invalid_grant", message: "Missing code_verifier (PKCE required)" }, 400);
    }

    let computedChallenge: string;
    if (authCode.code_challenge_method === "S256") {
      computedChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");
    } else {
      // plain method
      computedChallenge = codeVerifier;
    }

    if (computedChallenge !== authCode.code_challenge) {
      codes.delete(code);
      return c.json({ error: "invalid_grant", message: "PKCE verification failed" }, 400);
    }
  }

  // Consume code (one-time use)
  codes.delete(code);

  // Issue access token
  const accessToken = `mock_at_${crypto.randomBytes(24).toString("hex")}`;
  const refreshToken = `mock_rt_${crypto.randomBytes(24).toString("hex")}`;
  const expiresIn = 3600;

  tokens.set(accessToken, {
    client_id: clientId,
    user_id: authCode.user_id,
    scope: authCode.scope,
    expires_at: Date.now() + expiresIn * 1000,
  });

  return c.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: refreshToken,
    scope: authCode.scope,
  });
});

// ── Protected Resources ───────────────────────────────────────────

function validateToken(authHeader: string | undefined): { user_id: string; scope: string } | null {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const data = tokens.get(token);
  if (!data) return null;
  if (data.expires_at < Date.now()) {
    tokens.delete(token);
    return null;
  }
  return { user_id: data.user_id, scope: data.scope };
}

// GET /userinfo — Mock user profile (like GitHub's /user)
app.get("/userinfo", (c) => {
  const auth = validateToken(c.req.header("authorization"));
  if (!auth) return c.json({ error: "unauthorized" }, 401);

  return c.json({
    id: auth.user_id,
    login: "test-user",
    name: "Test User",
    email: "test@example.com",
    avatar_url: "https://example.com/avatar.png",
    bio: "A mock user for ATH E2E testing",
  });
});

// GET /api/repos — Mock repos (like GitHub's /user/repos)
app.get("/api/repos", (c) => {
  const auth = validateToken(c.req.header("authorization"));
  if (!auth) return c.json({ error: "unauthorized" }, 401);

  if (!auth.scope.includes("repo")) {
    return c.json({ error: "insufficient_scope", message: "Requires 'repo' scope" }, 403);
  }

  return c.json([
    { id: 1, name: "ath-gateway", full_name: "test-user/ath-gateway", private: false, description: "ATH Gateway implementation" },
    { id: 2, name: "my-app", full_name: "test-user/my-app", private: true, description: "My private app" },
  ]);
});

// GET /api/emails — Mock emails (like GitHub's /user/emails)
app.get("/api/emails", (c) => {
  const auth = validateToken(c.req.header("authorization"));
  if (!auth) return c.json({ error: "unauthorized" }, 401);

  return c.json([
    { email: "test@example.com", primary: true, verified: true },
    { email: "test+alt@example.com", primary: false, verified: true },
  ]);
});

// ── Server Metadata ───────────────────────────────────────────────

app.get("/.well-known/oauth-authorization-server", (c) => {
  const baseUrl = process.env.OAUTH_BASE_URL || "http://localhost:4000";
  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    userinfo_endpoint: `${baseUrl}/userinfo`,
    scopes_supported: ["repo", "read:user", "user:email", "read:org"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256", "plain"],
  });
});

// Health check
app.get("/health", (c) => c.json({ status: "ok", provider: "mock-oauth" }));

export { app };
