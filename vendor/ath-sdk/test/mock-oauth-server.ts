/**
 * Self-contained mock OAuth2 server for SDK E2E tests.
 *
 * Implements OAuth 2.0 authorization code grant with:
 *   - PKCE (RFC 7636) — S256 + plain
 *   - Resource Indicators (RFC 8707)
 *   - Auto-approve mode (?auto_approve=true)
 *
 * This is a Hono app — no side-effect `serve()` call.
 * Tests start it explicitly via @hono/node-server.
 */
import { Hono } from "hono";
import crypto from "node:crypto";

export interface MockOAuthConfig {
  clientId?: string;
  clientSecret?: string;
  baseUrl?: string;
}

export function createMockOAuthServer(config: MockOAuthConfig = {}) {
  const CLIENT_ID = config.clientId || "ath-test-client";
  const CLIENT_SECRET = config.clientSecret || "ath-test-secret";

  const app = new Hono();

  const clients = new Map<string, { client_secret: string; redirect_uris: string[] }>();
  clients.set(CLIENT_ID, { client_secret: CLIENT_SECRET, redirect_uris: [] });

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

  const tokens = new Map<string, {
    client_id: string;
    user_id: string;
    scope: string;
    expires_at: number;
  }>();

  app.get("/authorize", (c) => {
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");
    const responseType = c.req.query("response_type");
    const scope = c.req.query("scope") || "";
    const state = c.req.query("state") || "";
    const codeChallenge = c.req.query("code_challenge");
    const codeChallengeMethod = c.req.query("code_challenge_method");
    const resource = c.req.query("resource");

    if (responseType !== "code") return c.json({ error: "unsupported_response_type" }, 400);

    const client = clientId ? clients.get(clientId) : undefined;
    if (!client) return c.json({ error: "invalid_client" }, 400);

    const autoApprove = c.req.query("auto_approve") === "true";
    if (!autoApprove) return c.json({ error: "interaction_required", message: "Set auto_approve=true for tests" }, 400);

    const code = crypto.randomBytes(16).toString("hex");
    codes.set(code, {
      client_id: clientId!,
      redirect_uri: redirectUri || "",
      scope,
      user_id: "test-user-001",
      expires_at: Date.now() + 600_000,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      resource,
    });

    const redirect = new URL(redirectUri!);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);
    return c.redirect(redirect.toString());
  });

  app.post("/token", async (c) => {
    const contentType = c.req.header("content-type") || "";
    let grantType: string, code: string, clientId: string, clientSecret: string;
    let redirectUri: string, codeVerifier: string | undefined;

    if (contentType.includes("application/json")) {
      const json = await c.req.json() as Record<string, string>;
      grantType = json.grant_type; code = json.code; clientId = json.client_id;
      clientSecret = json.client_secret; redirectUri = json.redirect_uri; codeVerifier = json.code_verifier;
    } else {
      const form = await c.req.parseBody();
      grantType = form["grant_type"] as string; code = form["code"] as string;
      clientId = form["client_id"] as string; clientSecret = form["client_secret"] as string;
      redirectUri = form["redirect_uri"] as string; codeVerifier = form["code_verifier"] as string | undefined;
    }

    if (!clientId) {
      const authHeader = c.req.header("authorization") || "";
      if (authHeader.startsWith("Basic ")) {
        const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
        [clientId, clientSecret] = decoded.split(":");
      }
    }

    if (grantType !== "authorization_code") return c.json({ error: "unsupported_grant_type" }, 400);

    const client = clients.get(clientId);
    if (!client || client.client_secret !== clientSecret) return c.json({ error: "invalid_client" }, 401);

    const authCode = codes.get(code);
    if (!authCode || authCode.client_id !== clientId) return c.json({ error: "invalid_grant" }, 400);
    if (authCode.expires_at < Date.now()) { codes.delete(code); return c.json({ error: "invalid_grant" }, 400); }

    if (authCode.code_challenge) {
      if (!codeVerifier) return c.json({ error: "invalid_grant", message: "Missing code_verifier" }, 400);
      const computed = authCode.code_challenge_method === "S256"
        ? crypto.createHash("sha256").update(codeVerifier).digest("base64url")
        : codeVerifier;
      if (computed !== authCode.code_challenge) { codes.delete(code); return c.json({ error: "invalid_grant", message: "PKCE failed" }, 400); }
    }

    codes.delete(code);

    const accessToken = `mock_at_${crypto.randomBytes(24).toString("hex")}`;
    tokens.set(accessToken, { client_id: clientId, user_id: authCode.user_id, scope: authCode.scope, expires_at: Date.now() + 3600_000 });

    return c.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: authCode.scope });
  });

  function validateToken(authHeader: string | undefined) {
    if (!authHeader?.startsWith("Bearer ")) return null;
    const t = tokens.get(authHeader.slice(7));
    return t && t.expires_at > Date.now() ? t : null;
  }

  app.get("/userinfo", (c) => {
    if (!validateToken(c.req.header("authorization"))) return c.json({ error: "unauthorized" }, 401);
    return c.json({ login: "test-user", name: "Test User", email: "test@example.com" });
  });

  app.get("/api/repos", (c) => {
    const auth = validateToken(c.req.header("authorization"));
    if (!auth) return c.json({ error: "unauthorized" }, 401);
    return c.json([{ id: 1, name: "ath-gateway", full_name: "test-user/ath-gateway" }]);
  });

  app.get("/health", (c) => c.json({ status: "ok", provider: "mock-oauth" }));

  app.get("/.well-known/oauth-authorization-server", (c) => {
    const baseUrl = config.baseUrl || "http://localhost:4000";
    return c.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      scopes_supported: ["repo", "read:user", "user:email", "read:org", "mail:read", "mail:send", "mail:delete", "calendar:read"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256", "plain"],
    });
  });

  return app;
}
