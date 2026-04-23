/**
 * Authorization HTTP routes — OAuth flow orchestration, token exchange, revocation.
 * All operations are scoped to the authenticated user (tenant).
 */
import { Hono } from "hono";
import crypto from "node:crypto";
import { agentStore } from "../registry/agent-store.js";
import { verifyAttestation, intersectScopes } from "@ath-protocol/server";
import { sessionStore } from "./session-store.js";
import { tokenStore } from "./token.js";
import { oauthBridge } from "../oauth/client.js";
import { ATHError, ATHErrorCode } from "../types.js";
import type { AuthorizationRequest, TokenExchangeRequest, AppEnv } from "../types.js";
import { loadConfig } from "../config.js";
import { hashSecret } from "../utils.js";
import { assertFreshJti } from "./jti-replay.js";

export const authRoutes = new Hono<AppEnv>();

// POST /ath/authorize — Start authorization flow
authRoutes.post("/authorize", async (c) => {
  const body = (await c.req.json()) as AuthorizationRequest;
  const tenantId = c.get("userId") as string;
  const config = loadConfig();

  if (!body.state) {
    throw new ATHError(ATHErrorCode.STATE_MISMATCH, "Missing required state parameter", 400);
  }

  const agent = await agentStore.getScoped(body.client_id, tenantId);
  if (!agent) {
    throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Agent not registered", 403);
  }
  if (agent.agent_status !== "approved") {
    throw new ATHError(ATHErrorCode.AGENT_UNAPPROVED, "Agent not approved", 403);
  }

  const jtiCheck = assertFreshJti(body.agent_attestation);
  if (!jtiCheck.ok) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, jtiCheck.error, 401);
  }

  const attestResult = await verifyAttestation(body.agent_attestation, {
    audience: config.gatewayUrl,
    skipSignatureVerification: true,
  });
  if (!attestResult.valid) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, attestResult.error || "Invalid attestation", 401);
  }

  // redirect_uri validation per protocol spec
  if (agent.redirect_uris && agent.redirect_uris.length > 0) {
    if (body.user_redirect_uri && !agent.redirect_uris.includes(body.user_redirect_uri)) {
      throw new ATHError(
        ATHErrorCode.INVALID_ATTESTATION,
        "user_redirect_uri does not match any registered redirect_uris",
        400,
      );
    }
  } else if (body.user_redirect_uri) {
    throw new ATHError(
      ATHErrorCode.INVALID_ATTESTATION,
      "Agent has no registered redirect_uris; user_redirect_uri must not be provided",
      400,
    );
  }

  const providerApproval = agent.approved_providers.find((p) => p.provider_id === body.provider_id);
  if (!providerApproval) {
    throw new ATHError(
      ATHErrorCode.PROVIDER_NOT_APPROVED,
      `Agent not approved for provider "${body.provider_id}"`,
      403,
    );
  }

  const unapprovedScopes = body.scopes.filter((s) => !providerApproval.approved_scopes.includes(s));
  if (unapprovedScopes.length > 0) {
    throw new ATHError(
      ATHErrorCode.SCOPE_NOT_APPROVED,
      `Agent not approved for scopes: ${unapprovedScopes.join(", ")}`,
      403,
      { unapproved_scopes: unapprovedScopes },
    );
  }

  const oauthState = crypto.randomBytes(16).toString("hex");
  const callbackUrl = `${config.gatewayUrl}/ath/callback`;
  const authResult = await oauthBridge.getAuthUrl(
    body.provider_id,
    body.scopes,
    callbackUrl,
    oauthState,
    { resource: body.resource },
  );

  const session = await sessionStore.create({
    tenant_id: tenantId,
    client_id: body.client_id,
    provider_id: body.provider_id,
    requested_scopes: body.scopes,
    oauth_state: oauthState,
    code_verifier: authResult.code_verifier,
    resource: body.resource,
    expires_at: new Date(Date.now() + config.sessionExpirySeconds * 1000).toISOString(),
    status: "oauth_in_progress",
    user_redirect_uri: body.user_redirect_uri || `${config.gatewayUrl}/ui/callback`,
  });

  return c.json({
    authorization_url: authResult.url,
    ath_session_id: session.session_id,
  });
});

// GET /ath/callback — OAuth callback handler (no user auth — browser redirect)
authRoutes.get("/callback", async (c) => {
  const state = c.req.query("state");
  const error = c.req.query("error");
  const errorDescription = c.req.query("error_description");

  if (!state) {
    throw new ATHError(ATHErrorCode.STATE_MISMATCH, "Missing state parameter", 400);
  }

  const session = await sessionStore.getByState(state);
  if (!session) {
    throw new ATHError(ATHErrorCode.SESSION_NOT_FOUND, "No session found for this state", 400);
  }

  if (session.status !== "oauth_in_progress") {
    throw new ATHError(ATHErrorCode.SESSION_EXPIRED, "Session is not in progress", 400);
  }

  if (error) {
    const errorMsg = errorDescription
      || (error === "access_denied" ? "User denied consent" : error);
    await sessionStore.update(session.session_id, {
      status: "failed",
      error: errorMsg,
    });
    const redirectUrl = new URL(session.user_redirect_uri);
    redirectUrl.searchParams.set("error", error);
    if (errorDescription) redirectUrl.searchParams.set("error_description", errorDescription);
    redirectUrl.searchParams.set("ath_session_id", session.session_id);
    return c.redirect(redirectUrl.toString());
  }

  try {
    const fullCallbackUrl = c.req.url;
    const result = await oauthBridge.handleCallback(session.provider_id, fullCallbackUrl, {
      code_verifier: session.code_verifier,
      expected_state: session.oauth_state,
    });

    const consentedScopes = result.token.scope
      ? result.token.scope.split(/[\s,]+/).filter(Boolean)
      : session.requested_scopes;

    await sessionStore.update(session.session_id, {
      status: "completed",
      oauth_connection_id: result.connection_id,
      user_id: result.connection_id,
      user_consented_scopes: consentedScopes,
    });

    const config = loadConfig();
    const redirectUrl = new URL(`${config.gatewayUrl}/ui/callback`);
    redirectUrl.searchParams.set("session_id", session.session_id);
    redirectUrl.searchParams.set("success", "true");
    return c.redirect(redirectUrl.toString());
  } catch (err) {
    await sessionStore.update(session.session_id, {
      status: "failed",
      error: err instanceof Error ? err.message : "OAuth callback failed",
    });
    throw new ATHError(ATHErrorCode.OAUTH_ERROR, "Failed to complete OAuth flow", 500);
  }
});

// POST /ath/token — Exchange for ATH access token
authRoutes.post("/token", async (c) => {
  const body = (await c.req.json()) as TokenExchangeRequest;
  const tenantId = c.get("userId") as string;
  const config = loadConfig();

  if (!body.agent_attestation) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, "Missing required agent_attestation", 400);
  }

  const agent = await agentStore.getScoped(body.client_id, tenantId);
  if (!agent) {
    throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Agent not registered", 403);
  }

  const secretHash = hashSecret(body.client_secret);
  if (secretHash !== agent.client_secret_hash) {
    throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Invalid client credentials", 401);
  }

  const jtiCheck = assertFreshJti(body.agent_attestation);
  if (!jtiCheck.ok) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, jtiCheck.error, 401);
  }

  const tokenEndpointUrl = `${config.gatewayUrl}/ath/token`;
  const attestResult = await verifyAttestation(body.agent_attestation, {
    audience: tokenEndpointUrl,
    skipSignatureVerification: true,
  });
  if (!attestResult.valid) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, attestResult.error || "Invalid attestation", 401);
  }
  if (attestResult.agentId !== agent.agent_id) {
    throw new ATHError(
      ATHErrorCode.AGENT_IDENTITY_MISMATCH,
      "Attestation sub claim does not match registered agent_id",
      403,
    );
  }

  const session = await sessionStore.get(body.ath_session_id);
  if (!session) {
    throw new ATHError(ATHErrorCode.SESSION_NOT_FOUND, "Session not found", 400);
  }

  if (session.client_id !== body.client_id) {
    throw new ATHError(ATHErrorCode.AGENT_IDENTITY_MISMATCH, "Session does not belong to this agent", 403);
  }

  if (session.tenant_id !== tenantId) {
    throw new ATHError(ATHErrorCode.FORBIDDEN, "Session does not belong to this user", 403);
  }

  if (session.status === "failed") {
    const errorCode = session.error === "User denied consent"
      ? ATHErrorCode.USER_DENIED
      : ATHErrorCode.INTERNAL_ERROR;
    throw new ATHError(errorCode, session.error || "Authorization failed", 400);
  }

  if (session.status !== "completed") {
    throw new ATHError(ATHErrorCode.SESSION_NOT_FOUND, "Authorization not yet completed", 400);
  }

  const providerApproval = agent.approved_providers.find((p) => p.provider_id === session.provider_id);
  const agentApproved = providerApproval?.approved_scopes || [];
  const userConsented = session.user_consented_scopes || session.requested_scopes;

  const intersection = intersectScopes(agentApproved, userConsented, session.requested_scopes);

  if (intersection.effective.length === 0) {
    throw new ATHError(
      ATHErrorCode.SCOPE_NOT_APPROVED,
      "No effective scopes after intersection",
      403,
      { intersection },
    );
  }

  const expiresAt = new Date(Date.now() + config.tokenExpirySeconds * 1000).toISOString();
  const accessToken = await tokenStore.create({
    tenant_id: tenantId,
    agent_id: agent.agent_id,
    client_id: agent.client_id,
    user_id: session.user_id || session.oauth_connection_id || "unknown",
    provider_id: session.provider_id,
    scopes: intersection.effective,
    oauth_connection_id: session.oauth_connection_id || "",
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
  });

  await sessionStore.delete(session.session_id);

  return c.json({
    access_token: accessToken,
    token_type: "Bearer" as const,
    expires_in: config.tokenExpirySeconds,
    effective_scopes: intersection.effective,
    provider_id: session.provider_id,
    agent_id: agent.agent_id,
    scope_intersection: {
      agent_approved: intersection.agent_approved,
      user_consented: intersection.user_consented,
      effective: intersection.effective,
    },
  });
});

// POST /ath/revoke — Revoke an ATH token
authRoutes.post("/revoke", async (c) => {
  const { client_id, client_secret, token } = (await c.req.json()) as {
    client_id?: string;
    client_secret?: string;
    token: string;
  };
  const tenantId = c.get("userId") as string;

  if (!token) {
    throw new ATHError(ATHErrorCode.TOKEN_INVALID, "Missing token", 400);
  }

  if (client_id) {
    if (!client_secret) {
      throw new ATHError(
        ATHErrorCode.AGENT_NOT_REGISTERED,
        "client_secret is required when client_id is provided (RFC 7009)",
        401,
      );
    }
    const agent = await agentStore.getScoped(client_id, tenantId);
    if (!agent) {
      throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Agent not registered", 403);
    }
    const secretHash = hashSecret(client_secret);
    if (secretHash !== agent.client_secret_hash) {
      throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Invalid client credentials", 401);
    }
  }

  const bound = await tokenStore.get(token);
  if (bound && bound.tenant_id !== tenantId) {
    throw new ATHError(ATHErrorCode.FORBIDDEN, "Token does not belong to this user", 403);
  }

  if (client_id && bound && bound.client_id !== client_id) {
    throw new ATHError(ATHErrorCode.AGENT_IDENTITY_MISMATCH, "Token does not belong to this agent", 403);
  }

  const revoked = await tokenStore.revoke(token);
  if (!revoked) {
    throw new ATHError(ATHErrorCode.TOKEN_INVALID, "Token not found", 400);
  }

  return c.json({ message: "Token revoked" });
});
