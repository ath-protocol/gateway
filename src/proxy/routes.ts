/**
 * API Proxy routes — validates ATH tokens and proxies requests to providers.
 * Token must belong to the authenticated user's tenant.
 */
import { Hono } from "hono";
import { tokenStore } from "../auth/token.js";
import { oauthBridge } from "../oauth/client.js";
import { ATHError, ATHErrorCode } from "../types.js";
import type { AppEnv } from "../types.js";

export const proxyRoutes = new Hono<AppEnv>();

// ANY /ath/proxy/:providerId/*
proxyRoutes.all("/:providerId/*", async (c) => {
  const providerId = c.req.param("providerId");
  const tenantId = c.get("userId") as string;
  const fullPath = c.req.path;
  const proxyPath = fullPath.replace(`/ath/proxy/${providerId}`, "") || "/";

  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new ATHError(ATHErrorCode.TOKEN_INVALID, "Missing or invalid Authorization header", 401);
  }
  const token = authHeader.slice(7);

  const bound = await tokenStore.validate(token);
  if (!bound) {
    const raw = await tokenStore.get(token);
    if (raw?.revoked) {
      throw new ATHError(ATHErrorCode.TOKEN_REVOKED, "Token has been revoked", 401);
    }
    if (raw && new Date(raw.expires_at) < new Date()) {
      throw new ATHError(ATHErrorCode.TOKEN_EXPIRED, "Token has expired", 401);
    }
    throw new ATHError(ATHErrorCode.TOKEN_INVALID, "Invalid token", 401);
  }

  if (bound.tenant_id !== tenantId) {
    throw new ATHError(ATHErrorCode.FORBIDDEN, "Token does not belong to this user", 403);
  }

  const agentId = c.req.header("X-ATH-Agent-ID");
  if (agentId && agentId !== bound.agent_id) {
    throw new ATHError(
      ATHErrorCode.AGENT_IDENTITY_MISMATCH,
      "Agent identity does not match token binding",
      403,
    );
  }

  if (providerId !== bound.provider_id) {
    throw new ATHError(
      ATHErrorCode.PROVIDER_MISMATCH,
      `Token not valid for provider "${providerId}"`,
      403,
    );
  }

  let body: unknown = undefined;
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    try {
      body = await c.req.json();
    } catch {
      // No body or non-JSON body
    }
  }

  const result = await oauthBridge.proxy(
    providerId,
    bound.oauth_connection_id,
    c.req.method,
    proxyPath,
    body,
  );

  return c.json(result.body as object, result.status as 200);
});
