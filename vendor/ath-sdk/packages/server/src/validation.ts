/**
 * validateToken — single source of truth for ATH access-token acceptance.
 *
 * Every consumer of a `TokenStore` (proxy, native API middleware, revocation,
 * introspection) runs its checks through here so the rules — expiry, revocation,
 * agent binding, scope containment — cannot drift between call sites.
 */
import type { BoundToken, TokenStore } from "./tokens.js";

export type TokenValidationCode =
  | "TOKEN_INVALID"
  | "TOKEN_REVOKED"
  | "TOKEN_EXPIRED"
  | "AGENT_IDENTITY_MISMATCH"
  | "SCOPE_NOT_APPROVED";

export type TokenValidationResult =
  | { valid: true; token: BoundToken }
  | { valid: false; code: TokenValidationCode; message: string; denied?: string[] };

export interface ValidateTokenOptions {
  /** If provided, the token's bound agent_id MUST equal this value. */
  agentId?: string;
  /** If provided, every scope listed MUST appear in the token's bound scopes. */
  requiredScopes?: string[];
  /** Override "now" (ms since epoch) for deterministic tests. */
  now?: number;
}

export async function validateToken(
  tokenStore: TokenStore,
  token: string | undefined | null,
  options: ValidateTokenOptions = {},
): Promise<TokenValidationResult> {
  if (!token) {
    return { valid: false, code: "TOKEN_INVALID", message: "Missing token" };
  }

  const bound = await tokenStore.get(token);
  if (!bound) {
    return { valid: false, code: "TOKEN_INVALID", message: "Token not found" };
  }

  if (bound.revoked) {
    return { valid: false, code: "TOKEN_REVOKED", message: "Token has been revoked" };
  }

  const nowMs = options.now ?? Date.now();
  if (new Date(bound.expires_at).getTime() <= nowMs) {
    return { valid: false, code: "TOKEN_EXPIRED", message: "Token has expired" };
  }

  if (options.agentId && options.agentId !== bound.agent_id) {
    return {
      valid: false,
      code: "AGENT_IDENTITY_MISMATCH",
      message: "Token is not bound to this agent",
    };
  }

  if (options.requiredScopes && options.requiredScopes.length > 0) {
    const granted = new Set(bound.scopes);
    const denied = options.requiredScopes.filter((s) => !granted.has(s));
    if (denied.length > 0) {
      return {
        valid: false,
        code: "SCOPE_NOT_APPROVED",
        message: `Missing required scopes: ${denied.join(", ")}`,
        denied,
      };
    }
  }

  return { valid: true, token: bound };
}
