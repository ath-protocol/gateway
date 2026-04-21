/**
 * Gateway types — re-exports SDK protocol types and defines gateway-specific types.
 */

// Re-export all protocol types from the official SDK
export type {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AuthorizationRequest,
  AuthorizationResponse,
  TokenExchangeRequest,
  TokenResponse,
  TokenRevocationRequest,
  DiscoveryDocument,
  ProviderInfo,
  ProviderApproval,
  DeveloperInfo,
  ScopeIntersection,
  ATHErrorCode as ATHErrorCodeType,
} from "@ath-protocol/types";

// Re-export server-side types
export type {
  RegisteredAgent as SDKRegisteredAgent,
  ScopeIntersectionResult,
  AttestationResult,
  BoundToken as SDKBoundToken,
  AuthorizationSession as SDKAuthorizationSession,
} from "@ath-protocol/server";

// Hono environment bindings for typed c.get()/c.set()
export type AppEnv = {
  Variables: {
    userId: string;
    userRole: UserRole;
  };
};

// Users & Roles
export type UserRole = "admin" | "user";

export interface GatewayUser {
  id: string;
  username: string;
  email?: string;
  password_hash: string;
  role: UserRole;
  created_at: string;
}

// Gateway-extended types (add tenant_id to SDK base types)
export interface RegisteredAgent {
  tenant_id: string;
  client_id: string;
  client_secret_hash: string;
  agent_id: string;
  agent_status: "approved" | "pending" | "denied";
  approved_providers: import("@ath-protocol/types").ProviderApproval[];
  approval_expires: string;
  registered_at: string;
  developer: import("@ath-protocol/types").DeveloperInfo;
  purpose: string;
  redirect_uris: string[];
}

export interface AuthorizationSession {
  session_id: string;
  tenant_id: string;
  client_id: string;
  provider_id: string;
  requested_scopes: string[];
  user_id?: string;
  oauth_state: string;
  oauth_connection_id?: string;
  code_verifier?: string;
  resource?: string;
  user_consented_scopes?: string[];
  created_at: string;
  expires_at: string;
  status: "pending" | "oauth_in_progress" | "completed" | "failed";
  error?: string;
  user_redirect_uri: string;
}

export interface BoundToken {
  tenant_id: string;
  agent_id: string;
  client_id: string;
  user_id: string;
  provider_id: string;
  scopes: string[];
  oauth_connection_id: string;
  created_at: string;
  expires_at: string;
  revoked: boolean;
}

// Gateway error codes (superset of protocol codes + gateway-specific ones)
export enum ATHErrorCode {
  AGENT_NOT_REGISTERED = "AGENT_NOT_REGISTERED",
  AGENT_UNAPPROVED = "AGENT_UNAPPROVED",
  INVALID_ATTESTATION = "INVALID_ATTESTATION",
  PROVIDER_NOT_APPROVED = "PROVIDER_NOT_APPROVED",
  SCOPE_NOT_APPROVED = "SCOPE_NOT_APPROVED",
  TOKEN_EXPIRED = "TOKEN_EXPIRED",
  TOKEN_INVALID = "TOKEN_INVALID",
  TOKEN_REVOKED = "TOKEN_REVOKED",
  AGENT_IDENTITY_MISMATCH = "AGENT_IDENTITY_MISMATCH",
  PROVIDER_MISMATCH = "PROVIDER_MISMATCH",
  SESSION_NOT_FOUND = "SESSION_NOT_FOUND",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  USER_DENIED = "USER_DENIED",
  STATE_MISMATCH = "STATE_MISMATCH",
  OAUTH_ERROR = "OAUTH_ERROR",
  AUTH_REQUIRED = "AUTH_REQUIRED",
  SIGNUP_DISABLED = "SIGNUP_DISABLED",
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  USER_EXISTS = "USER_EXISTS",
  FORBIDDEN = "FORBIDDEN",
  INTERNAL_ERROR = "INTERNAL_ERROR",
}

export class ATHError extends Error {
  constructor(
    public readonly code: ATHErrorCode,
    message: string,
    public readonly status: number = 400,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ATHError";
  }
}
