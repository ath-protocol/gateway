// Auto-generated from ATH Protocol JSON Schema — DO NOT EDIT
// Source: https://raw.githubusercontent.com/ath-protocol/agent-trust-handshake-protocol/refs/heads/main/schema/0.1/schema.json
// Generated: 2026-04-23

/** Gateway discovery document returned by GET /.well-known/ath.json. Lists available providers and the agent registration endpoint. */
export interface DiscoveryDocument {
  /** Protocol version implemented by this gateway. */
  ath_version: string;
  /** Identifier for this gateway instance. */
  gateway_id: string;
  /** URL where agents submit registration requests. */
  agent_registration_endpoint: string;
  /** List of service providers available through this gateway. */
  supported_providers: ProviderInfo[];
}

/** Service-side discovery document returned by GET /.well-known/ath-app.json. Published by services that natively support ATH (Native Mode). */
export interface ServiceDiscoveryDocument {
  /** Protocol version supported by this service. */
  ath_version: string;
  /** Unique identifier for this service. */
  app_id: string;
  /** Human-readable name of the service. */
  name: string;
  auth: ServiceAuthConfig;
  /** Base URL for the service's API. */
  api_base: string;
}

/** Authentication configuration published by an ATH-native service. */
export interface ServiceAuthConfig {
  /** Authentication type. */
  type: "oauth2";
  /** OAuth 2.0 authorization endpoint URL. */
  authorization_endpoint: string;
  /** OAuth 2.0 token endpoint URL. */
  token_endpoint: string;
  /** Developer registration page URL. */
  registration_endpoint?: string;
  /** OAuth scopes supported by this service. */
  scopes_supported: string[];
  /** Whether the service requires agent attestation JWTs. */
  agent_attestation_required?: boolean;
}

/** Information about a service provider available through the gateway. */
export interface ProviderInfo {
  /** Unique identifier for this provider within the gateway. */
  provider_id: string;
  /** Human-readable name of the provider. */
  display_name: string;
  /** Categories describing the provider's domain. */
  categories?: string[];
  /** Scopes that agents can request for this provider. */
  available_scopes: string[];
  /** Authentication mode used by this provider. */
  auth_mode: string;
  /** Whether agents must be registered and approved before accessing this provider. */
  agent_approval_required: boolean;
}

/** Agent identity document published at the agent's Agent_ID URI (e.g. https://agent.example.com/.well-known/agent.json). Contains the agent's metadata and public key for attestation verification. */
export interface AgentIdentityDocument {
  /** Protocol version. */
  ath_version: string;
  /** Canonical URI for this agent. */
  agent_id: string;
  /** Human-readable agent name. */
  name: string;
  developer: DeveloperInfo;
  /** List of agent capabilities. */
  capabilities?: string[];
  /** JWK or PEM public key for agent attestation verification. */
  public_key: unknown;
}

/** Information about the agent's developer or organization. */
export interface DeveloperInfo {
  /** Developer or organization name. */
  name: string;
  /** Developer identifier. */
  id: string;
  /** Security contact email. */
  contact?: string;
}

/** Request body for POST /ath/agents/register. Registers a new agent with the ATH implementor (Phase A: app-side authorization). */
export interface AgentRegistrationRequest {
  /** The agent's canonical URI. */
  agent_id: string;
  /** Signed JWT (ES256) proving agent identity. MUST include iss, sub, aud, iat, exp, and jti claims. The jti MUST be unique per attestation and implementors MUST reject replayed jti values. */
  agent_attestation: string;
  developer: DeveloperInfo;
  /** Providers and scopes the agent is requesting access to. */
  requested_providers: ProviderScopeRequest[];
  /** Human-readable description of the agent's purpose. */
  purpose?: string;
  /** OAuth callback URIs for this agent. If provided, the implementor MUST validate user_redirect_uri against this list using exact-match comparison during authorization. If omitted (e.g., for local agents without a public endpoint), the implementor MUST reject any authorization request that includes a user_redirect_uri, and the OAuth callback MUST be handled entirely by the implementor without redirecting to the agent. */
  redirect_uris?: string[];
}

/** A request for access to a specific provider with specific scopes. */
export interface ProviderScopeRequest {
  /** Provider to request access to. */
  provider_id: string;
  /** Scopes being requested for this provider. */
  scopes: string[];
}

/** Response from POST /ath/agents/register. Contains the agent's credentials and per-provider approval results. */
export interface AgentRegistrationResponse {
  /** Unique identifier for this agent registration. */
  client_id: string;
  /** Secret for authenticating token exchange requests. Store securely. */
  client_secret: string;
  /** Overall registration status. */
  agent_status: AgentStatus;
  /** Per-provider approval results. */
  approved_providers: ProviderApproval[];
  /** When this registration expires. ISO 8601 timestamp. */
  approval_expires: string;
}

/** Registration status of an agent. */
export type AgentStatus = "approved" | "pending" | "denied";

/** The result of an agent's registration request for a specific provider. The implementor MAY approve a subset of requested scopes. */
export interface ProviderApproval {
  /** Provider this approval applies to. */
  provider_id: string;
  /** Scopes that were approved for the agent. */
  approved_scopes: string[];
  /** Scopes that were denied for the agent. */
  denied_scopes: string[];
  /** Human-readable reason for scope denial. */
  denial_reason?: string;
}

/** Request body for POST /ath/authorize. Initiates the user-side OAuth authorization flow (Phase B). The implementor generates PKCE parameters (RFC 7636) server-side. */
export interface AuthorizationRequest {
  /** The agent's client_id from registration. */
  client_id: string;
  /** Fresh signed JWT proving agent identity. */
  agent_attestation: string;
  /** Which provider to authorize access to. */
  provider_id: string;
  /** Scopes to request. Must be within the agent's approved scopes for this provider. */
  scopes: string[];
  /** Where to redirect the user after OAuth consent. */
  user_redirect_uri?: string;
  /** Opaque state parameter for CSRF protection. MUST be generated from a CSPRNG with at least 128 bits of entropy. The implementor MUST validate state on the OAuth callback and reject mismatches. */
  state: string;
  /** Target resource server URI. Optional, per RFC 8707 (Resource Indicators). */
  resource?: string;
}

/** Response from POST /ath/authorize. Contains the OAuth consent URL (with PKCE parameters) and a session identifier. */
export interface AuthorizationResponse {
  /** URL where the user should be directed for OAuth consent. Includes code_challenge and code_challenge_method=S256 (PKCE). */
  authorization_url: string;
  /** Session identifier used during token exchange. */
  ath_session_id: string;
}

/** Request body for POST /ath/token. Exchanges an OAuth authorization code for an ATH access token after user consent. */
export interface TokenExchangeRequest {
  /** Must be 'authorization_code'. */
  grant_type: "authorization_code";
  /** The agent's client_id. */
  client_id: string;
  /** The agent's client_secret. */
  client_secret: string;
  /** Fresh signed JWT proving current possession of the agent's private key. The attestation sub claim MUST match the client_id's registered agent_id. The aud claim MUST be set to the token endpoint URL. */
  agent_attestation: string;
  /** OAuth authorization code from the callback. */
  code: string;
  /** Session ID from the authorization step. */
  ath_session_id: string;
}

/** Response from POST /ath/token. Contains the ATH access token with scope intersection breakdown showing how effective permissions were derived. */
export interface TokenResponse {
  /** The ATH access token. Bound to (agent_id, user_id, provider_id, scopes). */
  access_token: string;
  /** Token type. Always 'Bearer'. */
  token_type: "Bearer";
  /** Token lifetime in seconds. */
  expires_in: number;
  /** The computed effective scopes (result of scope intersection). */
  effective_scopes: string[];
  /** Which provider this token grants access to. */
  provider_id: string;
  /** The agent this token is bound to. */
  agent_id: string;
  scope_intersection: ScopeIntersection;
}

/** Breakdown of the scope intersection computation. Effective = Agent Approved ∩ User Consented ∩ Requested. */
export interface ScopeIntersection {
  /** Scopes the service approved for this agent (Phase A). */
  agent_approved: string[];
  /** Scopes the user consented to in the OAuth flow (Phase B). */
  user_consented: string[];
  /** The intersection — the actual permissions the token carries. */
  effective: string[];
}

/** Request body for POST /ath/revoke. Immediately invalidates an ATH access token. When called by an agent, client_secret is required for authentication per RFC 7009. Users and administrators authenticate through the implementor's own mechanism (e.g., session cookie, admin API key) and are not required to provide client_secret. */
export interface TokenRevocationRequest {
  /** The agent's client_id. Required when the caller is the agent. */
  client_id?: string;
  /** The agent's client_secret. Required when the caller is the agent, for client authentication per RFC 7009. */
  client_secret?: string;
  /** The ATH access token to revoke. */
  token: string;
}

/** Standard error response returned by all ATH endpoints on failure. */
export interface ATHError {
  /** Machine-readable error code. */
  code: ATHErrorCode;
  /** Human-readable error message. */
  message: string;
  /** Additional structured error details. */
  details?: Record<string, unknown>;
}

/** Enumeration of ATH error codes. */
export type ATHErrorCode = "INVALID_ATTESTATION" | "AGENT_NOT_REGISTERED" | "AGENT_UNAPPROVED" | "PROVIDER_NOT_APPROVED" | "SCOPE_NOT_APPROVED" | "SESSION_NOT_FOUND" | "SESSION_EXPIRED" | "STATE_MISMATCH" | "TOKEN_INVALID" | "TOKEN_EXPIRED" | "TOKEN_REVOKED" | "AGENT_IDENTITY_MISMATCH" | "PROVIDER_MISMATCH" | "USER_DENIED" | "OAUTH_ERROR" | "INTERNAL_ERROR";
