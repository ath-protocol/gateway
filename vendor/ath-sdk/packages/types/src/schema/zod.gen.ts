// Auto-generated Zod validators from ATH Protocol JSON Schema — DO NOT EDIT
// Source: https://raw.githubusercontent.com/ath-protocol/agent-trust-handshake-protocol/refs/heads/main/schema/0.1/schema.json
// Generated: 2026-04-20

import { z } from "zod";

export const zProviderInfo = z.object({
  provider_id: z.string(),
  display_name: z.string(),
  categories: z.array(z.string()).optional(),
  available_scopes: z.array(z.string()),
  auth_mode: z.string(),
  agent_approval_required: z.boolean(),
});

export const zDiscoveryDocument = z.object({
  ath_version: z.string(),
  gateway_id: z.string(),
  agent_registration_endpoint: z.string().url(),
  supported_providers: z.array(zProviderInfo),
});

export const zServiceAuthConfig = z.object({
  type: z.literal("oauth2"),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  registration_endpoint: z.string().url().optional(),
  scopes_supported: z.array(z.string()),
  agent_attestation_required: z.boolean().optional(),
});

export const zServiceDiscoveryDocument = z.object({
  ath_version: z.string(),
  app_id: z.string(),
  name: z.string(),
  auth: zServiceAuthConfig,
  api_base: z.string().url(),
});

export const zDeveloperInfo = z.object({
  name: z.string(),
  id: z.string(),
  contact: z.string().email().optional(),
});

export const zAgentIdentityDocument = z.object({
  ath_version: z.string(),
  agent_id: z.string().url(),
  name: z.string(),
  developer: zDeveloperInfo,
  capabilities: z.array(z.string()).optional(),
  public_key: z.unknown(),
});

export const zProviderScopeRequest = z.object({
  provider_id: z.string(),
  scopes: z.array(z.string()),
});

export const zAgentRegistrationRequest = z.object({
  agent_id: z.string().url(),
  agent_attestation: z.string(),
  developer: zDeveloperInfo,
  requested_providers: z.array(zProviderScopeRequest),
  purpose: z.string().optional(),
  redirect_uris: z.array(z.string().url()).optional(),
});

export const zAgentStatus = z.enum(["approved", "pending", "denied"]);

export const zProviderApproval = z.object({
  provider_id: z.string(),
  approved_scopes: z.array(z.string()),
  denied_scopes: z.array(z.string()),
  denial_reason: z.string().optional(),
});

export const zAgentRegistrationResponse = z.object({
  client_id: z.string(),
  client_secret: z.string(),
  agent_status: zAgentStatus,
  approved_providers: z.array(zProviderApproval),
  approval_expires: z.string().datetime(),
});

export const zAuthorizationRequest = z.object({
  client_id: z.string(),
  agent_attestation: z.string(),
  provider_id: z.string(),
  scopes: z.array(z.string()),
  user_redirect_uri: z.string().url().optional(),
  state: z.string().optional(),
  resource: z.string().url().optional(),
});

export const zAuthorizationResponse = z.object({
  authorization_url: z.string().url(),
  ath_session_id: z.string(),
});

export const zTokenExchangeRequest = z.object({
  grant_type: z.literal("authorization_code"),
  client_id: z.string(),
  client_secret: z.string(),
  code: z.string(),
  ath_session_id: z.string(),
});

export const zScopeIntersection = z.object({
  agent_approved: z.array(z.string()),
  user_consented: z.array(z.string()),
  effective: z.array(z.string()),
});

export const zTokenResponse = z.object({
  access_token: z.string(),
  token_type: z.literal("Bearer"),
  expires_in: z.number().int(),
  effective_scopes: z.array(z.string()),
  provider_id: z.string(),
  agent_id: z.string().url(),
  scope_intersection: zScopeIntersection,
});

export const zTokenRevocationRequest = z.object({
  client_id: z.string(),
  token: z.string(),
});

export const zATHErrorCode = z.enum(["INVALID_ATTESTATION", "AGENT_NOT_REGISTERED", "AGENT_UNAPPROVED", "PROVIDER_NOT_APPROVED", "SCOPE_NOT_APPROVED", "SESSION_NOT_FOUND", "SESSION_EXPIRED", "STATE_MISMATCH", "TOKEN_INVALID", "TOKEN_EXPIRED", "TOKEN_REVOKED", "AGENT_IDENTITY_MISMATCH", "PROVIDER_MISMATCH", "USER_DENIED", "OAUTH_ERROR", "INTERNAL_ERROR"]);

export const zATHError = z.object({
  code: zATHErrorCode,
  message: z.string(),
  details: z.record(z.string(), z.unknown()).optional(),
});
