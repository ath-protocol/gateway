/**
 * @ath-protocol/server — Server-side helpers for building ATH gateways and native implementations.
 *
 * Re-exports all protocol types from @ath-protocol/types.
 */
export { verifyAttestation, type AttestationResult, type AttestationVerifyOptions } from "./attestation.js";
export {
  type AgentRegistry,
  type RegisteredAgent,
  InMemoryAgentRegistry,
  hashSecret,
  generateCredentials,
} from "./registry.js";
export { intersectScopes, type ScopeIntersectionResult } from "./scopes.js";
export { type TokenStore, type BoundToken, InMemoryTokenStore } from "./tokens.js";
export {
  type SessionStore,
  type AuthorizationSession,
  type SessionStatus,
  InMemorySessionStore,
} from "./sessions.js";
export {
  createATHHandlers,
  type ATHHandlers,
  type ATHHandlerConfig,
  type ATHHandlerDeps,
  type ATHHandlerRequest,
  type ATHHandlerResponse,
} from "./handlers.js";
export {
  createServiceDiscoveryDocument,
  type ServiceDiscoveryConfig,
} from "./discovery.js";
export * from "@ath-protocol/types";
