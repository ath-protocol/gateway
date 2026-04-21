// Auto-generated barrel — DO NOT EDIT

export * from "./types.gen.js";
export { 
  zDiscoveryDocument,
  zServiceDiscoveryDocument,
  zServiceAuthConfig,
  zProviderInfo,
  zAgentIdentityDocument,
  zDeveloperInfo,
  zAgentRegistrationRequest,
  zProviderScopeRequest,
  zAgentRegistrationResponse,
  zAgentStatus,
  zProviderApproval,
  zAuthorizationRequest,
  zAuthorizationResponse,
  zTokenExchangeRequest,
  zTokenResponse,
  zScopeIntersection,
  zTokenRevocationRequest,
  zATHError,
  zATHErrorCode
} from "./zod.gen.js";

export const PROTOCOL_VERSION = "0.1";

export const ATH_ENDPOINTS = {
  discovery: { method: "GET", path: "/.well-known/ath.json" },
  service_discovery: { method: "GET", path: "/.well-known/ath-app.json" },
  register: { method: "POST", path: "/ath/agents/register" },
  get_agent: { method: "GET", path: "/ath/agents/{clientId}" },
  authorize: { method: "POST", path: "/ath/authorize" },
  callback: { method: "GET", path: "/ath/callback" },
  token: { method: "POST", path: "/ath/token" },
  proxy: { method: "ANY", path: "/ath/proxy/{provider_id}/{path}" },
  revoke: { method: "POST", path: "/ath/revoke" },
} as const;
