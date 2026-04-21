/**
 * Service discovery document builder for ATH native mode.
 * Produces a valid /.well-known/ath-app.json document.
 */
import type { ServiceDiscoveryDocument } from "@ath-protocol/types";

export interface ServiceDiscoveryConfig {
  ath_version?: string;
  app_id: string;
  name: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported: string[];
  agent_attestation_required?: boolean;
  api_base: string;
}

export function createServiceDiscoveryDocument(config: ServiceDiscoveryConfig): ServiceDiscoveryDocument {
  return {
    ath_version: config.ath_version || "0.1",
    app_id: config.app_id,
    name: config.name,
    auth: {
      type: "oauth2" as const,
      authorization_endpoint: config.authorization_endpoint,
      token_endpoint: config.token_endpoint,
      registration_endpoint: config.registration_endpoint,
      scopes_supported: config.scopes_supported,
      agent_attestation_required: config.agent_attestation_required ?? true,
    },
    api_base: config.api_base,
  };
}
