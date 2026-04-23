/**
 * Framework-agnostic ATH endpoint handlers.
 * Implements register, authorize, callback, token, and revoke for both
 * gateway and native mode. Uses openid-client for OAuth 2.0 with PKCE (RFC 7636).
 */
import * as oidc from "openid-client";
import crypto from "node:crypto";
import type {
  AgentRegistrationRequest,
  AgentRegistrationResponse,
  AuthorizationRequest,
  AuthorizationResponse,
  TokenExchangeRequest,
  TokenResponse,
  TokenRevocationRequest,
} from "@ath-protocol/types";
import { verifyAttestation } from "./attestation.js";
import type { AgentRegistry, RegisteredAgent } from "./registry.js";
import { generateCredentials, hashSecret } from "./registry.js";
import { intersectScopes } from "./scopes.js";
import type { TokenStore } from "./tokens.js";
import type { SessionStore } from "./sessions.js";
import { InMemoryProviderTokenStore, type ProviderTokenStore } from "./provider-tokens.js";

export interface ATHHandlerRequest {
  method: string;
  path: string;
  headers: Record<string, string | undefined>;
  body?: unknown;
  query?: Record<string, string>;
  url?: string;
}

export interface ATHHandlerResponse {
  status: number;
  headers?: Record<string, string>;
  body: unknown;
}

export interface ATHHandlerConfig {
  audience: string;
  tokenExpirySeconds?: number;
  sessionExpirySeconds?: number;
  callbackUrl: string;

  availableScopes: string[];
  appId: string;

  oauth: {
    authorize_endpoint: string;
    token_endpoint: string;
    client_id: string;
    client_secret: string;
  };

  skipAttestationVerification?: boolean;
}

export interface ATHHandlerDeps {
  registry: AgentRegistry;
  tokenStore: TokenStore;
  sessionStore: SessionStore;
  /**
   * Storage for upstream OAuth tokens. Optional for backwards compatibility —
   * defaults to `InMemoryProviderTokenStore`. Pass an injected store to share
   * provider tokens with `createProxyHandler` or across server replicas.
   */
  providerTokenStore?: ProviderTokenStore;
  config: ATHHandlerConfig;
}

function oidcConfig(cfg: ATHHandlerConfig): oidc.Configuration {
  const config = new oidc.Configuration(
    {
      issuer: new URL(cfg.oauth.authorize_endpoint).origin,
      authorization_endpoint: cfg.oauth.authorize_endpoint,
      token_endpoint: cfg.oauth.token_endpoint,
    } as oidc.ServerMetadata,
    cfg.oauth.client_id,
    cfg.oauth.client_secret,
  );

  if (cfg.oauth.authorize_endpoint.startsWith("http://")) {
    oidc.allowInsecureRequests(config);
  }

  return config;
}

export interface ATHHandlers {
  register(req: ATHHandlerRequest): Promise<ATHHandlerResponse>;
  authorize(req: ATHHandlerRequest): Promise<ATHHandlerResponse>;
  callback(req: ATHHandlerRequest): Promise<ATHHandlerResponse>;
  token(req: ATHHandlerRequest): Promise<ATHHandlerResponse>;
  revoke(req: ATHHandlerRequest): Promise<ATHHandlerResponse>;
}

export function createATHHandlers(deps: ATHHandlerDeps): ATHHandlers {
  const { registry, tokenStore, sessionStore, config } = deps;
  const providerTokenStore = deps.providerTokenStore ?? new InMemoryProviderTokenStore();
  const tokenExpiry = config.tokenExpirySeconds || 3600;
  const sessionExpiry = config.sessionExpirySeconds || 600;

  return {
    async register(req): Promise<ATHHandlerResponse> {
      const body = req.body as AgentRegistrationRequest;
      if (!body?.agent_id || !body?.agent_attestation) {
        return { status: 400, body: { code: "INVALID_ATTESTATION", message: "Missing agent_id or attestation" } };
      }

      const attestResult = await verifyAttestation(body.agent_attestation, {
        audience: config.audience,
        skipSignatureVerification: config.skipAttestationVerification,
      });
      if (!attestResult.valid) {
        return { status: 401, body: { code: "INVALID_ATTESTATION", message: attestResult.error } };
      }

      const { clientId, clientSecret, secretHash } = generateCredentials();

      const approvedProviders = (body.requested_providers || []).map((rp) => {
        const approved = rp.scopes.filter((s) => config.availableScopes.includes(s));
        const denied = rp.scopes.filter((s) => !config.availableScopes.includes(s));
        return {
          provider_id: rp.provider_id,
          approved_scopes: approved,
          denied_scopes: denied,
        };
      });

      const agent: RegisteredAgent = {
        client_id: clientId,
        client_secret_hash: secretHash,
        agent_id: body.agent_id,
        agent_status: "approved",
        approved_providers: approvedProviders,
        approval_expires: new Date(Date.now() + 365 * 86400_000).toISOString(),
        registered_at: new Date().toISOString(),
        developer: body.developer,
        purpose: body.purpose || "",
        redirect_uris: body.redirect_uris || [config.callbackUrl],
      };

      await registry.register(agent);

      const response: AgentRegistrationResponse = {
        client_id: clientId,
        client_secret: clientSecret,
        agent_status: "approved",
        approved_providers: approvedProviders,
        approval_expires: agent.approval_expires,
      };

      return { status: 201, body: response };
    },

    async authorize(req): Promise<ATHHandlerResponse> {
      const body = req.body as AuthorizationRequest;
      if (!body?.client_id) {
        return { status: 400, body: { code: "AGENT_NOT_REGISTERED", message: "Missing client_id" } };
      }

      if (!body.state) {
        return { status: 400, body: { code: "STATE_MISMATCH", message: "Missing required state parameter" } };
      }

      const agent = await registry.get(body.client_id);
      if (!agent) {
        return { status: 403, body: { code: "AGENT_NOT_REGISTERED", message: "Agent not registered" } };
      }
      if (agent.agent_status !== "approved") {
        return { status: 403, body: { code: "AGENT_UNAPPROVED", message: "Agent not approved" } };
      }

      if (body.user_redirect_uri && agent.redirect_uris.length > 0) {
        if (!agent.redirect_uris.includes(body.user_redirect_uri)) {
          return { status: 400, body: { code: "INVALID_ATTESTATION", message: "user_redirect_uri does not match any registered redirect_uris" } };
        }
      }
      if (body.user_redirect_uri && agent.redirect_uris.length === 0) {
        return { status: 400, body: { code: "INVALID_ATTESTATION", message: "Agent registered without redirect_uris; user_redirect_uri is not allowed" } };
      }

      const attestResult = await verifyAttestation(body.agent_attestation, {
        audience: config.audience,
        skipSignatureVerification: config.skipAttestationVerification,
      });
      if (!attestResult.valid) {
        return { status: 401, body: { code: "INVALID_ATTESTATION", message: attestResult.error } };
      }

      const providerApproval = agent.approved_providers.find((p) => p.provider_id === body.provider_id);
      if (!providerApproval) {
        return { status: 403, body: { code: "PROVIDER_NOT_APPROVED", message: `Agent not approved for ${body.provider_id}` } };
      }

      const unapproved = body.scopes.filter((s) => !providerApproval.approved_scopes.includes(s));
      if (unapproved.length > 0) {
        return { status: 403, body: { code: "SCOPE_NOT_APPROVED", message: `Unapproved scopes: ${unapproved.join(", ")}` } };
      }

      const oauthState = crypto.randomBytes(16).toString("hex");
      const oidcCfg = oidcConfig(config);
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);

      const params: Record<string, string> = {
        redirect_uri: config.callbackUrl,
        scope: body.scopes.join(" "),
        state: oauthState,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      };
      if (body.resource) params.resource = body.resource;

      const authUrl = oidc.buildAuthorizationUrl(oidcCfg, params);

      const session = await sessionStore.create({
        client_id: body.client_id,
        provider_id: body.provider_id,
        requested_scopes: body.scopes,
        oauth_state: oauthState,
        code_verifier: codeVerifier,
        resource: body.resource,
        expires_at: new Date(Date.now() + sessionExpiry * 1000).toISOString(),
        status: "oauth_in_progress",
        user_redirect_uri: body.user_redirect_uri || config.callbackUrl,
      });

      const response: AuthorizationResponse = {
        authorization_url: authUrl.toString(),
        ath_session_id: session.session_id,
      };

      return { status: 200, body: response };
    },

    async callback(req): Promise<ATHHandlerResponse> {
      const state = req.query?.state;
      const error = req.query?.error;

      if (!state) {
        return { status: 400, body: { code: "STATE_MISMATCH", message: "Missing state" } };
      }

      const session = await sessionStore.getByState(state);
      if (!session) {
        return { status: 400, body: { code: "SESSION_NOT_FOUND", message: "No session for state" } };
      }

      if (error) {
        await sessionStore.update(session.session_id, { status: "failed", error });
        return { status: 302, headers: { Location: `${session.user_redirect_uri}?error=${error}&ath_session_id=${session.session_id}` }, body: null };
      }

      try {
        const oidcCfg = oidcConfig(config);
        const callbackUrl = req.url || `${config.callbackUrl}?code=${req.query?.code}&state=${state}`;

        const tokens = await oidc.authorizationCodeGrant(oidcCfg, new URL(callbackUrl), {
          pkceCodeVerifier: session.code_verifier,
          expectedState: session.oauth_state,
        });

        const connectionId = `native_${crypto.randomBytes(8).toString("hex")}`;
        await providerTokenStore.set(connectionId, {
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          scope: tokens.scope,
        });

        const consentedScopes = tokens.scope
          ? tokens.scope.split(/[\s,]+/).filter(Boolean)
          : session.requested_scopes;

        await sessionStore.update(session.session_id, {
          status: "completed",
          oauth_connection_id: connectionId,
          user_id: connectionId,
          user_consented_scopes: consentedScopes,
        });

        return {
          status: 302,
          headers: { Location: `${session.user_redirect_uri}?session_id=${session.session_id}&success=true` },
          body: null,
        };
      } catch (err) {
        await sessionStore.update(session.session_id, {
          status: "failed",
          error: err instanceof Error ? err.message : "OAuth callback failed",
        });
        return { status: 500, body: { code: "OAUTH_ERROR", message: "OAuth callback failed" } };
      }
    },

    async token(req): Promise<ATHHandlerResponse> {
      const body = req.body as TokenExchangeRequest;
      if (!body?.client_id || !body?.client_secret) {
        return { status: 400, body: { code: "AGENT_NOT_REGISTERED", message: "Missing credentials" } };
      }

      if (!body.agent_attestation) {
        return { status: 400, body: { code: "INVALID_ATTESTATION", message: "Missing agent_attestation" } };
      }

      const agent = await registry.get(body.client_id);
      if (!agent) {
        return { status: 403, body: { code: "AGENT_NOT_REGISTERED", message: "Agent not registered" } };
      }

      if (hashSecret(body.client_secret) !== agent.client_secret_hash) {
        return { status: 401, body: { code: "AGENT_NOT_REGISTERED", message: "Invalid credentials" } };
      }

      const attestResult = await verifyAttestation(body.agent_attestation, {
        audience: config.audience,
        skipSignatureVerification: config.skipAttestationVerification,
      });
      if (!attestResult.valid) {
        return { status: 401, body: { code: "INVALID_ATTESTATION", message: attestResult.error } };
      }
      if (attestResult.agentId !== agent.agent_id) {
        return { status: 401, body: { code: "AGENT_IDENTITY_MISMATCH", message: "Attestation sub does not match registered agent_id" } };
      }

      const session = await sessionStore.get(body.ath_session_id);
      if (!session) {
        return { status: 400, body: { code: "SESSION_NOT_FOUND", message: "Session not found" } };
      }

      if (session.client_id !== body.client_id) {
        return { status: 403, body: { code: "AGENT_IDENTITY_MISMATCH", message: "Session does not belong to this agent" } };
      }

      if (session.status !== "completed") {
        return { status: 400, body: { code: "SESSION_NOT_FOUND", message: "Authorization not completed" } };
      }

      const providerApproval = agent.approved_providers.find((p) => p.provider_id === session.provider_id);
      const agentApproved = providerApproval?.approved_scopes || [];
      const userConsented = session.user_consented_scopes || session.requested_scopes;
      const intersection = intersectScopes(agentApproved, userConsented, session.requested_scopes);

      if (intersection.effective.length === 0) {
        return { status: 403, body: { code: "SCOPE_NOT_APPROVED", message: "No effective scopes" } };
      }

      const expiresAt = new Date(Date.now() + tokenExpiry * 1000).toISOString();
      const accessToken = await tokenStore.create({
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

      const response: TokenResponse = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: tokenExpiry,
        effective_scopes: intersection.effective,
        provider_id: session.provider_id,
        agent_id: agent.agent_id,
        scope_intersection: {
          agent_approved: intersection.agent_approved,
          user_consented: intersection.user_consented,
          effective: intersection.effective,
        },
      };

      return { status: 200, body: response };
    },

    async revoke(req): Promise<ATHHandlerResponse> {
      const body = req.body as TokenRevocationRequest;
      if (!body?.token) {
        return { status: 400, body: { code: "TOKEN_INVALID", message: "Missing token" } };
      }

      if (body.client_id) {
        if (!body.client_secret) {
          return { status: 400, body: { code: "AGENT_NOT_REGISTERED", message: "Missing client_secret (required for agent-initiated revocation)" } };
        }
        const agent = await registry.get(body.client_id);
        if (!agent) {
          return { status: 403, body: { code: "AGENT_NOT_REGISTERED", message: "Agent not registered" } };
        }
        if (hashSecret(body.client_secret) !== agent.client_secret_hash) {
          return { status: 401, body: { code: "AGENT_NOT_REGISTERED", message: "Invalid credentials" } };
        }

        const bound = await tokenStore.get(body.token);
        if (bound && bound.client_id !== body.client_id) {
          return { status: 403, body: { code: "AGENT_IDENTITY_MISMATCH", message: "Token does not belong to this agent" } };
        }
      }

      const revoked = await tokenStore.revoke(body.token);
      if (!revoked) {
        return { status: 200, body: { message: "Token revoked" } };
      }

      return { status: 200, body: { message: "Token revoked" } };
    },
  };
}
