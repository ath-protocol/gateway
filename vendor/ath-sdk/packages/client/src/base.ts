/**
 * ATHClientBase — abstract base class for ATH protocol clients.
 * Shared logic for gateway mode and native mode.
 */
import type {
  AgentRegistrationResponse,
  AuthorizationResponse,
  TokenResponse,
  DeveloperInfo,
  ProviderScopeRequest,
} from "@ath-protocol/types";
import { signAttestation, type KeyInput } from "./attestation.js";
import { ATHClientError } from "./errors.js";

export interface ATHClientConfig {
  url: string;
  agentId: string;
  privateKey: KeyInput;
  keyId?: string;
}

export abstract class ATHClientBase {
  protected url: string;
  protected agentId: string;
  protected privateKey: KeyInput;
  protected keyId: string;

  protected clientId?: string;
  protected clientSecret?: string;
  protected currentToken?: string;

  constructor(config: ATHClientConfig) {
    this.url = config.url.replace(/\/$/, "");
    this.agentId = config.agentId;
    this.privateKey = config.privateKey;
    this.keyId = config.keyId || "default";
  }

  protected async attest(audience?: string): Promise<string> {
    return signAttestation({
      agentId: this.agentId,
      privateKey: this.privateKey,
      keyId: this.keyId,
      audience: audience || this.url,
    });
  }

  protected async request<T>(
    method: string,
    fullUrl: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<T> {
    const res = await fetch(fullUrl, {
      method,
      headers: { "Content-Type": "application/json", ...headers },
      body: body ? JSON.stringify(body) : undefined,
    });

    let data: T & { code?: string; message?: string };
    try {
      data = (await res.json()) as T & { code?: string; message?: string };
    } catch {
      if (!res.ok) {
        throw new ATHClientError("UNKNOWN", `Request failed: ${res.status} ${res.statusText}`, res.status);
      }
      throw new ATHClientError("UNKNOWN", "Response was not valid JSON");
    }

    if (!res.ok) {
      throw new ATHClientError(
        data.code || "UNKNOWN",
        data.message || `Request failed: ${res.status}`,
        res.status,
        data as Record<string, unknown>,
      );
    }

    return data;
  }

  protected athUrl(path: string): string {
    return `${this.url}${path}`;
  }

  abstract discover(): Promise<unknown>;

  async register(options: {
    developer: DeveloperInfo;
    providers: ProviderScopeRequest[];
    purpose: string;
    redirectUris?: string[];
  }): Promise<AgentRegistrationResponse> {
    const attestation = await this.attest();

    const res = await this.request<AgentRegistrationResponse>("POST", this.athUrl("/ath/agents/register"), {
      agent_id: this.agentId,
      agent_attestation: attestation,
      developer: options.developer,
      requested_providers: options.providers,
      purpose: options.purpose,
      redirect_uris: options.redirectUris || [`${this.url}/ath/callback`],
    });

    this.clientId = res.client_id;
    this.clientSecret = res.client_secret;

    return res;
  }

  async authorize(
    provider: string,
    scopes: string[],
    options?: { redirectUri?: string; resource?: string },
  ): Promise<AuthorizationResponse> {
    if (!this.clientId) {
      throw new ATHClientError("NOT_REGISTERED", "Agent not registered. Call register() first.");
    }

    const attestation = await this.attest();
    const stateBytes = new Uint8Array(16);
    (globalThis.crypto ?? await import("node:crypto")).getRandomValues(stateBytes);
    const state = Array.from(stateBytes, (b) => b.toString(16).padStart(2, "0")).join("");

    return this.request<AuthorizationResponse>("POST", this.athUrl("/ath/authorize"), {
      client_id: this.clientId,
      agent_attestation: attestation,
      provider_id: provider,
      scopes,
      user_redirect_uri: options?.redirectUri || `${this.url}/ath/callback`,
      state,
      resource: options?.resource,
    });
  }

  async exchangeToken(code: string, sessionId: string): Promise<TokenResponse> {
    if (!this.clientId || !this.clientSecret) {
      throw new ATHClientError("NOT_REGISTERED", "Agent not registered. Call register() first.");
    }

    const tokenEndpoint = this.athUrl("/ath/token");
    const attestation = await this.attest(tokenEndpoint);

    const res = await this.request<TokenResponse>("POST", tokenEndpoint, {
      grant_type: "authorization_code",
      client_id: this.clientId,
      client_secret: this.clientSecret,
      agent_attestation: attestation,
      code,
      ath_session_id: sessionId,
    });

    this.currentToken = res.access_token;
    return res;
  }

  async revoke(): Promise<void> {
    if (!this.currentToken || !this.clientId) return;

    await this.request("POST", this.athUrl("/ath/revoke"), {
      client_id: this.clientId,
      client_secret: this.clientSecret,
      token: this.currentToken,
    });

    this.currentToken = undefined;
  }

  getClientId(): string | undefined {
    return this.clientId;
  }

  setCredentials(clientId: string, clientSecret: string): void {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  setToken(token: string): void {
    this.currentToken = token;
  }
}
