/**
 * ProviderTokenStore — storage for upstream OAuth tokens obtained on behalf of
 * an agent+user during a completed handshake.
 *
 * These tokens are the credentials the gateway uses to call the real service
 * provider. They are indexed by `connection_id` (the value stored on the
 * bound ATH token as `oauth_connection_id`). They MUST never leak to agents
 * or users — they live exclusively server-side and are consumed by the proxy.
 */
export interface ProviderTokens {
  access_token: string;
  refresh_token?: string;
  expires_at?: string;
  scope?: string;
}

export interface ProviderTokenStore {
  set(connectionId: string, tokens: ProviderTokens): Promise<void>;
  get(connectionId: string): Promise<ProviderTokens | null>;
  delete(connectionId: string): Promise<boolean>;
}

export class InMemoryProviderTokenStore implements ProviderTokenStore {
  private store = new Map<string, ProviderTokens>();

  async set(connectionId: string, tokens: ProviderTokens): Promise<void> {
    this.store.set(connectionId, tokens);
  }

  async get(connectionId: string): Promise<ProviderTokens | null> {
    return this.store.get(connectionId) ?? null;
  }

  async delete(connectionId: string): Promise<boolean> {
    return this.store.delete(connectionId);
  }
}
