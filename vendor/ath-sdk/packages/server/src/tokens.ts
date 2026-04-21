/**
 * Token store — interface + in-memory implementation for ATH access tokens.
 */
import crypto from "node:crypto";

export interface BoundToken {
  token: string;
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

export interface TokenStore {
  create(data: Omit<BoundToken, "token" | "revoked">): Promise<string>;
  get(token: string): Promise<BoundToken | null>;
  revoke(token: string): Promise<boolean>;
}

export class InMemoryTokenStore implements TokenStore {
  private tokens = new Map<string, BoundToken>();

  async create(data: Omit<BoundToken, "token" | "revoked">): Promise<string> {
    const token = `ath_tk_${crypto.randomBytes(16).toString("hex")}`;
    this.tokens.set(token, { ...data, token, revoked: false });
    return token;
  }

  async get(token: string): Promise<BoundToken | null> {
    return this.tokens.get(token) || null;
  }

  async revoke(token: string): Promise<boolean> {
    const bound = this.tokens.get(token);
    if (!bound) return false;
    bound.revoked = true;
    return true;
  }
}
