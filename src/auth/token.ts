/**
 * ATH Token generation, validation, and storage.
 * Tokens are opaque strings mapped to binding info in memory.
 */
import crypto from "node:crypto";
import type { BoundToken } from "../types.js";

const tokens = new Map<string, BoundToken>();

function generateTokenString(): string {
  return `ath_tk_${crypto.randomBytes(32).toString("hex")}`;
}

export const tokenStore = {
  async create(binding: Omit<BoundToken, "revoked">): Promise<string> {
    const token = generateTokenString();
    tokens.set(token, { ...binding, revoked: false });
    return token;
  },

  async get(token: string): Promise<BoundToken | null> {
    return tokens.get(token) ?? null;
  },

  async validate(token: string): Promise<BoundToken | null> {
    const bound = tokens.get(token);
    if (!bound) return null;
    if (bound.revoked) return null;
    if (new Date(bound.expires_at) < new Date()) return null;
    return bound;
  },

  async revoke(token: string): Promise<boolean> {
    const bound = tokens.get(token);
    if (!bound) return false;
    bound.revoked = true;
    return true;
  },

  clear(): void {
    tokens.clear();
  },
};
