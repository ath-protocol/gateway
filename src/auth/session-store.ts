/**
 * Authorization session store — in-memory storage for pending OAuth sessions.
 */
import crypto from "node:crypto";
import type { AuthorizationSession } from "../types.js";

const sessions = new Map<string, AuthorizationSession>();

export const sessionStore = {
  async create(
    data: Omit<AuthorizationSession, "session_id" | "created_at">,
  ): Promise<AuthorizationSession> {
    const session: AuthorizationSession = {
      ...data,
      session_id: `ath_sess_${crypto.randomBytes(12).toString("hex")}`,
      created_at: new Date().toISOString(),
    };
    sessions.set(session.session_id, session);
    return session;
  },

  async get(sessionId: string): Promise<AuthorizationSession | null> {
    const session = sessions.get(sessionId) ?? null;
    if (session && new Date(session.expires_at) < new Date()) {
      session.status = "failed";
      session.error = "Session expired";
    }
    return session;
  },

  async update(sessionId: string, updates: Partial<AuthorizationSession>): Promise<void> {
    const session = sessions.get(sessionId);
    if (session) {
      Object.assign(session, updates);
    }
  },

  async delete(sessionId: string): Promise<void> {
    sessions.delete(sessionId);
  },

  async getByState(state: string): Promise<AuthorizationSession | null> {
    for (const session of sessions.values()) {
      if (session.oauth_state === state) return session;
    }
    return null;
  },

  clear(): void {
    sessions.clear();
  },
};
