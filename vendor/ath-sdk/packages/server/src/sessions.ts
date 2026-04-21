/**
 * Session store — interface + in-memory implementation for authorization sessions.
 */
import crypto from "node:crypto";

export type SessionStatus = "pending" | "oauth_in_progress" | "completed" | "failed";

export interface AuthorizationSession {
  session_id: string;
  client_id: string;
  provider_id: string;
  requested_scopes: string[];
  user_id?: string;
  oauth_state: string;
  oauth_connection_id?: string;
  code_verifier?: string;
  resource?: string;
  user_consented_scopes?: string[];
  created_at: string;
  expires_at: string;
  status: SessionStatus;
  error?: string;
  user_redirect_uri: string;
}

export interface SessionStore {
  create(data: Omit<AuthorizationSession, "session_id" | "created_at">): Promise<AuthorizationSession>;
  get(sessionId: string): Promise<AuthorizationSession | null>;
  getByState(state: string): Promise<AuthorizationSession | null>;
  update(sessionId: string, fields: Partial<AuthorizationSession>): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

export class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, AuthorizationSession>();

  async create(data: Omit<AuthorizationSession, "session_id" | "created_at">): Promise<AuthorizationSession> {
    const session: AuthorizationSession = {
      ...data,
      session_id: `ath_sess_${crypto.randomBytes(8).toString("hex")}`,
      created_at: new Date().toISOString(),
    };
    this.sessions.set(session.session_id, session);
    return session;
  }

  async get(sessionId: string): Promise<AuthorizationSession | null> {
    return this.sessions.get(sessionId) || null;
  }

  async getByState(state: string): Promise<AuthorizationSession | null> {
    for (const s of this.sessions.values()) {
      if (s.oauth_state === state) return s;
    }
    return null;
  }

  async update(sessionId: string, fields: Partial<AuthorizationSession>): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) Object.assign(session, fields);
  }

  async delete(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }
}
