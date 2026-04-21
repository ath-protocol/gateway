/**
 * Agent registry — interface + in-memory implementation.
 *
 * Tracks registered agents, their approved providers/scopes, and credentials.
 */
import type { AgentStatus, ProviderApproval, DeveloperInfo } from "@ath-protocol/types";
import crypto from "node:crypto";

export interface RegisteredAgent {
  client_id: string;
  client_secret_hash: string;
  agent_id: string;
  agent_status: AgentStatus;
  approved_providers: ProviderApproval[];
  approval_expires: string;
  registered_at: string;
  developer: DeveloperInfo;
  purpose: string;
  redirect_uris: string[];
}

export interface AgentRegistry {
  get(clientId: string): Promise<RegisteredAgent | null>;
  register(agent: RegisteredAgent): Promise<void>;
  delete(clientId: string): Promise<boolean>;
  list(): Promise<RegisteredAgent[]>;
}

export function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

export function generateCredentials(): { clientId: string; clientSecret: string; secretHash: string } {
  const clientId = `ath_${crypto.randomBytes(8).toString("hex")}`;
  const clientSecret = `ath_secret_${crypto.randomBytes(16).toString("hex")}`;
  const secretHash = hashSecret(clientSecret);
  return { clientId, clientSecret, secretHash };
}

export class InMemoryAgentRegistry implements AgentRegistry {
  private agents = new Map<string, RegisteredAgent>();

  async get(clientId: string): Promise<RegisteredAgent | null> {
    return this.agents.get(clientId) || null;
  }

  async register(agent: RegisteredAgent): Promise<void> {
    this.agents.set(agent.client_id, agent);
  }

  async delete(clientId: string): Promise<boolean> {
    return this.agents.delete(clientId);
  }

  async list(): Promise<RegisteredAgent[]> {
    return [...this.agents.values()];
  }
}
