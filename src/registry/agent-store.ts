/**
 * Agent Store — In-memory storage for registered agents, scoped by tenant (user).
 */
import type { RegisteredAgent } from "../types.js";

const agents = new Map<string, RegisteredAgent>();

export const agentStore = {
  async set(clientId: string, agent: RegisteredAgent): Promise<void> {
    agents.set(clientId, agent);
  },

  async get(clientId: string): Promise<RegisteredAgent | null> {
    return agents.get(clientId) ?? null;
  },

  /** Get by clientId, but only if it belongs to the given tenant. */
  async getScoped(clientId: string, tenantId: string): Promise<RegisteredAgent | null> {
    const a = agents.get(clientId) ?? null;
    if (a && a.tenant_id !== tenantId) return null;
    return a;
  },

  async getByAgentId(agentId: string): Promise<RegisteredAgent | null> {
    for (const agent of agents.values()) {
      if (agent.agent_id === agentId) return agent;
    }
    return null;
  },

  /** Same agent_id may exist for different tenants — search within tenant. */
  async getByAgentIdScoped(agentId: string, tenantId: string): Promise<RegisteredAgent | null> {
    for (const agent of agents.values()) {
      if (agent.agent_id === agentId && agent.tenant_id === tenantId) return agent;
    }
    return null;
  },

  async delete(clientId: string): Promise<void> {
    agents.delete(clientId);
  },

  async list(): Promise<RegisteredAgent[]> {
    return Array.from(agents.values());
  },

  /** List agents for a specific tenant. */
  async listByTenant(tenantId: string): Promise<RegisteredAgent[]> {
    return Array.from(agents.values()).filter((a) => a.tenant_id === tenantId);
  },

  clear(): void {
    agents.clear();
  },
};
