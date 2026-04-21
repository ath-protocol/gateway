import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryAgentRegistry, generateCredentials, hashSecret } from "../registry.js";

describe("InMemoryAgentRegistry", () => {
  let registry: InMemoryAgentRegistry;

  beforeEach(() => {
    registry = new InMemoryAgentRegistry();
  });

  it("registers and retrieves an agent", async () => {
    const { clientId, clientSecret, secretHash } = generateCredentials();
    await registry.register({
      client_id: clientId,
      client_secret_hash: secretHash,
      agent_id: "https://agent.example.com/.well-known/agent.json",
      agent_status: "approved",
      approved_providers: [{ provider_id: "github", approved_scopes: ["repo"], denied_scopes: [] }],
      approval_expires: "2027-01-01T00:00:00Z",
      registered_at: new Date().toISOString(),
      developer: { name: "Test", id: "dev-1" },
      purpose: "testing",
      redirect_uris: ["http://localhost/callback"],
    });

    const agent = await registry.get(clientId);
    expect(agent).not.toBeNull();
    expect(agent!.agent_id).toBe("https://agent.example.com/.well-known/agent.json");
    expect(hashSecret(clientSecret)).toBe(secretHash);
  });

  it("returns null for unknown agent", async () => {
    expect(await registry.get("nonexistent")).toBeNull();
  });

  it("deletes an agent", async () => {
    const { clientId, secretHash } = generateCredentials();
    await registry.register({
      client_id: clientId,
      client_secret_hash: secretHash,
      agent_id: "https://agent.example.com/.well-known/agent.json",
      agent_status: "approved",
      approved_providers: [],
      approval_expires: "2027-01-01T00:00:00Z",
      registered_at: new Date().toISOString(),
      developer: { name: "Test", id: "dev-1" },
      purpose: "testing",
      redirect_uris: [],
    });
    expect(await registry.delete(clientId)).toBe(true);
    expect(await registry.get(clientId)).toBeNull();
  });

  it("lists all agents", async () => {
    const { clientId: id1, secretHash: h1 } = generateCredentials();
    const { clientId: id2, secretHash: h2 } = generateCredentials();

    for (const [clientId, secretHash] of [[id1, h1], [id2, h2]]) {
      await registry.register({
        client_id: clientId,
        client_secret_hash: secretHash,
        agent_id: `https://${clientId}.example.com/.well-known/agent.json`,
        agent_status: "approved",
        approved_providers: [],
        approval_expires: "2027-01-01T00:00:00Z",
        registered_at: new Date().toISOString(),
        developer: { name: "Test", id: "dev-1" },
        purpose: "testing",
        redirect_uris: [],
      });
    }

    const all = await registry.list();
    expect(all).toHaveLength(2);
  });
});
