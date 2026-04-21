import { describe, it, expect } from "vitest";
import { InMemoryTokenStore } from "../tokens.js";

describe("InMemoryTokenStore", () => {
  it("creates and retrieves a token", async () => {
    const store = new InMemoryTokenStore();
    const token = await store.create({
      agent_id: "https://agent.example.com/.well-known/agent.json",
      client_id: "ath_test",
      user_id: "user-1",
      provider_id: "github",
      scopes: ["repo"],
      oauth_connection_id: "conn_1",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    });

    expect(token).toMatch(/^ath_tk_/);
    const bound = await store.get(token);
    expect(bound).not.toBeNull();
    expect(bound!.agent_id).toBe("https://agent.example.com/.well-known/agent.json");
    expect(bound!.revoked).toBe(false);
  });

  it("revokes a token", async () => {
    const store = new InMemoryTokenStore();
    const token = await store.create({
      agent_id: "https://agent.example.com/.well-known/agent.json",
      client_id: "ath_test",
      user_id: "user-1",
      provider_id: "github",
      scopes: ["repo"],
      oauth_connection_id: "conn_1",
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    });

    expect(await store.revoke(token)).toBe(true);
    const bound = await store.get(token);
    expect(bound!.revoked).toBe(true);
  });

  it("returns false when revoking unknown token", async () => {
    const store = new InMemoryTokenStore();
    expect(await store.revoke("nonexistent")).toBe(false);
  });
});
