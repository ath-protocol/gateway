import { describe, it, expect } from "vitest";
import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { verifyAttestation } from "../attestation.js";

describe("verifyAttestation", () => {
  it("verifies a valid attestation JWT", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const agentId = "https://agent.example.com/.well-known/agent.json";

    const jwt = await new SignJWT({ capabilities: [] })
      .setProtectedHeader({ alg: "ES256", kid: "test-key" })
      .setIssuer(agentId)
      .setSubject(agentId)
      .setAudience("https://gateway.example.com")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

    const result = await verifyAttestation(jwt, {
      audience: "https://gateway.example.com",
      publicKey,
    });

    expect(result.valid).toBe(true);
    expect(result.agentId).toBe(agentId);
  });

  it("rejects an expired JWT", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const agentId = "https://agent.example.com/.well-known/agent.json";

    const jwt = await new SignJWT({ capabilities: [] })
      .setProtectedHeader({ alg: "ES256", kid: "test-key" })
      .setIssuer(agentId)
      .setSubject(agentId)
      .setAudience("https://gateway.example.com")
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(privateKey);

    const result = await verifyAttestation(jwt, {
      audience: "https://gateway.example.com",
      publicKey,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain("expired");
  });

  it("rejects wrong audience", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const agentId = "https://agent.example.com/.well-known/agent.json";

    const jwt = await new SignJWT({ capabilities: [] })
      .setProtectedHeader({ alg: "ES256", kid: "test-key" })
      .setIssuer(agentId)
      .setSubject(agentId)
      .setAudience("https://other-gateway.example.com")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

    const result = await verifyAttestation(jwt, {
      audience: "https://gateway.example.com",
      publicKey,
    });

    expect(result.valid).toBe(false);
  });

  it("supports skip signature verification mode", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const agentId = "https://agent.example.com/.well-known/agent.json";

    const jwt = await new SignJWT({ capabilities: [] })
      .setProtectedHeader({ alg: "ES256", kid: "test-key" })
      .setIssuer(agentId)
      .setSubject(agentId)
      .setAudience("https://gateway.example.com")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

    const result = await verifyAttestation(jwt, {
      audience: "https://gateway.example.com",
      skipSignatureVerification: true,
    });

    expect(result.valid).toBe(true);
    expect(result.agentId).toBe(agentId);
  });
});
