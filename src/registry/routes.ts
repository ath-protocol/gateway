/**
 * Registry HTTP routes — agent registration, status, revocation.
 * All operations are scoped to the authenticated user (tenant).
 */
import { Hono } from "hono";
import { agentStore } from "./agent-store.js";
import { verifyAttestation } from "@ath-protocol/server";
import { evaluatePolicy } from "./policy.js";
import { ATHError, ATHErrorCode } from "../types.js";
import type { AgentRegistrationRequest, RegisteredAgent, AppEnv } from "../types.js";
import { loadConfig } from "../config.js";
import { hashSecret, generateCredentials } from "../utils.js";

export const registryRoutes = new Hono<AppEnv>();

// POST /ath/agents/register
registryRoutes.post("/register", async (c) => {
  const body = (await c.req.json()) as AgentRegistrationRequest;
  const tenantId = c.get("userId") as string;

  if (!body.agent_id || !body.agent_attestation || !body.requested_providers?.length) {
    throw new ATHError(
      ATHErrorCode.INVALID_ATTESTATION,
      "Missing required fields: agent_id, agent_attestation, requested_providers",
      400,
    );
  }

  // Duplicate check within this tenant only
  const existing = await agentStore.getByAgentIdScoped(body.agent_id, tenantId);
  if (existing) {
    return c.json(
      { code: "CONFLICT", message: "Agent already registered", client_id: existing.client_id },
      409,
    );
  }

  const config = loadConfig();
  const attestResult = await verifyAttestation(body.agent_attestation, {
    audience: config.gatewayUrl,
    skipSignatureVerification: true,
  });
  if (!attestResult.valid) {
    throw new ATHError(ATHErrorCode.INVALID_ATTESTATION, attestResult.error || "Invalid attestation", 401);
  }

  const policyResult = await evaluatePolicy(body.agent_id, body.requested_providers);

  const { clientId, clientSecret, secretHash: clientSecretHash } = generateCredentials();

  const agent: RegisteredAgent = {
    tenant_id: tenantId,
    client_id: clientId,
    client_secret_hash: clientSecretHash,
    agent_id: body.agent_id,
    agent_status: policyResult.status,
    approved_providers: policyResult.approved_providers,
    approval_expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    registered_at: new Date().toISOString(),
    developer: body.developer || { name: "unknown", id: "unknown" },
    purpose: body.purpose || "",
    redirect_uris: body.redirect_uris || [],
  };

  await agentStore.set(clientId, agent);

  return c.json(
    {
      client_id: clientId,
      client_secret: clientSecret,
      agent_status: agent.agent_status,
      approved_providers: agent.approved_providers,
      approval_expires: agent.approval_expires,
    },
    201,
  );
});

// GET /ath/agents/:clientId
registryRoutes.get("/:clientId", async (c) => {
  const clientId = c.req.param("clientId");
  const tenantId = c.get("userId") as string;
  const agent = await agentStore.getScoped(clientId, tenantId);

  if (!agent) {
    throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Agent not found", 404);
  }

  return c.json({
    client_id: agent.client_id,
    agent_id: agent.agent_id,
    agent_status: agent.agent_status,
    approved_providers: agent.approved_providers,
    approval_expires: agent.approval_expires,
    registered_at: agent.registered_at,
    developer: agent.developer,
    purpose: agent.purpose,
  });
});

// DELETE /ath/agents/:clientId
registryRoutes.delete("/:clientId", async (c) => {
  const clientId = c.req.param("clientId");
  const tenantId = c.get("userId") as string;
  const agent = await agentStore.getScoped(clientId, tenantId);

  if (!agent) {
    throw new ATHError(ATHErrorCode.AGENT_NOT_REGISTERED, "Agent not found", 404);
  }

  await agentStore.delete(clientId);
  return c.json({ message: "Agent registration revoked" });
});
