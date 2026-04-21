/**
 * Agent attestation verification — uses `jose` for JWT verification.
 *
 * Verifies that an agent attestation JWT is:
 *  - Signed with a valid key (ES256)
 *  - Not expired
 *  - Addressed to the correct audience
 *  - Issued by the agent_id
 */
import { jwtVerify, importJWK, decodeJwt, decodeProtectedHeader, errors as joseErrors } from "jose";
import type { CryptoKey, KeyObject } from "jose";

type KeyLike = CryptoKey | KeyObject;

export interface AttestationResult {
  valid: boolean;
  agentId?: string;
  error?: string;
}

export interface AttestationVerifyOptions {
  audience: string;
  /** Provide a public key directly (for testing or when you already have it). */
  publicKey?: KeyLike | Uint8Array;
  /**
   * Fetch the agent's public key from their agent_id URI.
   * Defaults to fetching {iss}/.well-known/agent.json and reading `public_key`.
   * Override for custom key resolution.
   */
  resolvePublicKey?: (agentId: string) => Promise<KeyLike | Uint8Array>;
  /** Skip signature verification (development only). */
  skipSignatureVerification?: boolean;
}

async function fetchAgentPublicKey(agentId: string): Promise<KeyLike | Uint8Array> {
  const res = await fetch(agentId);
  if (!res.ok) {
    throw new Error(`Failed to fetch agent identity from ${agentId}: ${res.status}`);
  }
  const doc = (await res.json()) as { public_key?: unknown };
  if (!doc.public_key) {
    throw new Error(`No public_key in agent identity document at ${agentId}`);
  }
  if (typeof doc.public_key === "object") {
    return importJWK(doc.public_key as Parameters<typeof importJWK>[0], "ES256");
  }
  throw new Error("public_key must be a JWK object");
}

export async function verifyAttestation(
  token: string,
  options: AttestationVerifyOptions,
): Promise<AttestationResult> {
  try {
    if (options.skipSignatureVerification) {
      const header = decodeProtectedHeader(token);
      if (header.alg !== "ES256") {
        return { valid: false, error: `Unsupported algorithm: ${header.alg}` };
      }
      const payload = decodeJwt(token);
      return { valid: true, agentId: payload.sub as string };
    }

    const resolve = options.resolvePublicKey || fetchAgentPublicKey;
    const rawPayload = decodeJwt(token);

    const issuer = rawPayload.iss;
    if (!issuer) return { valid: false, error: "Missing issuer claim" };

    const publicKey = options.publicKey || (await resolve(issuer));

    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ["ES256"],
      audience: options.audience,
      issuer,
    });

    return { valid: true, agentId: payload.sub as string };
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      return { valid: false, error: "Attestation JWT has expired" };
    }
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      return { valid: false, error: `Claim validation failed: ${err.message}` };
    }
    return {
      valid: false,
      error: err instanceof Error ? err.message : "Unknown verification error",
    };
  }
}
