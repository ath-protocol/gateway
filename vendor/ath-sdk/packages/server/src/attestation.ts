/**
 * Agent attestation verification — uses `jose` for JWT verification.
 *
 * Verifies that an agent attestation JWT is:
 *  - Signed with a valid key (ES256)
 *  - Not expired
 *  - Addressed to the correct audience
 *  - Issued by the agent_id
 *  - Contains a unique jti (replay protection)
 */
import { jwtVerify, importJWK, decodeJwt, decodeProtectedHeader, errors as joseErrors } from "jose";
import type { CryptoKey, KeyObject } from "jose";

type KeyLike = CryptoKey | KeyObject;

export interface JtiReplayCache {
  has(jti: string): boolean | Promise<boolean>;
  add(jti: string): void | Promise<void>;
}

/**
 * Simple in-memory jti cache with automatic TTL-based eviction.
 * Suitable for single-process deployments; replace with a shared store
 * (e.g. Redis) for multi-replica setups.
 */
export class InMemoryJtiCache implements JtiReplayCache {
  private seen = new Map<string, number>();
  private ttlMs: number;

  constructor(ttlMs = 3600_000) {
    this.ttlMs = ttlMs;
  }

  has(jti: string): boolean {
    this.evict();
    return this.seen.has(jti);
  }

  add(jti: string): void {
    this.seen.set(jti, Date.now());
  }

  private evict(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [k, ts] of this.seen) {
      if (ts < cutoff) this.seen.delete(k);
    }
  }
}

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
  /** jti replay cache. When provided, replayed jti values are rejected. */
  jtiCache?: JtiReplayCache;
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
    let payload: { sub?: string; jti?: string; iss?: string };

    if (options.skipSignatureVerification) {
      const header = decodeProtectedHeader(token);
      if (header.alg !== "ES256") {
        return { valid: false, error: `Unsupported algorithm: ${header.alg}` };
      }
      payload = decodeJwt(token);
    } else {
      const resolve = options.resolvePublicKey || fetchAgentPublicKey;
      const rawPayload = decodeJwt(token);

      const issuer = rawPayload.iss;
      if (!issuer) return { valid: false, error: "Missing issuer claim" };

      const publicKey = options.publicKey || (await resolve(issuer));

      const result = await jwtVerify(token, publicKey, {
        algorithms: ["ES256"],
        audience: options.audience,
        issuer,
      });
      payload = result.payload;
    }

    if (options.jtiCache) {
      const jti = payload.jti;
      if (!jti) {
        return { valid: false, error: "Missing jti claim (required for replay protection)" };
      }
      if (await options.jtiCache.has(jti)) {
        return { valid: false, error: "Replayed attestation (duplicate jti)" };
      }
      await options.jtiCache.add(jti);
    }

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
