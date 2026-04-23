/**
 * Agent attestation JWT helpers — sign ES256 JWTs proving agent identity.
 */
import { SignJWT } from "jose";
import type { CryptoKey, KeyObject } from "jose";

export type KeyInput = CryptoKey | KeyObject | Uint8Array;

export async function signAttestation(opts: {
  agentId: string;
  privateKey: KeyInput;
  keyId: string;
  audience: string;
}): Promise<string> {
  const jti = globalThis.crypto?.randomUUID?.()
    ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;

  return new SignJWT({ capabilities: [] })
    .setProtectedHeader({ alg: "ES256", kid: opts.keyId })
    .setIssuer(opts.agentId)
    .setSubject(opts.agentId)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setExpirationTime("1h")
    .setJti(jti)
    .sign(opts.privateKey);
}
