/**
 * Reject replayed agent attestation JWTs by tracking `jti` until `exp`.
 */
import { decodeJwt } from "jose";

const usedJti = new Map<string, number>(); // jti -> expMs

function prune(now: number): void {
  for (const [jti, expMs] of usedJti) {
    if (expMs <= now) usedJti.delete(jti);
  }
}

export function assertFreshJti(token: string, nowMs: number = Date.now()): { ok: true } | { ok: false; error: string } {
  prune(nowMs);
  let payload: { jti?: unknown; exp?: unknown };
  try {
    payload = decodeJwt(token) as { jti?: unknown; exp?: unknown };
  } catch {
    return { ok: false, error: "Invalid attestation JWT" };
  }
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    return { ok: false, error: "Attestation JWT must include a non-empty jti claim" };
  }
  const expSec = typeof payload.exp === "number" ? payload.exp : undefined;
  if (expSec === undefined) {
    return { ok: false, error: "Attestation JWT must include exp claim" };
  }
  const expMs = expSec * 1000;
  if (usedJti.has(payload.jti)) {
    return { ok: false, error: "Attestation JWT jti has already been used (replay detected)" };
  }
  usedJti.set(payload.jti, expMs);
  return { ok: true };
}

export function clearJtiReplayStore(): void {
  usedJti.clear();
}
