/**
 * Shared utilities — delegates to @ath-protocol/server for protocol operations.
 */
import crypto from "node:crypto";

// Re-export SDK credential utilities as the canonical source
export { hashSecret, generateCredentials } from "@ath-protocol/server";

/** Generate a cryptographically random ID with a prefix (for gateway-specific entities like users). */
export function generateId(prefix: string, bytes: number = 8): string {
  return `${prefix}_${crypto.randomBytes(bytes).toString("hex")}`;
}
