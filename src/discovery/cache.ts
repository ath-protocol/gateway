/**
 * Discovery document cache — invalidated when provider configuration changes.
 */
import type { DiscoveryDocument } from "../types.js";

let cachedDiscovery: DiscoveryDocument | null = null;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

export function getCachedDiscovery(now: number): DiscoveryDocument | null {
  if (cachedDiscovery && now < cacheExpiry) return cachedDiscovery;
  return null;
}

export function setCachedDiscovery(doc: DiscoveryDocument, now: number): void {
  cachedDiscovery = doc;
  cacheExpiry = now + CACHE_TTL_MS;
}

export function invalidateDiscoveryCache(): void {
  cachedDiscovery = null;
  cacheExpiry = 0;
}
