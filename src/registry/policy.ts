/**
 * Approval policy — decides what scopes an agent gets approved for.
 *
 * Reads available_scopes from the provider store (configured via dashboard/file/env).
 * Falls back to hardcoded demo providers when no providers are configured (mock mode).
 *
 * Production: extend this with manual review, allowlist-based, or registry-backed policy.
 */
import type { ProviderApproval } from "../types.js";
import { providerStore } from "../providers/store.js";

const DEMO_PROVIDERS: Record<string, string[]> = {
  github: ["repo", "read:user", "user:email", "read:org"],
  "google-mail": ["gmail.readonly", "gmail.send", "gmail.modify"],
  slack: ["channels:read", "chat:write", "users:read"],
  "google-calendar": ["calendar.readonly", "calendar.events"],
};

export interface PolicyResult {
  status: "approved" | "pending" | "denied";
  approved_providers: ProviderApproval[];
}

export async function evaluatePolicy(
  _agentId: string,
  requestedProviders: { provider_id: string; scopes: string[] }[],
): Promise<PolicyResult> {
  if (requestedProviders.length === 0) {
    return { status: "denied", approved_providers: [] };
  }

  const approvedProviders: ProviderApproval[] = [];

  for (const req of requestedProviders) {
    const provider = providerStore.get(req.provider_id);
    const availableScopes = provider?.available_scopes || DEMO_PROVIDERS[req.provider_id];

    if (!availableScopes) {
      approvedProviders.push({
        provider_id: req.provider_id,
        approved_scopes: [],
        denied_scopes: req.scopes,
        denial_reason: `Provider "${req.provider_id}" not available`,
      });
      continue;
    }

    const approved: string[] = [];
    const denied: string[] = [];

    for (const scope of req.scopes) {
      if (availableScopes.includes(scope)) {
        approved.push(scope);
      } else {
        denied.push(scope);
      }
    }

    approvedProviders.push({
      provider_id: req.provider_id,
      approved_scopes: approved,
      denied_scopes: denied,
      denial_reason: denied.length > 0 ? "Scope not in provider's available scopes" : undefined,
    });
  }

  const hasAnyApproved = approvedProviders.some((p) => p.approved_scopes.length > 0);
  return {
    status: hasAnyApproved ? "approved" : "denied",
    approved_providers: approvedProviders,
  };
}

export function getAvailableProviders(): Record<string, string[]> {
  const configured = providerStore.getAll();
  if (Object.keys(configured).length > 0) {
    return Object.fromEntries(
      Object.entries(configured).map(([id, p]) => [id, p.available_scopes]),
    );
  }
  return { ...DEMO_PROVIDERS };
}
