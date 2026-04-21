/**
 * Scope intersection — enforces the trusted handshake.
 *
 * Effective Scope = Agent Approved ∩ User Consented ∩ Requested
 */
import type { ScopeIntersection } from "@ath-protocol/types";

export interface ScopeIntersectionResult extends ScopeIntersection {
  requested: string[];
  denied: string[];
}

export function intersectScopes(
  agentApproved: string[],
  userConsented: string[],
  requested: string[],
): ScopeIntersectionResult {
  const approvedSet = new Set(agentApproved);
  const consentedSet = new Set(userConsented);

  const effective = requested.filter(
    (s) => approvedSet.has(s) && consentedSet.has(s),
  );
  const denied = requested.filter(
    (s) => !approvedSet.has(s) || !consentedSet.has(s),
  );

  return {
    agent_approved: agentApproved,
    user_consented: userConsented,
    effective,
    requested,
    denied,
  };
}
