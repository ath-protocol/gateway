/**
 * ATHGatewayClient — client for ATH gateway mode.
 * Connects to an ATH gateway that proxies requests to upstream service providers.
 */
import type { DiscoveryDocument } from "@ath-protocol/types";
import { ATHClientBase } from "./base.js";
import { ATHClientError } from "./errors.js";

export class ATHGatewayClient extends ATHClientBase {
  async discover(): Promise<DiscoveryDocument> {
    return this.request<DiscoveryDocument>("GET", this.athUrl("/.well-known/ath.json"));
  }

  async proxy<T = unknown>(
    provider: string,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    if (!this.currentToken) {
      throw new ATHClientError("NO_TOKEN", "No active token. Complete authorization flow first.");
    }

    return this.request<T>(method, this.athUrl(`/ath/proxy/${provider}${path}`), body, {
      Authorization: `Bearer ${this.currentToken}`,
      "X-ATH-Agent-ID": this.agentId,
    });
  }
}
