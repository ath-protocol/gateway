/**
 * ATHNativeClient — client for ATH native mode.
 * Connects directly to a service that implements ATH endpoints natively.
 */
import type { ServiceDiscoveryDocument } from "@ath-protocol/types";
import { ATHClientBase } from "./base.js";
import { ATHClientError } from "./errors.js";

export class ATHNativeClient extends ATHClientBase {
  private apiBase?: string;

  async discover(): Promise<ServiceDiscoveryDocument> {
    const doc = await this.request<ServiceDiscoveryDocument>("GET", this.athUrl("/.well-known/ath-app.json"));
    this.apiBase = doc.api_base.replace(/\/$/, "");
    return doc;
  }

  async api<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    if (!this.currentToken) {
      throw new ATHClientError("NO_TOKEN", "No active token. Complete authorization flow first.");
    }
    if (!this.apiBase) {
      throw new ATHClientError("NOT_DISCOVERED", "Service not discovered. Call discover() first.");
    }

    const fullPath = path.startsWith("/") ? path : `/${path}`;
    return this.request<T>(method, `${this.apiBase}${fullPath}`, body, {
      Authorization: `Bearer ${this.currentToken}`,
      "X-ATH-Agent-ID": this.agentId,
    });
  }
}
