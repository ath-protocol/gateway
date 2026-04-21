/**
 * Client-side error class for ATH protocol errors.
 */
import type { ATHErrorCode } from "@ath-protocol/types";

export class ATHClientError extends Error {
  constructor(
    public readonly code: ATHErrorCode | string,
    message: string,
    public readonly status?: number,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ATHClientError";
  }
}
