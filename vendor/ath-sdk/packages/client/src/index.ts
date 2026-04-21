/**
 * @ath-protocol/client — TypeScript client for the ATH protocol.
 *
 * Two client classes for the two ATH deployment modes:
 * - ATHGatewayClient: connects to an ATH gateway (proxy mode)
 * - ATHNativeClient: connects directly to an ATH-native service
 */
export { ATHClientBase, type ATHClientConfig } from "./base.js";
export { ATHGatewayClient } from "./gateway.js";
export { ATHNativeClient } from "./native.js";
export { ATHClientError } from "./errors.js";
export { signAttestation, type KeyInput } from "./attestation.js";
export * from "@ath-protocol/types";
