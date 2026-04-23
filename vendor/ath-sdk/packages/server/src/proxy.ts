/**
 * createProxyHandler — framework-agnostic implementation of the spec's
 * `ANY /ath/proxy/{provider_id}/{path}` endpoint (Gateway Mode).
 *
 * The handler enforces the trusted handshake at runtime:
 *   1. Validate the ATH bearer token (expiry + revocation + scope + binding).
 *   2. Verify `X-ATH-Agent-ID` matches the token's bound agent.
 *   3. Resolve the upstream URL for `provider_id` and the stored provider
 *      OAuth token for the bound `oauth_connection_id`.
 *   4. Forward method + path + body to upstream with the provider bearer.
 *   5. Stream the upstream response back — status, headers, body passthrough.
 *
 * The caller is responsible for routing `/ath/proxy/{provider_id}/{path}` to
 * this handler and for providing an `upstreams` resolver mapping `provider_id`
 * to a base URL.
 */
import type { TokenStore } from "./tokens.js";
import type { ProviderTokenStore } from "./provider-tokens.js";
import { validateToken } from "./validation.js";

export interface ProxyRequest {
  method: string;
  /** Full request path including `/ath/proxy/{provider_id}` prefix. */
  path: string;
  headers: Record<string, string | undefined>;
  body?: unknown;
  query?: Record<string, string>;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export type UpstreamResolver = (providerId: string) => string | null | undefined;

export interface ProxyHandlerConfig {
  tokenStore: TokenStore;
  providerTokenStore: ProviderTokenStore;
  /**
   * Maps `provider_id` to an upstream base URL (e.g. `https://api.github.com`).
   * Can be a plain object or a function for dynamic resolution.
   */
  upstreams: Record<string, string> | UpstreamResolver;
  /** Inject a custom fetch for testing/interception. Defaults to global fetch. */
  fetch?: typeof fetch;
}

export type ProxyHandler = (req: ProxyRequest) => Promise<ProxyResponse>;

/** Response headers we never forward from upstream back to the agent. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function extractBearer(headers: Record<string, string | undefined>): string | null {
  const raw = headers["authorization"] ?? headers["Authorization"];
  if (!raw || typeof raw !== "string") return null;
  if (!raw.startsWith("Bearer ")) return null;
  const token = raw.slice(7).trim();
  return token || null;
}

function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  return headers[name] ?? headers[name.toLowerCase()];
}

function resolveUpstream(cfg: ProxyHandlerConfig, providerId: string): string | null {
  const { upstreams } = cfg;
  const base = typeof upstreams === "function" ? upstreams(providerId) : upstreams[providerId];
  if (!base) return null;
  return base.replace(/\/$/, "");
}

function parseProxyPath(path: string): { providerId: string; upstreamPath: string } | null {
  const match = path.match(/^\/ath\/proxy\/([^/]+)(\/.*)?$/);
  if (!match) return null;
  return { providerId: match[1], upstreamPath: match[2] || "/" };
}

function errorResponse(status: number, code: string, message: string): ProxyResponse {
  return {
    status,
    headers: { "content-type": "application/json" },
    body: { code, message },
  };
}

export function createProxyHandler(cfg: ProxyHandlerConfig): ProxyHandler {
  const fetchImpl = cfg.fetch ?? fetch;

  return async function handle(req: ProxyRequest): Promise<ProxyResponse> {
    const token = extractBearer(req.headers);
    if (!token) {
      return errorResponse(401, "TOKEN_INVALID", "Missing or malformed Authorization header");
    }

    const parsed = parseProxyPath(req.path);
    if (!parsed) {
      return errorResponse(400, "INVALID_PATH", "Path must match /ath/proxy/{provider_id}/{path}");
    }
    const { providerId, upstreamPath } = parsed;

    const agentIdHeader = header(req.headers, "X-ATH-Agent-ID") ?? header(req.headers, "x-ath-agent-id");

    const result = await validateToken(cfg.tokenStore, token, {
      agentId: agentIdHeader,
    });
    if (!result.valid) {
      const status =
        result.code === "TOKEN_EXPIRED" || result.code === "TOKEN_REVOKED"
          ? 401
          : result.code === "AGENT_IDENTITY_MISMATCH"
            ? 403
            : 401;
      return errorResponse(status, result.code, result.message);
    }

    const bound = result.token;

    if (bound.provider_id !== providerId) {
      return errorResponse(403, "PROVIDER_MISMATCH", `Token is not valid for provider ${providerId}`);
    }

    const upstream = resolveUpstream(cfg, providerId);
    if (!upstream) {
      return errorResponse(403, "PROVIDER_NOT_CONFIGURED", `No upstream configured for ${providerId}`);
    }

    const providerTokens = await cfg.providerTokenStore.get(bound.oauth_connection_id);
    if (!providerTokens) {
      return errorResponse(502, "PROVIDER_TOKEN_MISSING", "No stored provider token for this connection");
    }

    // Build the upstream URL, carrying over any query string from the request.
    const query = req.query && Object.keys(req.query).length > 0 ? `?${new URLSearchParams(req.query).toString()}` : "";
    const upstreamUrl = `${upstream}${upstreamPath}${query}`;

    const fwdHeaders: Record<string, string> = {
      Authorization: `Bearer ${providerTokens.access_token}`,
    };
    // Forward select incoming headers but never the agent's ATH bearer or
    // the agent-id guard header (both are internal to ATH).
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined) continue;
      const lower = k.toLowerCase();
      if (lower === "authorization" || lower === "x-ath-agent-id" || lower === "host") continue;
      if (HOP_BY_HOP.has(lower)) continue;
      fwdHeaders[k] = v;
    }

    const hasBody = req.body !== undefined && req.body !== null && req.method.toUpperCase() !== "GET" && req.method.toUpperCase() !== "HEAD";
    const isJsonBody = hasBody && typeof req.body === "object";
    if (isJsonBody && !fwdHeaders["content-type"] && !fwdHeaders["Content-Type"]) {
      fwdHeaders["content-type"] = "application/json";
    }

    let upstreamRes: Response;
    try {
      upstreamRes = await fetchImpl(upstreamUrl, {
        method: req.method,
        headers: fwdHeaders,
        body: hasBody ? (isJsonBody ? JSON.stringify(req.body) : (req.body as BodyInit)) : undefined,
      });
    } catch (err) {
      return errorResponse(
        502,
        "UPSTREAM_ERROR",
        `Upstream request failed: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }

    const outHeaders: Record<string, string> = {};
    upstreamRes.headers.forEach((value, key) => {
      if (HOP_BY_HOP.has(key.toLowerCase())) return;
      outHeaders[key] = value;
    });

    const contentType = upstreamRes.headers.get("content-type") ?? "";
    let body: unknown;
    if (contentType.includes("application/json")) {
      try {
        body = await upstreamRes.json();
      } catch {
        body = null;
      }
    } else if (contentType.startsWith("text/")) {
      body = await upstreamRes.text();
    } else {
      body = await upstreamRes.arrayBuffer();
    }

    return { status: upstreamRes.status, headers: outHeaders, body };
  };
}
