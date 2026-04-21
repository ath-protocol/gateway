# ATH TypeScript SDK

TypeScript SDK for the [Agent Trust Handshake (ATH) Protocol](https://github.com/ath-protocol/agent-trust-handshake-protocol) — an open, lightweight protocol for establishing trusted connections between AI agents and external services.

Supports both ATH deployment modes: **Gateway Mode** and **Native Mode**.

## Packages

| Package | Description |
|---------|-------------|
| [`@ath-protocol/types`](packages/types) | Auto-generated TypeScript types and Zod validators from the [ATH JSON Schema](https://github.com/ath-protocol/agent-trust-handshake-protocol/blob/main/schema/0.1/schema.json) |
| [`@ath-protocol/client`](packages/client) | Client classes for agents — `ATHGatewayClient` and `ATHNativeClient` |
| [`@ath-protocol/server`](packages/server) | Server helpers for building ATH gateways and native implementations |

## Installation

```bash
# Agent developers (client)
npm install @ath-protocol/client

# Gateway / service implementors (server)
npm install @ath-protocol/server

# Types only
npm install @ath-protocol/types
```

## Quick Start

### Gateway Mode — connect an agent to an ATH gateway

```typescript
import { ATHGatewayClient } from "@ath-protocol/client";
import { generateKeyPair } from "jose";

const { privateKey } = await generateKeyPair("ES256");

const client = new ATHGatewayClient({
  url: "http://localhost:3000",
  agentId: "https://my-agent.example.com/.well-known/agent.json",
  privateKey,
});

// 1. Discover available providers
const discovery = await client.discover();

// 2. Register agent (Phase A: app-side authorization)
const reg = await client.register({
  developer: { name: "My Company", id: "dev-001" },
  providers: [{ provider_id: "github", scopes: ["repo", "read:user"] }],
  purpose: "Code review assistant",
});

// 3. Start user authorization (Phase B)
const auth = await client.authorize("github", ["repo", "read:user"]);
// Direct user to auth.authorization_url for OAuth consent

// 4. Exchange for ATH token (after user consents)
const token = await client.exchangeToken(code, auth.ath_session_id);

// 5. Call APIs through the gateway proxy
const user = await client.proxy("github", "GET", "/user");

// 6. Revoke when done
await client.revoke();
```

### Native Mode — connect directly to an ATH-native service

```typescript
import { ATHNativeClient } from "@ath-protocol/client";
import { generateKeyPair } from "jose";

const { privateKey } = await generateKeyPair("ES256");

const client = new ATHNativeClient({
  url: "https://mail.example.com",
  agentId: "https://my-agent.example.com/.well-known/agent.json",
  privateKey,
});

// 1. Discover the service
const discovery = await client.discover(); // fetches /.well-known/ath-app.json

// 2. Register + authorize (same API as gateway mode)
await client.register({
  developer: { name: "My Company", id: "dev-001" },
  providers: [{ provider_id: "com.example.mail", scopes: ["mail:read"] }],
  purpose: "Email assistant",
});

const auth = await client.authorize("com.example.mail", ["mail:read"]);
// User consents...
const token = await client.exchangeToken(code, auth.ath_session_id);

// 3. Call service API directly (no proxy)
const messages = await client.api("GET", "/v1/messages");
```

### Server — build a native ATH service

```typescript
import {
  createATHHandlers,
  createServiceDiscoveryDocument,
  InMemoryAgentRegistry,
  InMemoryTokenStore,
  InMemorySessionStore,
} from "@ath-protocol/server";

// Create handlers for all ATH endpoints (uses openid-client for OAuth + PKCE)
const handlers = createATHHandlers({
  registry: new InMemoryAgentRegistry(),
  tokenStore: new InMemoryTokenStore(),
  sessionStore: new InMemorySessionStore(),
  config: {
    audience: "https://mail.example.com",
    callbackUrl: "https://mail.example.com/ath/callback",
    availableScopes: ["mail:read", "mail:send"],
    appId: "com.example.mail",
    oauth: {
      authorize_endpoint: "https://mail.example.com/oauth/authorize",
      token_endpoint: "https://mail.example.com/oauth/token",
      client_id: "my-client-id",
      client_secret: "my-client-secret",
    },
  },
});

// Wire handlers into your framework (Hono, Express, Fastify, etc.)
// handlers.register, handlers.authorize, handlers.callback, handlers.token, handlers.revoke

// Serve discovery document
const discoveryDoc = createServiceDiscoveryDocument({
  app_id: "com.example.mail",
  name: "Example Mail",
  authorization_endpoint: "https://mail.example.com/oauth/authorize",
  token_endpoint: "https://mail.example.com/oauth/token",
  scopes_supported: ["mail:read", "mail:send"],
  api_base: "https://mail.example.com/api",
});
```

## Schema Codegen

Types are auto-generated from the canonical [ATH JSON Schema](https://github.com/ath-protocol/agent-trust-handshake-protocol/blob/main/schema/0.1/schema.json):

```bash
pnpm run generate
```

This downloads `schema.json` and `meta.json` from the spec repo and generates:
- `packages/types/src/schema/types.gen.ts` — TypeScript interfaces
- `packages/types/src/schema/zod.gen.ts` — Zod validators
- `packages/types/src/schema/index.ts` — barrel with `ATH_ENDPOINTS` and `PROTOCOL_VERSION`

## Testing

```bash
pnpm run test        # 17 server unit tests
pnpm run test:e2e    # 18 E2E tests (real HTTP, real PKCE, no mocks)
pnpm run test:all    # 35 total
```

### Test structure

```
packages/server/src/__tests__/    # Unit tests — scopes, registry, tokens, attestation
test/                              # E2E tests — self-contained, real HTTP servers
├── mock-oauth-server.ts          # OAuth2 test server (PKCE S256, auto-approve)
├── e2e-gateway.test.ts           # Gateway mode: 7 tests
├── e2e-native.test.ts            # Native mode: 11 tests
└── vitest.config.ts
```

All E2E tests are self-contained — they build their own ATH servers using `@ath-protocol/server` handlers and the SDK's own mock OAuth server. Zero imports from outside this directory.

## Architecture

```
ath-protocol/agent-trust-handshake-protocol    ← Spec repo (source of truth)
    schema/0.1/schema.json                      ← JSON Schema for all protocol types
    schema/0.1/meta.json                        ← Endpoint definitions + protocol version

typescript-sdk/                                 ← This SDK (standalone, product-ready)
    scripts/generate.ts                         ← Downloads schema → generates types
    packages/
        types/    → @ath-protocol/types          (auto-generated, zero runtime deps)
        client/   → @ath-protocol/client         (ATHGatewayClient + ATHNativeClient)
        server/   → @ath-protocol/server         (handlers, registry, tokens, attestation)
    test/                                        ← E2E tests (self-contained)
    examples/
        client-basic.ts                          ← Runnable gateway mode demo
```

## License

MIT
