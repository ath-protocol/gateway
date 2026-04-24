# ATH Gateway

English | [中文](README.md)

Standalone [ATH (Agent Trust Handshake)](https://github.com/ath-protocol/agent-trust-handshake-protocol) gateway server. Multi-tenant user accounts, admin-controlled OAuth providers, and full protocol enforcement — built on [Hono](https://hono.dev) and the official [`@ath-protocol/server`](https://github.com/ath-protocol/typescript-sdk) SDK.

## Quick start

```bash
git clone --recurse-submodules https://github.com/ath-protocol/gateway.git
cd gateway
pnpm install
pnpm run dev
```

On first start a **root** admin account is created with a random password printed to stdout. Use it to log in at `http://localhost:3000/ui/dashboard`.

## Features

- **User accounts** — signup (configurable), login, scrypt-hashed passwords, root user bootstrap
- **Multi-tenant isolation** — agents, sessions, and tokens scoped per user; cross-tenant access blocked
- **Admin-only providers** — only admin users can add/remove OAuth provider configurations
- **ATH protocol** — discovery, agent registration, attestation, authorization (PKCE via `openid-client`), scope intersection, token binding, proxy, revocation
- **Protocol security hardening** — JTI replay protection, mandatory `state` parameter, `redirect_uri` exact-match validation, `agent_attestation` required on token exchange, `client_secret` required for agent-initiated revocation (RFC 7009)
- **Product dashboard** — login page, per-user agent list, admin provider management

## Protocol alignment (v0.1)

This gateway is aligned with the latest [ATH Protocol spec v0.1](https://github.com/ath-protocol/agent-trust-handshake-protocol) and [TypeScript SDK](https://github.com/ath-protocol/typescript-sdk). Key changes:

| Endpoint | Change |
|---|---|
| `POST /ath/agents/register` | Attestation JWT must include `jti` (unique ID); gateway rejects replayed values |
| `POST /ath/authorize` | `state` is now required; `redirect_uri` validated by exact-match against registered URIs |
| `POST /ath/token` | New required field `agent_attestation`; `aud` must be the token endpoint URL; `sub` must match the registered `agent_id` |
| `POST /ath/revoke` | `client_secret` is now required when called by an agent (RFC 7009) |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ATH_PORT` | `3000` | HTTP listen port |
| `ATH_HOST` | `0.0.0.0` | Bind address |
| `ATH_GATEWAY_HOST` | `http://localhost:3000` | Public URL of this gateway (used for OAuth callbacks, etc.) |
| `ATH_PUBLIC_GATEWAY_URL` | same as `ATH_GATEWAY_HOST` | URL used for attestation JWT `aud` checks (useful for testing) |
| `ATH_GATEWAY_SECRET` | (random at boot) | Secret for legacy admin API auth |
| `ATH_SIGNUP_ENABLED` | `false` | Enable user self-registration |
| `ATH_JWT_SECRET` | (dev default) | Secret for session JWT signing — **set in production** |
| `ATH_SESSION_TOKEN_TTL` | `86400` | Session token lifetime (seconds) |
| `ATH_TOKEN_EXPIRY` | `3600` | ATH access token lifetime (seconds) |
| `ATH_SESSION_EXPIRY` | `600` | OAuth session timeout (seconds) |
| `OAUTH_BASE_URL` | — | Legacy single-provider OAuth base URL |
| `OAUTH_CLIENT_ID` | — | Legacy single-provider client ID |
| `OAUTH_CLIENT_SECRET` | — | Legacy single-provider client secret |

Providers can also be configured via `providers.json` in the working directory or the `ATH_PROVIDERS` env var (JSON object).

## API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/.well-known/ath.json` | Public | Gateway discovery document |
| `GET` | `/health` | Public | Health check |
| `POST` | `/auth/signup` | Public | Create user account (when enabled) |
| `POST` | `/auth/login` | Public | Get session token |
| `GET` | `/auth/me` | User | Current user info |
| `POST` | `/ath/agents/register` | User | Register an agent (per-tenant) |
| `GET` | `/ath/agents/:id` | User | Agent status |
| `DELETE` | `/ath/agents/:id` | User | Revoke agent |
| `POST` | `/ath/authorize` | User | Start OAuth flow |
| `GET` | `/ath/callback` | Public | OAuth callback (browser redirect) |
| `POST` | `/ath/token` | User | Exchange for ATH access token |
| `POST` | `/ath/revoke` | User | Revoke ATH token |
| `ANY` | `/ath/proxy/:provider/*` | User | Proxied API call |
| `GET` | `/ath/admin/providers` | User | List providers (secrets masked) |
| `POST/PUT/DELETE` | `/ath/admin/providers` | Admin | Manage providers |

Authentication: pass session token via `X-ATH-User-Token` header, `ath_session` cookie, or `Authorization: Bearer <token>` (the latter is skipped for ATH opaque tokens).

## Tests

```bash
pnpm test                         # all E2E tests
pnpm run test:e2e:direct-oauth    # direct OAuth server E2E only
```

Runs 36 E2E tests. The `full-flow` tests run in direct OAuth mode — real authorization code exchange and PKCE verification against the standalone mock OAuth server (`vendor/mock-oauth/`), with no gateway-internal mock callbacks.

## Project structure

```
src/
├── app.ts              # Hono app + middleware wiring
├── server.ts           # Server entry + root user bootstrap
├── config.ts           # Environment config
├── types.ts            # Re-exports @ath-protocol/types + gateway types
├── utils.ts            # Re-exports @ath-protocol/server utilities
├── users/              # User accounts, auth middleware
├── registry/           # Agent registration + policy
├── auth/               # OAuth flow, token exchange, revocation, JTI replay protection
├── oauth/              # OAuth bridge (openid-client / mock)
├── proxy/              # Token-validated API proxy
├── providers/          # Provider store + admin routes
├── discovery/          # .well-known endpoint + cache
└── ui/                 # Dashboard web UI
vendor/
├── ath-sdk/            # git submodule → github.com/ath-protocol/typescript-sdk
└── mock-oauth/         # Mock OAuth2 server for E2E tests
```

## License

MIT
