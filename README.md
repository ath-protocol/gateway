# ATH Gateway

[English](README.en.md) | 中文

独立部署的 [ATH (Agent Trust Handshake)](https://github.com/ath-protocol/agent-trust-handshake-protocol) 网关服务。支持多租户用户体系、管理员可控的 OAuth 供应商接入，以及完整的协议执行——基于 [Hono](https://hono.dev) 框架和官方 [`@ath-protocol/server`](https://github.com/ath-protocol/typescript-sdk) SDK 构建。

## 快速开始

```bash
pnpm install
pnpm run dev
```

首次启动时会自动创建 **root** 管理员账号，随机密码输出到控制台。使用该密码登录 `http://localhost:3000/ui/dashboard`。

## 功能特性

- **用户账户体系** — 注册（可配置）、登录、scrypt 密码哈希、root 用户引导
- **多租户隔离** — Agent、会话和令牌按用户隔离，跨租户访问被阻断
- **管理员专属供应商管理** — 仅管理员可添加/删除 OAuth 供应商配置
- **ATH 协议完整实现** — 发现、Agent 注册、身份证明（attestation）、授权（通过 `openid-client` 实现 PKCE）、权限交集、令牌绑定、API 代理、令牌撤销
- **协议安全增强** — JTI 重放防护、`state` 参数强制验证、`redirect_uri` 精确匹配、令牌交换时要求 `agent_attestation`、Agent 撤销时要求 `client_secret`（RFC 7009）
- **管理仪表盘** — 登录页面、用户级 Agent 列表、管理员供应商管理界面

## 协议对齐（v0.1）

本网关已对齐最新 [ATH 协议规范 v0.1](https://github.com/ath-protocol/agent-trust-handshake-protocol) 和 [TypeScript SDK](https://github.com/ath-protocol/typescript-sdk)。主要变更：

| 端点 | 变更 |
|---|---|
| `POST /ath/agents/register` | attestation JWT 必须携带 `jti`（唯一标识），网关拒绝重放 |
| `POST /ath/authorize` | `state` 参数变为必填；`redirect_uri` 根据注册信息精确匹配验证 |
| `POST /ath/token` | 新增必填字段 `agent_attestation`；`aud` 必须为令牌端点 URL；`sub` 必须匹配已注册的 `agent_id` |
| `POST /ath/revoke` | Agent 调用时 `client_secret` 变为必填（RFC 7009） |

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ATH_PORT` | `3000` | HTTP 监听端口 |
| `ATH_HOST` | `0.0.0.0` | 绑定地址 |
| `ATH_GATEWAY_HOST` | `http://localhost:3000` | 网关公开 URL（用于 OAuth 回调等） |
| `ATH_PUBLIC_GATEWAY_URL` | 同 `ATH_GATEWAY_HOST` | attestation JWT `aud` 校验使用的 URL（测试时有用） |
| `ATH_GATEWAY_SECRET` | （启动时随机生成） | 遗留管理 API 鉴权密钥 |
| `ATH_SIGNUP_ENABLED` | `false` | 是否允许用户自行注册 |
| `ATH_JWT_SECRET` | （开发环境默认值） | 会话 JWT 签名密钥——**生产环境必须设置** |
| `ATH_SESSION_TOKEN_TTL` | `86400` | 会话令牌有效期（秒） |
| `ATH_TOKEN_EXPIRY` | `3600` | ATH 访问令牌有效期（秒） |
| `ATH_SESSION_EXPIRY` | `600` | OAuth 会话超时时间（秒） |
| `OAUTH_BASE_URL` | — | 遗留单供应商 OAuth 基础 URL |
| `OAUTH_CLIENT_ID` | — | 遗留单供应商 Client ID |
| `OAUTH_CLIENT_SECRET` | — | 遗留单供应商 Client Secret |

供应商也可通过工作目录下的 `providers.json` 文件或 `ATH_PROVIDERS` 环境变量（JSON 对象）进行配置。

## API 端点

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| `GET` | `/.well-known/ath.json` | 公开 | 网关发现文档 |
| `GET` | `/health` | 公开 | 健康检查 |
| `POST` | `/auth/signup` | 公开 | 创建用户（启用时） |
| `POST` | `/auth/login` | 公开 | 获取会话令牌 |
| `GET` | `/auth/me` | 用户 | 当前用户信息 |
| `POST` | `/ath/agents/register` | 用户 | 注册 Agent（按租户隔离） |
| `GET` | `/ath/agents/:id` | 用户 | 查看 Agent 状态 |
| `DELETE` | `/ath/agents/:id` | 用户 | 撤销 Agent |
| `POST` | `/ath/authorize` | 用户 | 启动 OAuth 授权流程 |
| `GET` | `/ath/callback` | 公开 | OAuth 回调（浏览器重定向） |
| `POST` | `/ath/token` | 用户 | 交换 ATH 访问令牌 |
| `POST` | `/ath/revoke` | 用户 | 撤销 ATH 令牌 |
| `ANY` | `/ath/proxy/:provider/*` | 用户 | 代理 API 调用 |
| `GET` | `/ath/admin/providers` | 用户 | 查看供应商列表（密钥脱敏） |
| `POST/PUT/DELETE` | `/ath/admin/providers` | 管理员 | 管理供应商 |

认证方式：通过 `X-ATH-User-Token` 请求头、`ath_session` Cookie 或 `Authorization: Bearer <token>` 传递会话令牌（后者对 ATH 不透明令牌自动跳过）。

## 测试

```bash
pnpm test                         # 全部 E2E 测试
pnpm run test:e2e:direct-oauth    # 仅含直连 OAuth 服务器的 E2E
```

运行 36 项 E2E 测试。`full-flow` 测试在直连 OAuth 模式下运行——通过独立的模拟 OAuth 服务器（`vendor/mock-oauth/`）完成真实的授权码交换和 PKCE 验证，不使用网关内部的 mock 回调。

## 项目结构

```
src/
├── app.ts              # Hono 应用 + 中间件挂载
├── server.ts           # 服务启动 + root 用户引导
├── config.ts           # 环境配置
├── types.ts            # 重导出 @ath-protocol/types + 网关类型
├── utils.ts            # 重导出 @ath-protocol/server 工具函数
├── users/              # 用户账户、认证中间件
├── registry/           # Agent 注册 + 策略
├── auth/               # OAuth 流程、令牌交换、撤销、JTI 重放防护
├── oauth/              # OAuth 桥接（openid-client / mock）
├── proxy/              # 令牌验证 API 代理
├── providers/          # 供应商存储 + 管理路由
├── discovery/          # .well-known 端点 + 缓存
└── ui/                 # 管理仪表盘 Web UI
vendor/
├── ath-sdk/            # @ath-protocol/server + types（来自 github.com/ath-protocol/typescript-sdk）
└── mock-oauth/         # 用于 E2E 测试的模拟 OAuth2 服务器
```

## 许可证

MIT
