# TypeScript SDK for ATH 可信协议
> 🔌 让你的TypeScript/JavaScript项目5分钟接入ATH可信生态
## 🎯 项目简介
这是ATH可信代理握手协议的官方TypeScript开发工具包，专门为前端和Node.js开发者设计，让你不需要了解复杂的协议细节，只用几行代码就能让你的项目拥有可信交互能力。
## ✨ 核心特性
- ✅ 零依赖，打包后体积只有15KB，浏览器和Node.js环境都能使用
- ✅ 同时支持网关模式和原生模式两种部署方式
- ✅ 完整的TypeScript类型定义，开发体验一流
- ✅ 内置加密算法，不需要额外安装加密库
- ✅ 支持浏览器端本地缓存，减少重复握手请求
- ✅ 兼容所有现代浏览器和Node.js 14+版本
## 📦 安装方式
### npm安装
```bash
npm install @ath-protocol/client @ath-protocol/types
```
### yarn安装
```bash
yarn add @ath-protocol/client @ath-protocol/types
```
### pnpm安装
```bash
pnpm add @ath-protocol/client @ath-protocol/types
```
### 浏览器直接引入
```html
<script src="https://cdn.jsdelivr.net/npm/@ath-protocol/client/dist/index.umd.min.js"></script>
```
## 🚀 3步快速上手
### 第一步：初始化客户端
```typescript
import { ATHClient } from '@ath-protocol/client';
const client = new ATHClient({
  gatewayUrl: 'https://your-ath-gateway.com', // 你的ATH网关地址
  agentId: 'your-agent-id', // 你的AI代理ID
  privateKey: 'your-agent-private-key' // 你的AI代理私钥
});
```
### 第二步：发起握手请求
```typescript
// 申请访问某个服务的权限
const handshakeResult = await client.handshake({
  serviceId: 'target-service-id', // 要访问的服务ID
  permissions: ['user:read', 'data:write'], // 需要的权限列表
  expiresIn: 3600 // 权限有效期，单位秒
});
if (handshakeResult.approved) {
  console.log('握手成功！获得访问令牌:', handshakeResult.accessToken);
} else {
  console.log('握手被拒绝:', handshakeResult.reason);
}
```
### 第三步：访问服务
```typescript
// 使用获得的令牌访问服务
const response = await client.request('https://your-service-api.com/data', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${handshakeResult.accessToken}`
  }
});
console.log('服务返回结果:', response.data);
```
## 📚 包说明
| 包名 | 说明 | 适用场景 |
|------|------|----------|
| `@ath-protocol/client` | 核心客户端库 | 大部分开发者使用这个就够了 |
| `@ath-protocol/types` | 类型定义文件 | TypeScript项目需要 |
| `@ath-protocol/server` | 服务端工具库 | 开发ATH兼容服务时使用 |
| `@ath-protocol/crypto` | 加密工具库 | 需要自定义加密逻辑时使用 |
## 🎯 适用场景
- 🌐 浏览器端AI应用开发
- 🖥️ Node.js服务端集成
- 💻 跨平台Electron应用接入
- 📱 小程序/移动端H5开发
- 🔌 浏览器插件开发
## 📖 文档资源
- [完整API文档](https://athprotocol.dev/docs/sdk/typescript)
- [示例项目](https://github.com/ath-protocol/typescript-sdk/tree/main/examples)
- [常见问题](https://athprotocol.dev/docs/faq)
## 🤝 与其他组件的关系
```
你的TypeScript项目 → 本SDK → ATH网关 → 后端服务
```
本SDK负责处理和ATH网关的握手、认证、加密等所有复杂逻辑，你只需要关心业务代码即可。
## 📄 开源协议
本项目采用 **OpenATH License** 开源协议，具体条款请查看LICENSE文件。
