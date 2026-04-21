# ATH 网关服务
> 🚪 ATH可信生态系统的统一接入门户和安全屏障
## 🎯 项目简介
ATH网关是整个ATH可信生态系统的入口，所有外部请求都需要经过网关的验证和过滤，就像小区的保安和门禁系统，保护内部服务的安全，同时提供负载均衡和流量控制能力。
网关服务基于Hono框架开发，性能极高，资源占用极低，可以部署在各种云原生环境中。
## ✨ 核心功能
### 🔍 请求合法性校验
- 所有请求的令牌合法性验证
- 签名验证，防止请求被篡改
- 权限校验，确保请求有足够的权限
### 🔒 安全防护
- TLS 1.3加密传输，防止数据窃听
- 防DDoS攻击，自动封禁恶意IP
- 速率限制，防止服务被打垮
- SQL注入、XSS攻击防护
### ⚖️ 负载均衡
- 支持多种负载均衡算法（轮询、加权轮询、最小连接数等）
- 自动健康检查，自动剔除故障节点
- 支持灰度发布和流量切分
### 📊 流量监控
- 实时流量统计和监控
- 访问日志完整记录
- 性能指标导出，支持对接Prometheus和Grafana
### 🔄 协议转换
- 支持HTTP、HTTPS、WebSocket等多种协议
- 自动协议转换，适配不同的后端服务
- 支持请求和响应的自定义转换
## 📦 安装方式
### Docker安装（推荐）
```bash
docker run -d -p 80:80 -p 443:443 -v ./config:/etc/ath-gateway athprotocol/gateway:latest
```
### 二进制安装
```bash
# Linux
wget https://github.com/ath-protocol/gateway/releases/latest/download/ath-gateway-linux-amd64
# macOS
wget https://github.com/ath-protocol/gateway/releases/latest/download/ath-gateway-darwin-amd64
# Windows
wget https://github.com/ath-protocol/gateway/releases/latest/download/ath-gateway-windows-amd64.exe
```
## 🚀 快速开始
### 第一步：准备配置文件
创建`gateway.yaml`文件：
```yaml
server:
  http_port: 80
  https_port: 443
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
athx:
  endpoint: "http://your-athx-server:8080"  # ATHX引擎的地址
  api_token: "your-athx-api-token"  # 访问ATHX的API Token
services:
  - id: "user-service"
    name: "用户服务"
    upstream: "http://internal-user-service:3000"
    allowed_permissions: ["user:read", "user:write"]
  - id: "data-service"
    name: "数据服务"
    upstream: "http://internal-data-service:8000"
    allowed_permissions: ["data:read", "data:write"]
security:
  rate_limit: 1000  # 每秒最多1000个请求
  max_request_size: "10MB"  # 最大请求大小
  block_known_attacks: true  # 拦截已知攻击
```
### 第二步：启动网关
```bash
./ath-gateway start --config gateway.yaml
```
### 第三步：验证服务
```bash
curl http://localhost/health
# 正常返回：{"status": "ok", "version": "x.x.x"}
```
## 🏗️ 部署架构
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  外部请求   │ →   │  ATH网关    │ →   │  ATHX引擎   │ →   │  后端服务   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```
所有外部请求都必须经过网关，网关会自动验证请求的合法性，只有通过验证的请求才会转发到后端服务。
## 🎯 适用场景
- 🏢 企业级ATH部署
- 🌐 公网服务接入
- 🔒 高安全需求场景
- 📈 高并发业务场景
## 📖 文档资源
- [部署指南](https://athprotocol.dev/docs/gateway/deployment)
- [配置参考](https://athprotocol.dev/docs/gateway/configuration)
- [路由配置教程](https://athprotocol.dev/docs/gateway/routing)
- [安全配置最佳实践](https://athprotocol.dev/docs/gateway/security)
## 📄 开源协议
本项目采用 **OpenATH License** 开源协议，具体条款请查看LICENSE文件。
