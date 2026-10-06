# LiteAuth

**OAuth for Lite users.**

LiteAuth 是独立的 Linux.do Connect 接入服务：同时支持平台 Connect 登录和 Lite 用户自建应用登录，并向第三方网站提供 OAuth 2.0 / OIDC 接入。

由 [lafish](https://github.com/LeUKi) 维护，源码采用 [MIT 协议](LICENSE)。本项目不属于 Linux.do 官方服务。

## 功能

- 非 Lite 用户登录与 Lite 用户登录，按 Linux.do 稳定数字 ID 关联账号，支持用户名变更。账号成功完成非 Lite 验证后，只能继续使用非 Lite 登录；此前签发的 Lite 令牌自然到期。
- 加密托管用户提交的上游 Connect 凭据，验证、更新与撤销。
- 创建下游服务端应用或浏览器 / 原生应用，管理回调、密钥、Lite-only 与 0～4 级准入。
- 授权码流程、PKCE、不透明 Access Token、OIDC ID Token、Discovery 和 JWKS。
- 应用登录记录、管理员账号详情与操作审计，最近七天查询及自动清理。

上游 Connect 应用与下游 LiteAuth 应用是两套不同的凭据。凭据验证仅确认可用性与回调身份，不额外证明应用登记所有权；未接入 LiteAuth 的网站不会因此自动支持 Lite 登录。

## 技术栈

TypeScript / pnpm monorepo。后端使用 Hono、Drizzle、D1、Better Auth 和 openid-client；前端使用 React、TanStack Router / Query、Jotai、Tailwind CSS 和 Motion。前后端分别部署为 Cloudflare Worker，并通过同一域名提供服务。

## 本地开发

需要 Node.js 22、pnpm 10.8.1，以及用于实际登录的 Linux.do Connect 应用。

```sh
pnpm install --frozen-lockfile
cp apps/api/.dev.vars.example apps/api/.dev.vars
# 在 .dev.vars 中填写本地开发密钥
pnpm db:migrate:local
pnpm dev
```

打开 `http://127.0.0.1:5188`；前端代理认证和接口请求到本地 Worker。管理账户由实际回调的 Linux.do 数字 ID 确认：需要本地管理员时，显式填写本地配置中的 `ADMIN_LINUXDO_ID`，默认不授予管理员权限。

密钥、真实部署配置及本地 D1 数据均不提交。仓库的 `private: true` 用于防止意外发布 npm 包，不影响开源。

## 检查与发布

```sh
pnpm check
pnpm exec playwright install chromium
pnpm test:e2e
pnpm audit
pnpm audit --prod
```

按 [运维说明](docs/operations.md) 创建两套环境的数据库、私有配置与 Secrets，然后执行：

```sh
pnpm deploy:check
pnpm deploy:staging --dry-run
pnpm deploy:staging
# 完成 staging 验证后，生产复用同一份 Web 构建产物
pnpm deploy:production --dry-run --skip-build
pnpm deploy:production --skip-build
```

发布脚本检查管理员 ID、域名、路由、Web → API Service Binding 与环境隔离，不自动执行数据库迁移或导入密钥。生产同时核对 staging 的静态产物、Web Worker 入口源码及锁文件；需要重新构建或修改转发代码时先重新发布 staging，再用 `--skip-build` 发布 production。

部署在同一 Cloudflare Zone 的下游 Worker 也可以使用公开的 OAuth/OIDC 地址。LiteAuth 的 Web Worker 通过内部 Service Binding 转发接口请求，接入者无需配置 LiteAuth 的绑定权限。调用方兼容标志与云端验收方式见 [Worker 接入说明](docs/worker-integration.md)。

## 文档

- [产品、协议与调研依据](docs/liteauth-product-research.md)
- [部署、备份与清理](docs/operations.md)
- [验证结果与已知限制](docs/validation.md)
- [发布记录](docs/release-manifest.md)
- [参与贡献](CONTRIBUTING.md)
- [安全漏洞报告](SECURITY.md)
- [第三方许可证](THIRD_PARTY_NOTICES.md)

下游接入地址与可返回字段也可以在应用详情页直接查看。New API 实际联调仍延期。

## 友情链接

- [Linux.do](https://linux.do/)
