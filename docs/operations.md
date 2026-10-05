# 部署与运维

## 本地开发

Node.js 22、pnpm 10.8.1。公开的 `apps/api/wrangler.jsonc` 和 `apps/web/wrangler.jsonc` 仅包含本地默认配置。

```sh
pnpm install --frozen-lockfile
cp apps/api/.dev.vars.example apps/api/.dev.vars
# 填写本地开发密钥
pnpm db:migrate:local
pnpm dev
```

本地 API 为 `http://127.0.0.1:8798`，前端为 `http://127.0.0.1:5188`。Connect 回调使用前端代理地址 `http://127.0.0.1:5188/auth/connect/callback`；若 Connect 不接受 HTTP 本地回调，应在隔离的 HTTPS staging 环境联调。

## 创建隔离环境

为 staging 和 production 各准备一套独立的 Connect 应用、D1 数据库、API Worker、Web Worker 和 Secrets。以下域名均为示例，需要替换。

```sh
cp apps/api/wrangler.example.jsonc apps/api/wrangler.local.jsonc
cp apps/web/wrangler.example.jsonc apps/web/wrangler.local.jsonc
chmod 600 apps/api/wrangler.local.jsonc apps/web/wrangler.local.jsonc
pnpm exec wrangler login
pnpm exec wrangler d1 create liteauth-staging
pnpm exec wrangler d1 create liteauth-production
```

在两份 `wrangler.local.jsonc` 中填写 Cloudflare Account ID、实际 Worker 名称、D1 数据库 ID、路由所在区域与域名。它们已被 Git 忽略；不要用 `git add -f` 加入仓库。

API 环境变量：

| 变量 | 配置 |
|---|---|
| `APP_ORIGIN` | 环境的完整 HTTPS origin，不带路径，如 `https://liteauth.example.com` |
| `ENVIRONMENT` | 与目标环境一致的 `staging` 或 `production` |
| `ADMIN_LINUXDO_ID` | 管理员的 Linux.do 稳定正整数 ID；不能填写用户名 |

管理员权限仅由经过验证的 Connect 回调授予，空值或格式无效时不授予。部署预检会拒绝未填写的管理员配置。

Web Worker 使用 Custom Domain；API Worker 使用相同域名下的 `/api/*`、`/auth/*`、`/oauth2/*`、`/.well-known/*` Routes。关闭额外 `workers.dev` / preview URL 和自动请求日志，防止绕过正式入口或记录完整认证 URL。

## Secrets 与迁移

每个 API 环境都需要以下 Secrets：

| 名称 | 内容 |
|---|---|
| `BETTER_AUTH_SECRET` | 独立随机值，至少 32 字符 |
| `CREDENTIAL_ENCRYPTION_KEY` | 32 随机字节的 Base64 编码 |
| `CONNECT_CLIENT_ID` | 该环境平台 Connect 应用 ID |
| `CONNECT_CLIENT_SECRET` | 该环境平台 Connect 应用 Secret |

平台应用主页为当前环境首页，回调为 `${APP_ORIGIN}/auth/connect/callback`。使用受保护的文件或 Wrangler 交互输入密钥；不要把值写进 shell 命令、聊天或公开文档。以下命令会交互要求输入：

```sh
pnpm exec wrangler secret put BETTER_AUTH_SECRET --config apps/api/wrangler.local.jsonc --env staging
pnpm exec wrangler secret put CREDENTIAL_ENCRYPTION_KEY --config apps/api/wrangler.local.jsonc --env staging
pnpm exec wrangler secret put CONNECT_CLIENT_ID --config apps/api/wrangler.local.jsonc --env staging
pnpm exec wrangler secret put CONNECT_CLIENT_SECRET --config apps/api/wrangler.local.jsonc --env staging
pnpm exec wrangler d1 migrations apply DB --remote --config apps/api/wrangler.local.jsonc --env staging
```

首次上线也可以使用 Wrangler 的受保护 bulk secrets 文件；将环境参数改为 `production` 后分别配置生产。已有加密数据时，直接替换加密主密钥会使旧密文无法读取，必须先设计并验证重加密流程。

## 验证与发布

```sh
pnpm check
pnpm exec playwright install chromium
pnpm test:e2e
pnpm audit
pnpm audit --prod
pnpm deploy:check
pnpm deploy:staging --dry-run
pnpm deploy:staging
node scripts/verify-deployment.mjs https://staging.liteauth.example.com
```

确认 staging 的界面、真实登录和下游授权达到本次修改所需的验证范围后，生产复用已经验证过的前端产物：

```sh
pnpm deploy:production --dry-run --skip-build
pnpm deploy:production --skip-build
node scripts/verify-deployment.mjs https://liteauth.example.com
```

部署脚本先发布 API，再发布 Web。成功发布 staging 后会在被忽略的 `.wrangler` 目录记录前端文件哈希清单；production 强制要求 `--skip-build`，并拒绝缺少清单、环境或版本不匹配、产物被重新构建或修改的情况。清单证明复用了 staging 产物，实际业务冒烟仍需执行。`--dry-run` 只在本地构建和验证，不发布远端；`--skip-build` 复用 `apps/web/dist`。脚本不自动导入 Secrets、不自动应用迁移。协议交互验证可运行 `node scripts/verify-oidc.mjs --help`，凭据通过受保护文件传入。

发布时只运行一个部署进程，不同时重建或修改 `dist`。脚本在上传前后再次比对文件哈希，发现变化会中止并要求重新验证 staging；API 由当前源码构建，前端清单不代表 API 字节产物。

## Cookie 与升级影响

HTTPS 环境使用真正以 `__Host-` 开头的 Cookie 名称，包括 `__Host-liteauth.session`。所有认证 Cookie 保持 `Secure`、`HttpOnly`、`SameSite=Lax`、`Path=/`，不设置 `Domain`。本地 HTTP 开发使用不带该前缀的名称。

Better Auth 1.7.7 会给自定义名称额外加上 `__Secure-`，因此这里关闭自动名称前缀，显式配置 `__Host-liteauth` 前缀和 HTTPS Secure 属性。公开配置选项见 [Better Auth Cookie 文档](https://www.better-auth.com/docs/concepts/cookies)及[固定版本配置说明](https://github.com/better-auth/better-auth/blob/v1.7.7/docs/content/docs/reference/options.mdx#L623-L679)。不要删除显式的 Secure 属性或对旧会话 Cookie 名称增加兼容读取。

从旧版 `__Secure-__Host-liteauth.session` 升级后，用户需要重新登录管理站。数据库中的账号、应用、凭据及已经签发的下游令牌不会因 Cookie 改名被撤销。该变化防止不可信兄弟子域设置同名 Domain Cookie 后将访问者导入其他账号的会话。

## 日志与清理

- 登录记录与操作审计至少保留 `7×24` 小时，页面查询最近七天。
- 每天北京时间 04:30 执行 `30 20 * * *`，删除更早日志；按正常日频运行时物理保留约七至八天。
- `17 * * * *` 每小时清理过期认证状态，先记录终止结果，再按有效引用清理会话、令牌、事务及认证事件。
- 账号、应用配置和上游 Client ID 唯一占位不属于七天日志，不随日志清理。
- 不记录原始请求体、密钥、令牌、Cookie、授权码或完整认证回调 URL。业务审计保留必要的身份快照和请求标识。

管理会话最长七天、Access Token 一小时、ID Token 十分钟、授权码两分钟、Connect 事务十分钟；首版不签发刷新令牌。

## 回滚与恢复

保存每次发布前的 Worker 版本和 D1 恢复点到私有运维记录。Wrangler 支持按环境回滚 Worker：

```sh
pnpm exec wrangler rollback WORKER_VERSION_ID --config apps/api/wrangler.local.jsonc --env production
```

回滚前核对版本与当前数据库结构兼容；不能退回缺少等级准入、凭据单调版本撤销保护、真实 Host Cookie 前缀或本轮请求体限制的版本。Web 可独立回滚，但不能让 UI 的新策略字段被旧 API 忽略。

D1 恢复与 Worker 回滚是不同操作；先备份、评估数据丢失范围，再按 Cloudflare D1 Time Travel 或备份恢复流程执行。本次发布没有执行生产恢复演练，也未验证自动加密密钥轮换。
