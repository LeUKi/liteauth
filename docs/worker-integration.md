# Cloudflare Worker 接入

第三方站点使用应用详情给出的公开 OAuth/OIDC 地址。授权请求、Token、UserInfo、Discovery 和 JWKS 的地址与普通服务器接入相同；无需取得 LiteAuth 的 Cloudflare 账号权限或 Service Binding。

## 同 Zone 请求路径

同 Zone 指相同的 Cloudflare 域名区域，不是相同机房或地理地区。LiteAuth 使用 Web Worker Custom Domain 和 API Worker Routes：公网请求按保留路径进入 API Worker；某些同 Zone Worker 的全局 `fetch()` 会直接到 Custom Domain 所代表的源站，跳过这些 Routes。

Web Worker 因此将 `/api`、`/auth`、`/oauth2`、`/.well-known` 及其子路径通过内部 `API` Service Binding 转发给对应环境的 API Worker。原公开 URL、方法、查询参数、请求头和请求体传入 API，API 的状态码、重定向、Cookie 和响应体直接返回。`/apiary` 等不匹配路径继续由 SPA 处理。

转发不自动跟随重定向、不重试授权码兑换；绑定缺失或调用异常返回不可缓存的 JSON 503，不回退为 HTML。已经取得的 API 错误响应保留原样。

## 调用方的兼容标志

Cloudflare 在调用方 Worker 上提供 `global_fetch_strictly_public`：它让全局 `fetch()` 按公网入口处理，包括重新匹配 Routes。该标志影响调用方的所有全局 fetch；请求自己的匹配地址可能产生循环，启用前应检查调用方自己的路由用途。不能只根据较新的 `compatibility_date` 判断已经启用。

对应旧式源站行为的显式标志是 `global_fetch_private_origin`。真实兼容性测试分别使用这两个互斥标志，避免默认行为不明确。LiteAuth 的内部转发让这两条入口都可以处理 API 请求；它不会补回旧式路径已经绕过的 Cloudflare 边缘安全规则。鉴权、Origin 校验、请求体限制、账号策略和限流仍由 API 执行。

## 部署与验证

每个 Web 环境显式绑定自己的 API Worker，保留公网 Routes 和 `run_worker_first`。先发布 staging，验证后提升相同静态产物、Worker 入口源码和锁文件到 production。配置校验和发布命令见 [运维说明](operations.md)。

本地 Workers 测试覆盖转发保真、路径边界、失败关闭，以及经转发后 API 的安全检查。实际同 Zone 行为必须通过部署在同一 Zone 的调用 Worker 验证；Node、公网 curl、Vite 和独立 workerd 的结果不能替代。

云端验证使用受请求头凭证保护的临时调用 Worker，只允许固定测试动作和目标，不接受任意目标 URL。分别以旧式源站及严格公网模式验证元数据、授权码 POST 兑换、OAuth/OIDC UserInfo、重放拒绝、Cookie、重定向和准入策略。仅保存脱敏结果，结束后清理临时 Worker、路由、凭证及独立测试数据。合成会话的协议结果不表示执行了真人 Connect 登录。

可复用 [临时探针与运行说明](../scripts/same-zone-probe/README.md)。它验证协议传输和身份字段，确认 ID Token 存在；完整 JWT 签名校验继续由既有认证测试及独立 OIDC 验收覆盖，不由这份路由探针替代。

## 官方依据

- [Routes 的同 Zone fetch 限制](https://developers.cloudflare.com/workers/configuration/routing/routes/#background)
- [Custom Domain 与 Routes 的交互](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#interaction-with-routes)
- [global_fetch_strictly_public](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public)
- [HTTP Service Bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/http/)
