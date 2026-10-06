# 发布记录

- 版本：`0.1.0`
- 日期：2026-10-06
- 仓库：<https://github.com/LeUKi/liteauth>
- 许可证：MIT，适用于 LiteAuth 自有代码
- 初始基线提交：`f5a816e`，消息为 `chore: prepare LiteAuth for MIT open source`；后续补丁单独提交

## 本次内容

修复公开接口读取超大请求体、旧授权 UserInfo 读取当前用户资料和 HTTPS Cookie 双重前缀问题；管理员配置改为显式安全配置；定点覆盖受安全公告影响的间接依赖。

增加全站浅灰色页脚，显示 LiteAuth、作者、前端包版本以及构建时注入的 Unix 秒级时间戳。错误页面同样显示，生产复用 staging 的同一份构建。

加入 MIT LICENSE、贡献与安全说明、第三方依赖说明、最小只读 GitHub CI，并整理可复现的本地开发及 Cloudflare 部署步骤。真实配置、密钥、私人联调与发布证据保存在 Git 忽略目录。

## 验证与发布

| 项目 | 结果 |
|---|---|
| 冻结锁文件安装 | 通过 |
| Lint、类型检查、构建 | 通过 |
| Workers/API 测试 | 194 项通过 |
| 部署脚本测试 | 16 项通过 |
| Playwright | 40 项桌面／移动端用例通过 |
| 全部依赖／生产依赖审计 | 0／0 条已知漏洞 |
| Drizzle 兼容性 | 无 schema 变化，无需新增迁移 |
| staging API／Web | 发布、七组公开冒烟、桌面／移动端实际页面通过 |
| staging 协议回归 | 两种来源 × OAuth／OIDC，共四组；合成身份及临时记录已清理 |
| production API／Web | dry-run、发布、七组公开冒烟及实际页面检查通过 |
| 前端产物提升 | 本地文件清单一致；两个环境线上 JS／CSS 的 SHA-256 一致，HTML 应用入口一致 |
| Git 整理 | 原 Git 目录完整移至仓库外备份；公开文件建立本地单根提交；未推送 |

详细验证范围及证据边界见 [验证记录](validation.md)。公开记录不保存 Cloudflare 版本 ID、Account ID、D1 ID、私人身份或本机路径。

## 升级影响与限制

Cookie 修复要求已登录的管理站用户重新登录，不撤销已经签发的下游令牌。本轮没有重新执行真人 Connect 登录；实际 HTTP 协议回归使用 staging 合成会话。New API 联调与人工真实改名测试均沿用既定延期／豁免。

生产回滚、数据库恢复及主密钥轮换没有在本轮演练。GitHub Private vulnerability reporting 尚未确认启用，仓库公开前必须核验；本次交付止于本地提交，不包含远端推送或公开仓库。

## 2026-10-06 后续页脚补丁

作者说明改为纯文本 `Made with ❤️ by lafish`，仅 LiteAuth 品牌保留仓库链接。版本仍为 `0.1.0`，该次构建时间为 `1791249866`。

本次仅发布 Web Worker：先 staging，再将同一产物发布到 production。Lint、前端类型检查、生产构建和两项桌面／移动端页脚回归通过；两个环境的登录、404、错误页及线上 JS／CSS 哈希检查通过。

补丁和开源初始基线推送到 `LeUKi/liteauth` 的 `main`。远端仓库本次创建为私有，公开发布及公开前安全设置核验另行执行。

## 2026-10-06 账号登录方式锁定升级

按 Linux.do 稳定用户 ID 永久保存首次非 Lite 验证事实。此后拒绝 Lite 登录、Connect 凭据验证／更新和新的 Lite 授权；此前签发的 Lite 令牌继续按原来源自然到期。增加锁定状态展示、Lite-only 拒绝与切换账号路径，以及已取消授权的返回入口。详见 [升级说明](upgrade-account-lock.md)。

staging 和 production 均按“新增字段迁移 → 执行约束的 API/Web 发布 → 历史回填 → 线上验收 → 最终回填”完成。两个环境 API 均核对为新版本承载 100% 流量，升级前已进入处理状态的 Connect 事务均为 0。生产初次回填 6 个有保留成功认证证据的账号；没有证据的账号不推断、不锁定。重复回填没有新增结果。

| 验证 | 本次结果 |
|---|---|
| Lint、类型检查、API/Web 构建 | 通过 |
| Workers/API 回归 | 217 项通过 |
| 部署脚本回归 | 16 项通过 |
| Playwright 桌面／移动端 | 64 项通过 |
| 独立代码／安全审查 | APPROVE |
| 独立架构审查 | CLEAR |
| staging／production 公开部署冒烟 | 每个环境 7 组通过 |
| staging／production 实际协议回归 | 每个环境两种来源 × OAuth/OIDC，共 4 组通过 |
| 锁定与兼容回归 | 两环境均通过：旧 Lite 管理会话失效、凭据验证被拒、待兑换码取消、旧 Lite Token/UserInfo 仍有效、回填幂等 |
| 实际桌面／移动端页面 | 两环境 Lite-only 提示、禁用控件、切换账号及页脚通过 |
| 构建提升 | 生产复用 staging 产物，线上 JS/CSS SHA-256 与本地一致；`build @ 1791258390` |

协议回归使用隔离的合成身份和真实部署的 HTTP 端点、认证库及 D1；所有临时账号、应用、会话、授权和审计已清理。本轮没有让用户重新完成真人 Connect 登录，不能把这些结果表述为新的真人上游验证。New API 联调及人工实际改名仍按既定边界延期／豁免。

原版本 `0.1.0`、MIT 许可证及仓库可见性保持不变。迁移字段和已确认事实不可清除，API 不能回滚到忽略账号锁定的版本。

## 2026-10-06 同 Zone Worker 接入补丁

Web Worker 对 `/api`、`/auth`、`/oauth2`、`/.well-known` 及其子路径，使用同环境 `API` Service Binding 转发。请求只发送一次，不跟随重定向，直接返回 API 响应；绑定缺失或调用异常返回不可缓存的 JSON 503。保留公网 Routes 和 SPA 路径边界。接入者无需取得 LiteAuth Service Binding，详见 [Worker 接入说明](worker-integration.md)。

发布预检增加服务绑定目标、Worker 优先执行和入口校验；staging 晋级清单增加 Web Worker 入口与锁文件 SHA-256，production 继续复用静态产物。本次沿用 API → Web 发布流程，API 业务代码和数据库结构没有变化，无需迁移。

| 验证 | 本次结果 |
|---|---|
| 类型检查、Lint、API/Web 构建 | 通过 |
| Workers/API 回归 | 235 项通过，含转发与账号准入相关回归 |
| 部署预检、源码晋级与探针防护测试 | 29 项通过 |
| Playwright 桌面／移动端 | 64 项通过 |
| 独立代码与探针审查 | 未发现发布阻断问题 |
| 修复前同 Zone 对照 | 旧式源站模式的健康检查、Discovery、JWKS、UserInfo 返回 404；严格公网模式通过 |
| staging／production 公网部署冒烟 | 每个环境 7 组通过 |
| staging／production 真实同 Zone 调用 | 每个环境分别使用 `global_fetch_private_origin` 与 `global_fetch_strictly_public`；每种模式 7 组基础检查、6 组协议／策略检查全部通过 |
| 协议／策略范围 | OAuth/OIDC 授权码兑换、Cookie／重定向、UserInfo、错误码与重放拒绝、Lite-only、等级门槛及独立历史令牌 |
| 实际页面与产物 | 两环境桌面／移动端页面通过，线上 JS/CSS SHA-256 与 staging 清单一致；`build @ 1791263621` |
| 云端配置 | 两环境 API/Web 新版本均承载 100% 流量；Web 绑定各自 API |

云端协议验收使用独立合成 Lite 会话和实际部署的 HTTP 端点。路由探针确认 ID Token 存在，但不替代完整 JWT 签名验证或真人 Connect 登录；完整协议和账号锁定约束继续由现有 Workers/API 回归覆盖。刻意重放授权码会触发认证库撤销该码衍生的令牌，历史策略检查因此使用另一份未重放的授权。

临时测试账号、应用、会话、授权和相关审计均已按独立测试身份清理并核对为零；临时调用 Worker、路由和探针凭证在验收后移除。版本仍为 `0.1.0`，New API 联调继续延期。本补丁的回滚范围是 Web Worker 和其绑定配置，保留公网 Routes，不回退已有的 API 准入与撤销保护。
