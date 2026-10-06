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
