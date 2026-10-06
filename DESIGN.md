# Design

## Source of truth

- Status: Active
- Last refreshed: 2026-10-05（Asia/Shanghai）
- Primary product surfaces: 登录、Connect 密钥、LiteAuth 应用、授权同意、账号与必要的管理员操作。
- Evidence reviewed: [已接受的实施契约](docs/implementation-plan.md)、[产品与技术调研](docs/liteauth-product-research.md)、[本轮升级记录](docs/upgrade-2026-10-05.md)，以及用户对表单、按钮、应用管理和审计的具体要求。
- 初版已建立最小控件与样式基线。本文件维护当前界面约定；规则与源码实现不替代升级后的浏览器、真实授权及部署验收，实际证据单独记录。

## Brand

- Personality: 简洁、平静、直接；品牌名 LiteAuth 仅用于必要的站点识别。
- Trust signals: 清楚的应用名称、实际登录方式、凭据状态、操作结果和可恢复错误。
- Avoid: 宣传 hero、技术原理介绍、装饰统计、插画、背景动画和官方认可／应用所有权已验证的暗示。Slogan 保留在产品资料中，操作页面无需展示。

## Product goals

- Goals: 完成双通道登录；安全管理 Connect 凭据；创建和管理下游应用；理解并确认目标应用的数据授权。
- Non-goals: 展示基础设施、解释 OAuth 架构、模拟 Linux.do 官方页面或提供与操作无关的内容。
- Success signals: 用户能辨认上下游应用；表单可用键盘完成；加载与失败均有恢复方式；敏感操作后果准确；移动端无横向溢出。

## Personas and jobs

- Primary personas: 使用自有 Connect 应用登录的用户、接入网站的站长、维护平台的管理员。
- User jobs: 登录；提交、验证、更新和删除 Connect 密钥；创建应用并配置回调、等级与登录方式限制；查看和复制 LiteAuth 应用凭据；检查最近七天的登录／操作记录；允许或拒绝授权。
- Key contexts of use: 从下游网站返回的短登录流程、首次凭据提交、日常应用管理、手机上的恢复操作。

## Information architecture

- Primary navigation: 最小顶栏；已登录时提供“Connect 密钥”“LiteAuth 应用”“账号”。管理员入口只在有效权限下出现。
- Core routes/screens: 平台登录、应用授权登录、Lite 用户名／凭据表单、Connect 密钥管理、应用列表、应用详情／创建、登录记录、授权同意、账号、管理员操作记录；错误屏保留重试或返回入口。
- Content hierarchy: 页面标题 → 当前对象与必要状态 → 表单／列表 → 主要操作。危险操作位于对象详情的次要区域。
- 登录页使用窄面板；管理页使用单列主区域。授权流程显示经过后端验证的目标应用，不从浏览器参数直接展示身份或策略。

## Design principles

- 功能优先：保留必要标签、状态、错误和操作后果，每段文字帮助完成当前步骤。
- 上下游清楚：始终区分“Connect 密钥”和“LiteAuth 应用凭据”；避免无法辨别对象的“我的密钥”。
- 真实状态：保存结果以服务端为准；敏感策略不做乐观生效；前端禁用不能代替后端校验。
- Tradeoffs: 采用成熟控件和少量统一样式；减少视觉层级，保留键盘、对比度、触控和错误恢复所需的信息。

## Visual language

- Color: 暖中性色背景 `#faf9f6`，白色面板 `#ffffff`，正文 `#252820`，次要文字 `#647064`，边框 `#e2e5dc`；功能强调绿 `#16784b`，危险操作红 `#b42318`。
- Typography: 系统字体与中文系统字体，不加载外部字体；正文 14–16px、行高约 1.5，页面标题 24px，面板标题 18–20px。凭据值可用等宽字体。
- Spacing/layout rhythm: 4px 基础节奏；控件间距 8–16px，面板间距 24px；桌面页面最大宽度约 1040px，登录面板约 440px；桌面内边距 24px，手机 16px。
- Shape/radius/elevation: 面板约 12px 圆角，控件约 8px；主要使用细边框，只给浮层和弹窗轻阴影。
- Motion: 常规约 160ms，短淡入与小幅位移、轻微按钮按压；无视差、弹跳或自动装饰。使用动态导入 features 的 LazyMotion 和 `domAnimation`；安全禁用、请求、导航与焦点转移立即执行。
- Footer: 全站共享页脚常驻显示 `LiteAuth · Made with ❤️ by lafish · v0.1.0 · build @ <Unix 秒级时间戳>`。仅品牌指向开源仓库 `https://github.com/LeUKi/liteauth`，作者说明为不可点击的纯文本。页脚使用很浅的灰 `#a8ada5`、12px、小间距和无底色样式；品牌链接悬停轻微加深，键盘焦点保持可辨认。构建时间由 Vite 构建开始时注入，同一产物在刷新、导航和部署到不同环境时保持不变。
- Imagery/iconography: 不需要图片；图标仅用于复制、外链、关闭、刷新等真实操作，并配备可访问名称。直接展示的下游密钥不需要显示／隐藏切换。

## Components

- Existing components to reuse: React Hook Form + Zod 表单；Radix 的对话框、开关与焦点管理；Tailwind 统一视觉 token。项目尚无既有控件时使用这些依赖建立最小按钮、输入框、面板和状态组件。
- New/changed components: 统一居中的登录按钮、固定 `@` 用户名输入、按字段校验的凭据表单、共享 Connect 设置指引、最低等级选择、Lite-only 开关、完整密钥展示／复制、记录筛选与分页表格、返回字段卡片、删除／轮换确认框。
- Variants and states: 主要、次要、危险按钮；默认、focus、disabled、pending；表单 field error；页面 loading、empty、error、success。
- Token/component ownership: 共享 token 在前端样式入口维护；相同控件复用单一实现；业务组件不复制协议状态或服务端数据。

## Accessibility

- Target standard: WCAG 2.2 AA，正常文字对比度至少 4.5:1；状态不能仅靠颜色表达。
- Keyboard/focus behavior: 原生可聚焦控件、可见 focus ring；弹窗保持焦点约束，关闭后返回触发控件；错误可定位到对应输入；所有操作可用键盘完成。
- Contrast/readability: 不以小字或浅灰承载关键后果；长 client ID／回调可换行或在字段内滚动，不挤压操作按钮。
- Screen-reader semantics: 输入有真实 label，错误关联 `aria-describedby`，反馈使用合适的 live region；对话框有名称；加载区域可标记 `aria-busy`。
- Reduced motion and sensory considerations: MotionConfig 尊重系统减少动态效果，必要时使用 `useReducedMotion`；关闭位移与缩放，保留即时状态反馈；不闪烁。

## Responsive behavior

- Supported breakpoints/devices: 320px 起的手机，平板与桌面；约 640px、1024px 为主要布局调整点。
- Layout adaptations: 手机控件纵向排列，记录／字段表格只在有名称且可聚焦的局部区域横向滚动；顶栏保持短标签并在必要时换行；长凭据和回调不导致整个页面横向滚动。
- Touch/hover differences: 关键按钮可触控面积至少约 44px；操作入口始终可见，不依赖 hover；工具提示不得承载唯一说明。

## Interaction states

- Loading: 数据区域显示简洁加载反馈；授权策略加载完成前登录按钮禁用；提交中防止重复请求。
- Empty: 用一句结果说明和真实行动入口，例如“尚未创建应用”“创建应用”；不填充装饰性示例。
- Error: 显示可理解的原因和重试／修正入口；不展示堆栈、凭据、原始回调 URL；保存失败保留可修正输入与旧有效配置。
- Success: 使用局部反馈，更新服务端查询；密钥留在当前详情的明确字段内，不用瞬时 toast 或一次性弹窗承载复制所需的结果。
- Account policy: 账号完成非 Lite 验证后，Lite 操作原生禁用，显示“此账号已完成非 Lite 验证，请使用非 Lite 用户登录。”；遇到 Lite-only 应用显示“此账号不符合该应用的登录要求”，提供返回及切换账号。Connect 密钥页保留绑定摘要与删除，隐藏提交／更新表单；管理员展示“仅可非 Lite 登录”和首次确认时间。
- Disabled: 应用启用 Lite-only 时“非 Lite 用户登录”按钮保持可见并原生禁用，旁边简短提示“此应用仅支持 Lite 登录”；禁用状态不延迟到动画结束。
- Offline/slow network: 显示请求仍在处理或可重试的结果；不能在策略获取失败时恢复官方入口，也不能显示未提交成功的设置。
- Secret lifecycle: 服务端应用详情完整展示 Client Secret，所有者可以重复读取和复制；浏览器／原生应用不展示不存在的 secret。历史纯哈希密钥提示“轮换后可查看密钥”。管理员查看他人应用提示“仅应用所有者可查看密钥”。离开页面或退出后清除当前明文，不写入持久缓存；上游 Connect secret 仍不回显。
- Policy changes: 保存 Lite-only 时准确说明“阻止新的非 Lite 授权；已有授权按原有效期继续”。最低等级展示 0～4 的独立选择；提高等级取消不合格及未确认身份的旧流程，已签发授权自然到期；取消状态不会因放宽策略恢复。
- Reauthentication: 等级不足时显示目标门槛和本次验证等级，并提供“重新验证”。复用旧会话时不把存储等级称作当前实时等级，未登录时不凭用户名显示身份或等级。
- Stable identity: 用户名只用于托管凭据查找和展示；管理详情使用稳定 LiteAuth ID 路由。改名后仍显示同一账号及其应用，历史验证记录保留当时的用户名。
- Administrator accounts: 账号列表展示 Linux.do ID、当前上游 Connect Client ID、最近验证等级/方式/时间和状态，支持搜索与分页；详情包含资料、上游绑定历史、Connect 验证表格和下游应用。
- Verification records: 明确区分目标账号与实际回调身份。未验证显示“身份未确认”，ID 不同时显示“身份不一致”；不把输入用户名当成成功登录者。所有记录显示北京时间，详情可展开事务标识，不展示 secret。
- Form validation: 固定 `@` 仅为输入前缀，提交不包含它；ID 与 Secret 分别报错和重新校验，已填写的 ID 不承接 Secret 的缺失错误。切换已托管／手动填写时清除不再适用的字段及错误。
- Record states: 表格显示用户和 Linux.do ID、登录方式、等级、结果、简短原因以及秒级北京时间（UTC+8）；未验证身份显示“身份未确认”。操作审计另列目标、关联应用与必要的修改前后值。加载、空状态、失败和分页均有功能性反馈。

## Content voice

- Tone: 简洁中文，使用用户可以直接操作的名称和动词。
- Terminology: “非 Lite 用户登录”“Lite 用户登录”“Connect 密钥”“LiteAuth 应用”“面向全部老友”“最低等级”“登录记录”“回调地址”“允许”“拒绝”“更新”“删除”。客户端类型统一为“服务端应用”与“浏览器 / 原生应用”。协议中的 `official_connect` 原值不变；`client_id`／`client_secret` 是必要字段，可作为标签辅助。
- Microcopy rules: 不把通道当永久账号等级；不把凭据验证称为应用所有权验证；不暗示官方背书；删除后果指向具体绑定或应用，不宣称所有下游立即退出。
- 错误与确认只解释当前动作的后果。OAuth 架构、Workers、D1 等基础设施说明放在接入和运维文档中。应用详情的“返回字段”是开发者完成接入所需的功能资料，按回调、Token、用户信息、ID Token 分组列出字段来源、类型、可能值与条件。
- Connect 指引列出应用名称、主页、描述、LOGO、最低等级和回调。自由填写项使用灰色“自行填写／按需填写”；主页提供当前环境推荐值，最低等级建议 0，回调提供准确值与复制按钮。灰色文字也保持可读对比度，不制作无法保存的假输入框。
- Login buttons: “非 Lite 用户登录”使用白底、深色文字、浅色边框的次要按钮，悬停时轻微变灰；“Lite 用户登录”及“验证并登录”使用绿色主按钮。上下按钮保持同一尺寸、图标大小和居中图文组合，加载与禁用状态不改变布局。列表中的登录对象说明与等级标签分开展示，不使用“双通道”作为用户标签。

## Implementation constraints

- Framework/styling system: React、TanStack Router／Query、Jotai、Tailwind、Motion；表单与可访问交互复用已选成熟依赖。
- Design-token constraints: 上述颜色、间距、圆角和时长统一维护；组件不能自行创建另一套视觉语言。
- Performance constraints: 不引入图片或外部字体；Motion features 用函数动态导入实现 LazyMotion；不为基本过渡载入拖拽或复杂布局特性。
- Compatibility constraints: 前后端分别部署到两个 Cloudflare Worker，同一 origin；Query 管理服务端数据，Jotai 仅承载必要临时状态；secret 不写入 Query 持久层、localStorage、URL 或共享长期 atom。
- Test/screenshot expectations: 桌面及手机截图检查；浏览器验证字段错误恢复、固定前缀、按钮居中、灰色设置指引、密钥重复读取、应用等级／Lite-only 组合、记录筛选及局部表格滚动、一屏授权同意、键盘／弹窗和减少动态效果；资料和源码检查不能替代运行证据。

## Open questions

- 当前没有阻止实施的视觉偏好问题。验收时由实施者检查真实页面的对比度、最窄布局和完整状态；不把尚未取得的截图或测试写成已通过。
