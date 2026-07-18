# 目前    RyuWebAuth   版本信息  V1.0.2.3

——————

# RyuWebAuth

<p align="center">
  <img src="./public/logo.jpg" alt="RyuWebAuth Logo" width="220">
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img src="./public/RyoWebAuth.png" alt="RyoWebAuth Wordmark" width="220">
</p>


Web 认证服务 —— 注册 / 登录 / 2FA 双因素验证 / 用户管理

> 基于 Node.js 原生 `http` 模块构建，零外部运行时依赖，JSON 文件持久化存储。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **用户注册与登录** | 支持注册新账号，密码使用 scrypt 哈希安全存储 |
| **超级管理员** | 固定账号 `RyuWebAuth`，首次启动生成随机密码，首次登录强制修改 |
| **注册开关** | 超级管理员可随时开/关注册功能，关闭后仅超级管理员可登录 |
| **角色管理** | 超级管理员可查看所有用户、设置/撤销管理员权限 |
| **2FA 双因素验证** | 标准 TOTP (RFC 6238)，6位数字，30秒刷新，支持扫码添加 |
| **不对称暗色 UI** | 琥珀暖色 / 深绿点缀，噪点纹理背景，Iconify 图标，非线性动画，手机端自适应 |
| **零依赖** | 仅使用 Node.js 内置模块（`http`、`crypto`、`fs`），无需 `npm install` |

---

## 快速启动

```bash
# Windows 双击运行
start.bat

# 或手动启动
node server.js
```

服务默认运行在 `http://localhost:3180`。

### 首次启动

控制台会输出超级管理员的随机密码，格式为 `12位随机字符（无易混淆字符）`：

```
==========================================================
  RyuWebAuth Super Admin Account Created
  Username : RyuWebAuth
  Password : AbC9!xK-qLm2
  Please change your password after first login!
==========================================================
```

**请妥善保存此密码，它只会显示一次！** 首次登录后系统会引导修改密码。

---

## 项目结构

```
RyuWebAuth/
├── start.bat          # Windows 启动脚本（Larry-3D-2 ASCII 艺术字）
├── server.js          # Node.js 后端服务（端口 3180）
├── public/
│   └── index.html     # 前端单页应用（HTML + CSS + JS）
├── data/              # JSON 数据存储目录（自动创建）
│   ├── users.json     # 用户数据
│   ├── sessions.json  # 会话数据
│   ├── settings.json  # 系统设置
│   └── 2fa_entries.json  # 用户 2FA 生成器条目（仅元数据，密钥按需获取）
└── README.md          # 项目文档
```

---

## API 接口

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/register` | 注册新用户 |
| POST | `/api/login` | 用户登录（含 2FA 验证） |
| POST | `/api/logout` | 退出登录 |
| GET | `/api/session` | 获取当前会话信息 |
| POST | `/api/change-password` | 修改密码 |

### 管理（需超级管理员 / 管理员权限）

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET  | `/api/admin/users` | 获取所有用户列表 | superadmin |
| POST | `/api/admin/set-role` | 设置用户角色（`user` / `admin`） | superadmin |
| GET  | `/api/admin/settings` | 获取系统设置 | superadmin / admin |
| POST | `/api/admin/settings` | 更新系统设置（注册开关等） | superadmin / admin |
| POST | `/api/admin/create-user` | 管理员创建用户 | superadmin |
| POST | `/api/admin/delete-user` | 管理员删除用户 | superadmin |
| POST | `/api/admin/reset-password` | 管理员强制改密（清空该用户所有 session） | superadmin |
| GET  | `/api/admin/user-2fa` | 获取指定用户的 2FA 信息（含明文 secret） | superadmin |
| POST | `/api/admin/force-disable-2fa` | 管理员强制关闭用户 2FA | superadmin |

### 2FA

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/2fa/setup` | 生成 2FA 密钥和二维码 URI |
| POST | `/api/2fa/verify-setup` | 验证 TOTP 码并激活 2FA |
| POST | `/api/2fa/disable` | 验证 TOTP 码 **和当前密码** 并禁用 2FA |

### TOTP 验证码生成器

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/2fa/generator/entries` | 列出当前用户的条目（不再返回 secret 明文） |
| GET  | `/api/2fa/generator/secret?id=<id>` | 按需拉取单条 secret + 当前验证码（限流） |
| POST | `/api/2fa/generator/add` | 通过 URI 或手动输入添加条目 |
| POST | `/api/2fa/generator/update` | 更新条目的 name / issuer / remark |
| POST | `/api/2fa/generator/delete` | 删除条目 |

---

## 技术实现

### TOTP (RFC 6238)

完全基于 Node.js 内置 `crypto` 模块实现，不依赖第三方库：

- 算法：HMAC-SHA1
- 时间步长：30 秒
- 验证码：6 位数字
- 密钥：Base32 编码，32 字符

### 密码安全

使用 `crypto.scryptSync` 进行密码哈希，随机盐值 16 字节，输出 64 字节。
比较时使用 `crypto.timingSafeEqual` 避免时序攻击。

### 会话管理

- 基于 Cookie 的 Session 机制
- Session ID 使用 `crypto.randomBytes(32)` 生成（256-bit 熵）
- 默认有效期 24 小时，"记住我" 模式 30 天
- Session 数据持久化到 `sessions.json`，**重启不失效**（与早期 README 描述不同，更新以本节为准）
- 自己改密 / 管理员强制改密 / 角色变更 / 用户被删除 均会清空该用户的所有 session

### 数据存储

所有数据以 JSON 格式存储在 `data/` 目录下，结构清晰，便于备份和迁移。
写文件采用「写临时文件 + rename」原子替换，避免半文件损坏。

### 速率限制 (Rate Limiting)

按 IP / 账号在内置滑动窗口中计数。默认阈值：

| 桶 | 窗口 | 上限 | 说明 |
|----|------|------|------|
| `api` | 1 秒 | 30 | 通用 API 防刷 |
| `login` | 1 分钟 | 10 | 登录尝试防爆破 |
| `register` | 1 小时 | 5 | 注册防滥用 |
| `changePw` | 1 分钟 | 5 | 改密防爆破 |
| `totp` | 5 分钟 | 10 | 2FA 验证防爆破 |

被限流时返回 `429 Too Many Requests` + `Retry-After` 头。

---

## 安全说明 (v1.0.2)

v1.0.2 是一次**安全加固版本**。在 v1.0.1 的基础上新增了：

| 类别 | 加固 |
|------|------|
| CSRF | 双重提交 Token 防护：登录/注册时下发 `csrf_token` cookie，所有写操作需 `X-CSRF-Token` 头携带 |
| 密码 | 强制策略：长度 ≥ 8，且至少包含两类 (小写/大写/数字/符号)，黑名单拦截常见弱密码 |
| 密码 | 改密时仍用旧密码 (撤销会话后改密易出现登录风险) |
| 并发 | JSON 文件读写加同步互斥锁，杜绝读-改-写竞态 |
| 响应头 | CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy |

### CSRF Token 工作机制

1. 登录或注册成功时，服务器下发两个 cookie：
   - `session_id` — `HttpOnly`（JS 不可读，防 XSS 盗取）
   - `csrf_token` — 非 `HttpOnly`（JS 可读，用于拼接到请求头）
2. 客户端所有写操作（POST/PUT/DELETE）必须从 `document.cookie` 读出 `csrf_token`，放到 `X-CSRF-Token` 头
3. 服务端用 `crypto.timingSafeEqual` 比对 header 值与会话存储值
4. 改密、强制改密、登出时会同时轮换 csrf_token
5. `GET` / `HEAD` 免校验；`/api/login` 和 `/api/register` 是认证入口本身免 CSRF

> 浏览器 SameSite=Lax 仍保留为第一道防线，CSRF Token 作为第二道。

### 密码策略

- 长度：8 ~ 128 位
- 复杂度：至少包含两类字符（小写 / 大写 / 数字 / 符号）
- 黑名单：`password`, `12345678`, `123456789`, `qwerty123`, `admin123`, `iloveyou1` 等
- 应用入口：注册、改密、管理员创建用户、管理员强制改密

### 安全响应头

| 头 | 值 | 作用 |
|----|------|------|
| `Content-Security-Policy` | 包含 `default-src 'self'` / `frame-ancestors 'none'` 等 | 阻止内联脚本 / 框架嵌套 |
| `X-Frame-Options` | `DENY` | 防 clickjacking |
| `X-Content-Type-Options` | `nosniff` | 阻止 MIME 嗅探 |
| `Referrer-Policy` | `no-referrer` | 不向外发送来源 URL |
| `Permissions-Policy` | 关闭 camera/mic/geolocation/payment | 减少权限面 |

### v1.0.1 已修复 (历史)

TOTP 密钥 CSPRNG、生成器 XSS、全站限流、timing-safe、TOTP ±1 窗口、原子写、SPA fallback 分离、登录时序均衡等。

### 信任假设

`/api/admin/user-2fa` 仍会返回普通用户的 2FA 明文密钥（仅限 superadmin）。该接口是 v1.0 既有行为，**部署时务必把 superadmin 视为完全可信**。

### 仍存局限（已知 TODO）

| 项目 | 说明 |
|------|------|
| 2FA Secret 磁盘明文 | 仍是 JSON 明文存储，建议部署时把 `data/` 目录设文件权限，或自行加上 AES-GCM 加密 |
| 第三方 CDN 依赖 | 用了 `cdn.jsdelivr.net` 与 Google Fonts，生产部署可考虑本地化 |
| 改密后旧 token 复用 | superadmin 强制改密后，该用户全部 session 被清；自己改密同样清空 |

---

## 技术栈

- **运行时**：Node.js >= 18.0.0
- **后端**：原生 `http` 模块，无框架
- **前端**：纯 HTML + CSS + JavaScript
- **QR 码**：qrcodejs (CDN)
- **图标**：Iconify (CDN)
- **存储**：JSON 文件

---

## 许可

MIT License


## 更新日志

### v1.0.2.3 (2026-07-18) — 摄像头修复版

- **修复点击打开摄像头无法打开**：修复由`MiniMax-M3`所导致的点击`添加生成器`中`打开摄像头`点击报错无法打开的问题
- **修复摄像头无法打开**：`Permissions-Policy` 头中 `camera=()` 完全禁用了摄像头，改为 `camera=(self)` 允许同源页面使用
- **摄像头启动失败提示增强**：区分 `NotAllowedError`（权限被拒 / 非 HTTPS）与通用失败，捕获 Html5Qrcode 包装异常，清理扫码区原始报错

### v1.0.2.2 (2026-07-18) — Logo 全面替换 / 2FA 限流可配置版

- **网站图标 (favicon) 替换**：用 `logo.jpg` (RyoWebAuth 猫娘 logo) 生成多尺寸 PNG/ICO
  - `favicon.ico` (16/32/48 多尺寸, 967 字节)
  - `favicon-16.png` / `favicon-32.png` / `favicon-48.png`
  - `apple-touch-icon.png` (180×180, Apple 设备主屏图标)
  - `logo-256.png` / `logo-512.png` (README / 文档展示)
  - HTML `<head>` 添加 4 个 `<link rel="icon">` / `<link rel="apple-touch-icon">` 标签, 跨设备兼容
- **网页内 logo 图标替换** (3 处, 文字保留):
  - 角落 logo (登录后左上角) — 36×36, 猫娘图 + "RyuWebAuth" 文字
  - 登录页顶部 logo — 44×44, 猫娘图 + "RyuWebAuth" 文字
  - 登录卡片内 logo — 52×52, 猫娘图 (无文字)
  - 新增 `public/logo-128.png` (29KB, 轻量级) 作为内嵌图标
  - CSS 用 `:has(.brand-img)` 覆盖默认蓝色渐变背景, 圆角裁剪 + 轻微阴影
- **登录卡片 logo 二次定制** (用户指定文件):
  - 登录卡片左侧 logo 改用 `public/RyoWebAuth.png` (用户提供的横向文字 wordmark, 1536×1024 RGBA, 2.2MB)
  - 新增 CSS 类 `.logo-icon-wordmark` / `.wordmark-img`: 宽高自适应 (120-160×64), `object-fit:contain`, 透明背景, 适配横向文字 logo
  - 原 `mdi:shield-key` 图标已被替换; "欢迎回来 / 登一下，很快的" 文字保留不变
- **README 头部展示**：使用 `./public/logo-256.png` 路径, 在 GitHub / IDE / TRAE 预览均可直接看到 logo
- **2FA 验证尝试次数可调**：新增 `/api/admin/settings` 接受 `totpRateLimit.max` (1-100) 和 `totpRateLimit.windowMs` (10s-1h) 参数, 立即生效
- **超管/管理员均可配置**：系统设置页新增"2FA 验证限流"区段, 2 个数字输入框（时间窗口 + 次数）+ 保存按钮, 提示文字实时显示当前值
- **默认 1 分钟 5 次**：保持安全默认值, 用户可根据风险偏好调整; 输入 0 = 紧急关停 2FA 验证
- **设置接口扩展**：GET /api/admin/settings 同时返回 `rateLimits` (各桶当前生效值), 方便前端展示
- **启动时加载覆盖**：服务启动时自动从 settings.json 读取 `rateLimits` 并应用, 无需重启
- **smoke 测试加固**：测试开始时把 totp 上限临时调到 100, 避免密集测试触发自身限流 (生产默认值不变)

### v1.0.2.1 (2026-07-18) — UI 修复版

- **密码长度提示同步**：所有"至少6位"的 placeholder / JS 提示已更新为 `≥8位，含两类字符`，与新密码策略保持一致（注册 / 改密 / 管理员创建用户 / 管理员强制改密 4 处）
- **客户端密码强度校验**：新增 `clientCheckPasswordStrength()`，提交前先校验，避免无意义请求
- **Iconify 图标本地化**：移除 `code.iconify.design` CDN 依赖，内联 11 个 MDI 图标 SVG（`mdi:weather-night` / `shield-lock` / `shield-key` / `shield-key-outline` / `login` / `account-plus` / `shield-check` / `lock-reset` / `logout` / `close` / `image-search`），离线可用
- **图标动态渲染**：用 `MutationObserver` 监听 DOM 变化，innerHTML 注入的图标也会被自动渲染（解决切 tab 出现的图标丢失）
- **CSP 收敛**：移除 iconify CDN 白名单，只保留必要的 jsdelivr / unpkg / google fonts

### v1.0.2 (2026-07-18) — 安全加固版

- **CSRF 双重提交 Token**：登录/注册时下发 `csrf_token` cookie；所有写操作需 `X-CSRF-Token` 头携带并通过 `timingSafeEqual` 校验
- **密码强度策略**：长度 ≥ 8、至少两类字符、常见弱密码黑名单；应用在注册 / 改密 / 超管创建用户 / 超管强制改密
- **JSON 文件读写同步互斥锁**：即使将来有 `await` 打断读-改-写序列也不会并发覆盖
- **安全响应头**：CSP（限制 inline + CDN 白名单）、X-Frame-Options DENY、nosniff、Referrer-Policy、Permissions-Policy
- **登录接口补充**：补 `Content-Length: 0` 修复无 body 时的请求解析边缘情况

### v1.0.1 (2026-07-18) — 安全修复版

- **CSPRNG**：TOTP 密钥、超管初始密码改用 `crypto.randomBytes`
- **XSS 修复**：生成器卡片改用 `data-*` + 事件委托，移除 `onclick` 中嵌入用户输入
- **全站限流**：登录 / 注册 / 2FA / 改密 / 通用 API 加入滑动窗口
- **timing-safe**：密码 / TOTP 改用 `crypto.timingSafeEqual`
- **TOTP 窗口**：验证加入 ±1 时间步容忍
- **请求体限制**：默认 1 MB
- **关闭 2FA**：需要 TOTP 码 + 当前密码
- **生成器 secret**：列表接口不再下发 secret，新增按需拉取接口（带限流）
- **改密后失效 session**：自己改密也会清空该用户所有 session（与超管强制改密一致）
- **角色变更失效 session**：用户角色被改后，所有该用户的 session 失效
- **CORS**：移除 `Access-Control-Allow-Origin: *`
- **Cookie Secure**：HTTPS 下自动附加
- **JSON 原子写**：写临时文件后 `rename`
- **登录时序均衡**：用户不存在时仍执行一次 scrypt
- **SPA fallback**：仅对 HTML 路径降级到 index.html，静态资源 404 真实返回

### 2026-07-17

### 新增功能
- 主题默认跟随系统 `prefers-color-scheme`，手动切换后记住自定义设置
- 摄像头自动降级：先尝试后置→失败自动切换前置
- 非 HTTPS 环境摄像头不可用时给出明确提示
- 管理员系统设置新增「添加用户」按钮
- 普通用户新增「注销账号」功能：需输入密码确认，注销后清除所有数据和生成器
- 普通用户注销账号前须先删除所有生成器（后端校验拦截）
- 超级管理员用户列表新增「改密」按钮，可强制修改任意用户密码（设置 forcePasswordChange，清除 session 强制重登）

### 修复
- 修复页面无法滚动（`.main-container` 移除 `overflow:hidden`）
- 修复退出登录后水印未恢复 100% 透明度
- 修复手机浏览器摄像头报错 `Camera streaming not supported`
- 增加容器底部 padding，防止生成器过多被 footer 遮挡
- 水印透明度按角色区分：登录页/超管 100%，普通用户/管理员 30%
- 修复编辑按钮点击无效：模态框缺少 `#editGenRemark` 输入框导致 JS 报错弹窗无法显示
- 修复保存生成器时备注字段未写入 API 请求体
- 修复后端 GET entries 端点遗漏 `remark` 字段，前端始终无法获取备注数据
- 备注显示位置从进度条上方移至进度条下方
- 手机版生成器卡片三个操作按钮改为纵向排列（✎ → × → ⋮）
- 点击验证码一键复制到剪贴板，含非 HTTPS 环境 fallback

### 其他
- 新增 `.gitignore`，忽略 `node_modules/`、`data/*.json`、`*.txt`、`.env`
- 生成器新增备注字段，可在编辑弹窗中填写（选填，默认空）
