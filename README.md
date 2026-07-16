# RyuWebAuth

> 独立、自托管的两步验证（2FA / TOTP）Web 服务，内置完整账户体系、管理后台、外部调用 API 与前端 SDK。

RyuWebAuth 是一个开箱即用的身份验证服务，基于 **Node.js + Express + SQLite** 构建。它既可以作为独立的账户中心（注册 / 登录 / 找回密码 / 两步验证），也可以作为一个 TOTP 动态码生成与校验中心，供你自己的业务系统通过 API Key 调用。

---

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [启动脚本 start.bat](#启动脚本-startbat)
- [默认超级管理员](#默认超级管理员)
- [环境变量配置](#环境变量配置)
- [HTTPS 证书](#https-证书)
- [页面说明](#页面说明)
- [数据库结构](#数据库结构)
- [API 文档](#api-文档)
- [外部 API 调用示例](#外部-api-调用示例)
- [安全设计](#安全设计)
- [目录结构](#目录结构)
- [常见问题](#常见问题)

---

## 功能特性

- **完整账户体系**：注册、登录、登出、会话（Cookie Session）管理。
- **两步验证（2FA / TOTP）**：兼容 Google Authenticator、Microsoft Authenticator、1Password 等标准验证器；支持二维码绑定与恢复码（Recovery Codes）。
- **密码找回**：支持「邮箱验证码」与「密保问题」两种方式。
- **邮箱验证**：注册时可选邮箱验证（可配置为强制），未配置 SMTP 时自动进入开发模式（验证码打印到控制台）。
- **管理后台**：超级管理员可管理账户（角色 / 状态 / 删除）、查看统计数据、开关注册与登录功能。
- **TOTP 管理仪表盘**：为外部服务集中托管密钥、实时生成动态码、批量查看。
- **外部调用 API**：通过 API Key 让你自己的业务系统校验 TOTP、获取当前动态码。
- **前端 SDK**：`public/2fa-sdk.js`，内置 CSRF 令牌自动处理。
- **生产级安全**：Helmet 安全响应头、CSRF 防护、速率限制、密钥加密存储、密码哈希、审计日志、可选 Webhook 回调。

## 技术栈

| 分类 | 选型 |
| --- | --- |
| 运行时 | Node.js |
| Web 框架 | Express 4 |
| 数据库 | better-sqlite3（SQLite） |
| 2FA / TOTP | speakeasy + qrcode |
| 安全 | helmet、cors、rate-limiter-flexible、Node crypto |
| 邮件 | nodemailer |
| 证书 | selfsigned / node-forge（自签名） |

---

## 快速开始

### 环境要求

- 安装 [Node.js](https://nodejs.org/)（建议 18+）。

### 安装与启动

```bash
# 1. 安装依赖
npm install

# 2. 复制环境变量模板并按需修改
copy .env.example .env      # Windows
# cp .env.example .env      # macOS / Linux

# 3. 启动服务
npm start
```

启动成功后，终端会输出品牌横幅 `RyuWebAuth` 以及可用于登录的多个地址，例如：

```
  ╔══════════════════════════════════════╗
  ║              RyuWebAuth              ║
  ╚══════════════════════════════════════╝

  两步验证（2FA / TOTP）服务已启动，可通过以下地址登录：

    - https://localhost:3180
    - https://127.0.0.1:3180
    - https://192.168.1.100:3180

  协议: HTTPS | CSRF: ON | 邮箱验证: 可选
```

默认端口为 **3180**，可通过 `.env` 中的 `PORT` 修改。

---

## 启动脚本 start.bat

Windows 用户可直接双击项目根目录下的 **`start.bat`** 一键启动。该脚本会：

1. 设置终端标题为 `RyuWebAuth` 并打印品牌横幅；
2. 列出可用于登录的地址（`localhost`、`127.0.0.1` 以及本机所有局域网 IPv4 地址，端口 `3180`）；
3. 检测 Node.js 是否安装，若缺失会给出提示；
4. 若 `node_modules` 不存在，自动执行 `npm install`；
5. 运行 `node server.js` 启动服务。

> 提示：脚本中的端口默认写死为 `3180`，若你修改了 `.env` 的 `PORT`，请同步修改 `start.bat` 顶部的 `set "PORT=3180"`。

---

## 默认超级管理员

首次启动且数据库中不存在管理员配置时，系统会自动创建一个超级管理员账户，并在控制台打印一次（请及时保存）：

| 用户名 | 密码 |
| --- | --- |
| `RyuWebAuth` | `F2a2026x` |

> **安全提醒**：请在首次登录后立即修改默认密码。生产环境务必更换默认凭据。

---

## 环境变量配置

复制 `.env.example` 为 `.env` 后按需填写：

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `PORT` | 服务监听端口 | `3180` |
| `NODE_ENV` | 运行环境（`production` 会关闭开发辅助接口） | `development` |
| `ENCRYPTION_KEY` | TOTP 密钥加密用的密钥，**32 字节十六进制（64 字符）** | 必填（生产） |
| `HTTPS_KEY` / `HTTPS_CERT` | HTTPS 证书路径 | `certs/key.pem`、`certs/cert.pem` |
| `ALLOWED_ORIGINS` | 跨域白名单（逗号分隔，留空允许任意来源） | 空 |
| `WEBHOOK_URL` | 验证成功 / 推送后的业务回调地址 | 空 |
| `ENABLE_CSRF` | 是否开启 CSRF 防护 | `true` |
| `REQUIRE_EMAIL_VERIFICATION` | 注册是否强制邮箱验证 | `false` |
| `EMAIL_CODE_TTL` | 邮箱验证码有效期（秒） | `600` |
| `VERIFY_RATE_POINTS` / `VERIFY_RATE_DURATION` | 验证速率限制（次数 / 秒） | `5` / `60` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURE` / `SMTP_USER` / `SMTP_PASS` | SMTP 邮件发送配置 | 空（开发模式） |
| `MAIL_FROM` | 发件人地址 | `no-reply@ryuwebauth.local` |
| `DB_FILE` | SQLite 数据库文件路径 | `./2fa.db` |
| `TWO_FACTOR_MODE` | 2FA 触发模式（预留：`every` / `session` / `timed`） | `every` |

生成加密密钥：

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## HTTPS 证书

- 当 `certs/key.pem` 与 `certs/cert.pem` 同时存在时，服务以 **HTTPS** 启动；否则回退为 HTTP 并给出警告。
- 项目已内置一套自签名证书，浏览器会提示「不安全」，本地开发可手动信任。
- 生产环境请替换为正式证书（如 Let's Encrypt），或通过 `HTTPS_KEY` / `HTTPS_CERT` 指定路径。

---

## 页面说明

| 路径 | 说明 |
| --- | --- |
| `/` | 账户中心入口（导航到各页面） |
| `/register.html` | 注册（信息 → 邮箱验证 → 2FA → 完成） |
| `/login.html` | 登录（用户名 / 邮箱 + 密码，必要时 2FA） |
| `/forgot.html` | 找回密码（邮箱 / 密保） |
| `/dashboard.html` | 仪表盘 / 管理后台（TOTP 管理、账户管理、设置、API Key） |

---

## 数据库结构

SQLite 单文件数据库（默认 `2fa.db`），主要表：

| 表 | 用途 |
| --- | --- |
| `accounts` | 账户信息（用户名、邮箱、密码哈希、角色、状态、密保等） |
| `users` | 已绑定 2FA 的用户密钥（加密）与恢复码哈希 |
| `sessions` | 登录会话 |
| `pending_regs` | 注册过程中的临时数据 |
| `reset_codes` | 密码重置验证码 |
| `api_keys` | 外部调用的 API Key（哈希存储） |
| `admin_config` | 超级管理员配置（加密） |
| `system_settings` | 系统开关（注册 / 登录） |
| `audit_log` | 审计日志 |

---

## API 文档

所有接口以 JSON 交互。除标注「API Key」的接口外，写操作（非 GET）默认需要携带 CSRF 令牌（请求头 `x-csrf-token`，值取自 `csrf_token` Cookie）；带「登录」的接口需要有效会话 Cookie。

### 账户 / 会话

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/login` | 用户名 / 邮箱 + 密码登录 |
| `POST` | `/api/logout` | 登出 |
| `GET` | `/api/me` | 当前登录用户信息（登录） |
| `GET` | `/api/config` | 公开配置 |

### 注册流程

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/reg/info` | 步骤一：提交账户信息 |
| `POST` | `/api/reg/email` | 步骤二：发送邮箱验证码（可选） |
| `POST` | `/api/reg/email/verify` | 校验邮箱验证码 |
| `POST` | `/api/reg/2fa` | 步骤三：开启 / 关闭 2FA |
| `POST` | `/api/reg/complete` | 步骤四：完成注册 |

### 两步验证（旧版通用接口）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/register` | 为 userId 绑定 2FA，返回密钥 / 二维码 / 恢复码 |
| `POST` | `/api/verify` | 校验动态码，返回临时令牌 |
| `POST` | `/api/session` | 用临时令牌换取会话 |
| `GET` | `/api/status/:userId` | 查询 2FA 是否开启 |
| `POST` | `/api/disable` | 校验动态码后禁用 2FA |
| `POST` | `/api/push/request` | 发起推送验证 |
| `POST` | `/api/push/approve` | 批准 / 拒绝推送 |
| `GET` | `/api/push/status/:pushId` | 查询推送状态 |
| `GET` | `/api/audit/:userId` | 查询审计日志（脱敏） |

### 用户 2FA 管理（登录）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/user/2fa/status` | 查询自己的 2FA 状态 |
| `POST` | `/api/user/2fa/enable` | 生成密钥并开启 |
| `POST` | `/api/user/2fa/verify` | 验证并确认开启 |
| `POST` | `/api/user/2fa/disable` | 验证后关闭 |

### 找回密码

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/reset/email` | 发送邮箱重置验证码 |
| `POST` | `/api/reset/verify` | 校验验证码并重置密码 |
| `POST` | `/api/reset/question` | 获取密保问题 |
| `POST` | `/api/reset/question/verify` | 校验密保答案并重置密码 |

### TOTP 管理（登录）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/totp/create` | 为账户导入 / 创建 TOTP 密钥 |
| `GET` | `/api/totp/current/:userId` | 获取当前动态码 |
| `POST` | `/api/totp/batch` | 批量获取动态码 |
| `POST` | `/api/totp/verify` | 校验动态码 |
| `DELETE` | `/api/totp/:userId` | 撤销 TOTP |
| `POST` | `/api/totp/apikey` | 创建 API Key |
| `GET` | `/api/totp/apikeys` | 列出 API Key（脱敏） |
| `DELETE` | `/api/totp/apikey/:id` | 删除 API Key |

### 外部 API（API Key 认证）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/totp/external/verify` | 校验 TOTP |
| `GET` | `/api/totp/external/current/:userId` | 获取当前动态码 |
| `GET` | `/api/totp/external/accounts` | 列出已配置 TOTP 的账户 |

### 管理员 API（超级管理员）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/admin/settings` | 读取系统设置 |
| `PUT` | `/api/admin/settings` | 更新系统设置（注册 / 登录开关） |
| `GET` | `/api/admin/stats` | 统计数据 |
| `GET` | `/api/admin/accounts` | 账号列表（分页 + 搜索） |
| `GET` | `/api/admin/accounts/:userId` | 账号详情 |
| `PUT` | `/api/admin/accounts/:userId` | 修改角色 / 状态 |
| `DELETE` | `/api/admin/accounts/:userId` | 删除账号 |

### 用户设置（登录）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/user/profile` | 个人资料 |
| `PUT` | `/api/user/profile` | 修改邮箱 / 密保 |
| `PUT` | `/api/user/password` | 修改密码 |
| `DELETE` | `/api/user/account` | 注销账户 |

---

## 外部 API 调用示例

先在仪表盘创建一个 API Key（形如 `f2a_xxxxxxxx...`），然后在请求头携带 `x-api-key`。

校验 TOTP：

```bash
curl -X POST https://your-server:3180/api/totp/external/verify \
  -H "Content-Type: application/json" \
  -H "x-api-key: f2a_your_api_key_here" \
  -d '{"userId":"alice","token":"123456"}'
```

获取当前动态码：

```bash
curl https://your-server:3180/api/totp/external/current/alice \
  -H "x-api-key: f2a_your_api_key_here"
```

---

## 安全设计

- **密钥加密存储**：TOTP 密钥使用 `ENCRYPTION_KEY` 加密后入库，恢复码仅存哈希。
- **密码哈希**：账户密码经哈希后存储，不可逆。
- **CSRF 防护**：默认开启，写操作需匹配 CSRF 令牌（外部 API 除外）。
- **速率限制**：登录、验证码发送、TOTP 校验等均有频率限制。
- **安全响应头**：Helmet（HSTS、`X-Content-Type-Options`、`X-Frame-Options` 等）。
- **审计日志**：关键操作记录用户、动作、IP 与结果。
- **Webhook**：可将验证成功等事件回调到业务系统。

---

## 目录结构

```
RyuWebAuth/
├── server.js            # 服务入口与全部路由
├── start.bat            # Windows 一键启动脚本
├── package.json
├── .env.example         # 环境变量模板
├── 2fa.db               # SQLite 数据库（运行时生成）
├── certs/               # HTTPS 证书（自签名）
│   ├── cert.pem
│   └── key.pem
├── src/
│   ├── db.js            # 数据库初始化与表结构
│   ├── crypto.js        # 加解密 / 哈希工具
│   ├── validation.js    # 用户名 / 密码 / 邮箱 / 年龄校验
│   └── email.js         # 邮件发送（含开发模式）
└── public/              # 前端页面与 SDK
    ├── index.html
    ├── login.html
    ├── register.html
    ├── forgot.html
    ├── dashboard.html
    └── 2fa-sdk.js
```

---

## 常见问题

**Q：启动后浏览器提示证书不安全？**
A：项目使用自签名证书，本地开发可手动信任；生产请替换为正式证书。

**Q：收不到邮箱验证码？**
A：未配置 SMTP 时为开发模式，验证码会打印到控制台；非生产环境也可通过 `GET /api/dev/code/:email` 读取。

**Q：忘记了超级管理员密码？**
A：可删除数据库中 `admin_config` 相关记录（或删除 `2fa.db` 重新初始化），重启后会重新生成默认管理员。请谨慎操作，删除数据库会清空所有数据。

**Q：如何修改端口？**
A：修改 `.env` 的 `PORT`，若使用 `start.bat` 请同步修改脚本顶部的 `set "PORT="`。
