# 目前    RyuWebAuth   版本信息  V1.0.0

——————

# RyuWebAuth

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

控制台会输出超级管理员的随机密码，格式为 `8位随机字母数字混合`：

```
==========================================================
  RyuWebAuth Super Admin Account Created
  Username : RyuWebAuth
  Password : !x9xKpQ1
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
├── package.json       # 项目元信息
├── public/
│   └── index.html     # 前端单页应用（HTML + CSS + JS）
├── data/              # JSON 数据存储目录（自动创建）
│   ├── users.json     # 用户数据
│   ├── sessions.json  # 会话数据
│   └── settings.json  # 系统设置
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

### 管理（需超级管理员权限）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/users` | 获取所有用户列表 |
| POST | `/api/admin/set-role` | 设置用户角色（`user` / `admin`） |
| GET | `/api/admin/settings` | 获取系统设置 |
| POST | `/api/admin/settings` | 更新系统设置（注册开关等） |

### 2FA

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/2fa/setup` | 生成 2FA 密钥和二维码 URI |
| POST | `/api/2fa/verify-setup` | 验证 TOTP 码并激活 2FA |
| POST | `/api/2fa/disable` | 验证 TOTP 码并禁用 2FA |

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

### 会话管理

- 基于 Cookie 的 Session 机制
- Session ID 使用 `crypto.randomUUID()` 生成
- 默认有效期 24 小时
- 服务重启后所有 Session 失效

### 数据存储

所有数据以 JSON 格式存储在 `data/` 目录下，结构清晰，便于备份和迁移。

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
