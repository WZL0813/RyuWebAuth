// ====================================================================
//  RyuWebAuth — Web 认证服务 (Node.js 原生 http 模块)
//  注册 / 登录 / 2FA TOTP 双因素验证 / 用户管理
//  v1.0.1 — 安全修复版
// ====================================================================
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { URL } = require('url');

const PORT = 3180;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 小时
const SESSION_TTL_LONG = 30 * 24 * 60 * 60 * 1000; // 30 天

// ==================== 请求体大小限制 ====================
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1 MB

// ==================== 频率限制 (IP/账号 滑动窗口) ====================
// 结构: { key: { count, firstAt, blockedUntil } }
// 启动时从 settings.json 覆盖 (超管可在 system settings 里调)
const RATE_LIMITS = {
  login:     { windowMs: 60 * 1000,        max: 10  }, // 1 分钟 10 次  (按 IP)
  register:  { windowMs: 60 * 60 * 1000,   max: 5   }, // 1 小时 5 次   (按 IP)
  totp:      { windowMs: 60 * 1000,        max: 5   }, // 1 分钟 5 次   (按 IP+用户名, 可调)
  changePw:  { windowMs: 60 * 1000,        max: 5   }, // 1 分钟 5 次   (按 IP)
  api:       { windowMs: 1000,             max: 30  }  // 通用每秒 30 次 (按 IP)
};
const rateState = new Map();

// 把 settings.json 里的限流覆盖写回 RATE_LIMITS
function applyRateLimitOverrides(overrides) {
  if (!overrides || typeof overrides !== 'object') return;
  for (const bucket of Object.keys(overrides)) {
    if (!RATE_LIMITS[bucket]) continue;
    const o = overrides[bucket];
    if (o && Number.isFinite(o.windowMs) && o.windowMs >= 1000 && o.windowMs <= 24 * 60 * 60 * 1000) {
      RATE_LIMITS[bucket].windowMs = Math.floor(o.windowMs);
    }
    if (o && Number.isFinite(o.max) && o.max >= 1 && o.max <= 100000) {
      RATE_LIMITS[bucket].max = Math.floor(o.max);
    }
  }
}

function clientIP(req) {
  // 仅信任本地回环; 生产部署在反代后请改从 X-Forwarded-For 取
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function rateCheck(bucket, key) {
  const cfg = RATE_LIMITS[bucket];
  if (!cfg) return { ok: true };
  const k = `${bucket}:${key}`;
  const now = Date.now();
  const entry = rateState.get(k) || { count: 0, firstAt: now, blockedUntil: 0 };
  if (entry.blockedUntil && entry.blockedUntil > now) {
    return { ok: false, retryAfter: Math.ceil((entry.blockedUntil - now) / 1000) };
  }
  if (now - entry.firstAt > cfg.windowMs) {
    entry.count = 0;
    entry.firstAt = now;
  }
  entry.count += 1;
  if (entry.count > cfg.max) {
    entry.blockedUntil = now + cfg.windowMs;
    rateState.set(k, entry);
    return { ok: false, retryAfter: Math.ceil(cfg.windowMs / 1000) };
  }
  rateState.set(k, entry);
  return { ok: true };
}

// 定期清理过期 rate 记录
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of rateState.entries()) {
    if ((e.blockedUntil && e.blockedUntil < now) ||
        (!e.blockedUntil && now - e.firstAt > 60 * 60 * 1000)) {
      rateState.delete(k);
    }
  }
}, 5 * 60 * 1000).unref();

// ==================== 日志工具 ====================
const COL = { reset: '\x1b[0m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', blue: '\x1b[34m', cyan: '\x1b[36m' };

function fmtTime() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function log(tag, msg, color) {
  const c = COL[color] || COL.reset;
  console.log(`${c}[${fmtTime()}] [${tag.padEnd(4)}] ${msg}${COL.reset}`);
}

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ==================== JSON 数据持久化 (原子写 + 同步互斥) ====================
// 说明: Node.js 的 JS 主线程是单线程, 因此对单个 JSON 文件的
//   "readFileSync -> 内存改 -> writeFileSync" 在没有 await 打断时本身是原子的。
//   但 readJSON/writeJSON 是模块顶层 API, 调用方可能穿插 await, 仍可能造成
//   读-改-写竞态。这里加一个同步互斥锁串行化所有读写, 即使将来有 await 也不影响。
//   由于所有操作都是同步的, 锁实际从不被等待 — 仅作"双保险"。
const writeLocks = new Map(); // filename -> true 表示持锁

function withSyncWriteLock(filename, fn) {
  if (writeLocks.get(filename)) {
    // 在同步 API 设计下, 同一个文件名不会出现并发持锁者
    throw new Error('data file lock contention: ' + filename);
  }
  writeLocks.set(filename, true);
  try {
    return fn();
  } finally {
    writeLocks.set(filename, false);
  }
}

function readJSON(filename) {
  return withSyncWriteLock(filename, () => {
    try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, filename), 'utf8')); }
    catch { return null; }
  });
}

function writeJSON(filename, data) {
  return withSyncWriteLock(filename, () => {
    const filePath = path.join(DATA_DIR, filename);
    const tmpPath = filePath + '.tmp.' + crypto.randomBytes(4).toString('hex');
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmpPath, filePath);
  });
}

// ==================== 密码哈希 (scrypt, timing-safe) ====================
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, expected] = stored.split(':');
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  // 使用常时比较避免时序攻击
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ==================== TOTP 实现 (RFC 6238, timing-safe + ±1 窗口) ====================
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  str = str.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0, value = 0;
  const output = [];
  for (let i = 0; i < str.length; i++) {
    value = (value << 5) | alphabet.indexOf(str[i]);
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTOTP(secret, timeStep = 30, digits = 6, counter = null) {
  if (counter == null) counter = Math.floor(Date.now() / 1000 / timeStep);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(counter));
  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % Math.pow(10, digits)).padStart(digits, '0');
}

// 常时比较 TOTP 码 (字符串定长 6 位, 转为 Buffer)
function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return crypto.timingSafeEqual(ab, bb);
}

// 验证 TOTP, 允许 ±1 时间步窗口 (RFC 6238 推荐)
function verifyTOTP(secret, code, timeStep = 30, digits = 6) {
  if (typeof code !== 'string' || code.length !== digits) return false;
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  for (let w = -1; w <= 1; w++) {
    const c = generateTOTP(secret, timeStep, digits, counter + w);
    if (timingSafeEqualStr(c, code)) return true;
  }
  return false;
}

// CSPRNG 生成 32 字符 Base32 密钥
function generateTOTPSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(20); // 160-bit
  let secret = '';
  for (let i = 0; i < 20; i++) {
    // 取 5 bit (0-31) 映射到 base32 字母表
    const byte = bytes[i];
    secret += alphabet[(byte >> (i % 8)) & 0x1f] || alphabet[byte & 0x1f];
  }
  // 简化: 5 bit 一组, 取 32 个 base32 字符 -> 直接生成 32 个字符
  const buf = crypto.randomBytes(32);
  let s = '';
  for (let i = 0; i < 32; i++) s += alphabet[buf[i] % 32];
  return s;
}

// CSPRNG 生成超管初始密码
function generateRandomPassword(length = 12) {
  // 排除容易混淆的字符
  const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
  const bytes = crypto.randomBytes(length);
  let pwd = '';
  for (let i = 0; i < length; i++) pwd += chars[bytes[i] % chars.length];
  return pwd;
}

function getTOTPUri(secret, label, issuer = 'RyuWebAuth') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ==================== 密码强度校验 ====================
// 策略: 长度 ≥ 8, 且至少包含两类 (小写/大写/数字/符号)
function validatePasswordStrength(pw) {
  if (typeof pw !== 'string') return '密码不能为空';
  if (pw.length < 8) return '密码长度不能少于 8 位';
  if (pw.length > 128) return '密码长度不能超过 128 位';
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  if (classes < 2) return '密码必须包含至少两类字符 (小写/大写/数字/符号)';
  // 常见弱密码黑名单
  const COMMON = new Set(['password', '12345678', '123456789', 'qwerty123', 'admin123', 'iloveyou1']);
  if (COMMON.has(pw.toLowerCase())) return '密码过于常见, 请更换';
  return null;
}

// ==================== Session 管理 ====================
function loadSessions() {
  const s = readJSON('sessions.json') || {};
  const now = Date.now();
  let changed = false;
  for (const sid of Object.keys(s)) {
    if (s[sid].expiresAt < now) { delete s[sid]; changed = true; }
  }
  if (changed) writeJSON('sessions.json', s);
  return s;
}

function saveSessions(s) { writeJSON('sessions.json', s); }

function createSession(username, role, ttl) {
  const sessions = loadSessions();
  const sessionId = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  sessions[sessionId] = {
    username, role,
    createdAt: Date.now(),
    expiresAt: Date.now() + (ttl || SESSION_TTL),
    csrfToken
  };
  saveSessions(sessions);
  return { sessionId, csrfToken };
}

function getSession(sessionId) {
  if (!sessionId) return null;
  const sessions = loadSessions();
  const s = sessions[sessionId];
  if (!s || s.expiresAt < Date.now()) return null;
  return s;
}

function destroySession(sessionId) {
  if (!sessionId) return;
  const sessions = loadSessions();
  delete sessions[sessionId];
  saveSessions(sessions);
}

// 清除某用户的所有 session
function destroyUserSessions(username) {
  const sessions = loadSessions();
  let changed = false;
  for (const [sid, s] of Object.entries(sessions)) {
    if (s.username === username) { delete sessions[sid]; changed = true; }
  }
  if (changed) saveSessions(sessions);
}

// ==================== 用户与设置管理 ====================
function loadUsers() {
  const users = readJSON('users.json') || {};
  // 超级管理员防篡改保护
  if (users['RyuWebAuth'] && users['RyuWebAuth'].role !== 'superadmin') {
    users['RyuWebAuth'].role = 'superadmin';
    saveUsers(users);
  }
  return users;
}
function saveUsers(u) { writeJSON('users.json', u); }
function loadSettings() { return readJSON('settings.json') || { registrationEnabled: true }; }
function saveSettings(s) { writeJSON('settings.json', s); }
function load2FAEntries() { return readJSON('2fa_entries.json') || {}; }
function save2FAEntries(e) { writeJSON('2fa_entries.json', e); }

// ==================== 超级管理员初始化 ====================
function initSuperAdmin() {
  const users = loadUsers();
  if (!users['RyuWebAuth']) {
    const password = generateRandomPassword(12);

    users['RyuWebAuth'] = {
      passwordHash: hashPassword(password),
      role: 'superadmin',
      forcePasswordChange: true,
      twoFactorEnabled: false,
      createdAt: Date.now()
    };
    saveUsers(users);

    process.stdout.write('\n');
    process.stdout.write('='.repeat(56) + '\n');
    process.stdout.write('  Super Admin Account Created\n');
    process.stdout.write('  Username : RyuWebAuth\n');
    process.stdout.write('  Password : ' + password + '\n');
    process.stdout.write('  Please change password on first login!\n');
    process.stdout.write('='.repeat(56) + '\n');
    process.stdout.write('\n');
    return { created: true, username: 'RyuWebAuth', password };
  }

  // 账号已存在，也打印提示避免用户困惑
  process.stdout.write('\n');
  process.stdout.write('  [INFO] Super admin account already exists (RyuWebAuth)\n');
  process.stdout.write('\n');
  return { created: false };
}

// ==================== 请求解析 (限制大小) ====================
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    let size = 0;
    let aborted = false;
    req.on('data', chunk => {
      if (aborted) return;
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        aborted = true;
        try { req.destroy(); } catch {}
        resolve({ __overflow: true });
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (aborted) return;
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
    req.on('error', () => { if (!aborted) resolve({}); });
  });
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

// ==================== 会话鉴权辅助 ====================
function getAuthSession(req, res) {
  const cookies = parseCookies(req);
  const session = getSession(cookies.session_id);
  if (!session) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '请先登录' }));
    return null;
  }
  return session;
}

function requireRole(req, res, roles) {
  const session = getAuthSession(req, res);
  if (!session) return null;
  if (roles && roles.length && !roles.includes(session.role)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '权限不足' }));
    return null;
  }
  return session;
}

// 要求会话 + CSRF 双重校验 (非 GET 方法). 用于所有写操作.
function requireSessionWithCsrf(req, res, roles) {
  const session = getAuthSession(req, res);
  if (!session) return null;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (!verifyCsrf(req, res, session)) return null;
  }
  if (roles && roles.length && !roles.includes(session.role)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '权限不足' }));
    return null;
  }
  return session;
}

// CSRF 双重提交校验: 客户端必须从 csrf_token cookie 读取值, 放到
//   X-CSRF-Token 头 中发回. 二者必须 timing-safe 相等.
// 单纯 "header || cookie" 失去了双重提交的意义, 因为浏览器会自动带 cookie
// —— 必须显式来自其他源 (如 JS 读 cookie 后放到 header).
function verifyCsrf(req, res, session) {
  if (!session.csrfToken) return true; // 旧 session 兼容 (理论上不存留)
  const headerToken = req.headers['x-csrf-token'] || '';
  if (!headerToken) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '缺少 CSRF Token' }));
    return false;
  }
  const a = Buffer.from(headerToken);
  const b = Buffer.from(session.csrfToken);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'CSRF Token 不匹配' }));
    return false;
  }
  return true;
}

// ==================== 安全响应头 ====================
// 注: 图标已全部内联到 index.html, 不再需要 iconify CDN 白名单.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "img-src 'self' data: blob: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'"
].join('; ');

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0'); // 旧浏览器兼容, 现代 CSP 优先
  // Permissions-Policy: 仅开放需要的特性
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(self), payment=()');
}

function setCspHeaders(res) {
  res.setHeader('Content-Security-Policy', CSP);
  setSecurityHeaders(res);
}

// ==================== 静态文件服务 ====================
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
};

function serveStatic(req, res) {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);
  let filePath = path.join(PUBLIC_DIR, reqUrl.pathname === '/' ? 'index.html' : reqUrl.pathname);

  // 规范化路径防止目录遍历
  filePath = path.normalize(filePath);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    setSecurityHeaders(res);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    // SPA fallback: 仅对 HTML 路径返回 index.html, 静态资源 404 真实返回
    if (reqUrl.pathname === '/' || reqUrl.pathname.endsWith('/') || path.extname(reqUrl.pathname) === '') {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    } else {
      setSecurityHeaders(res);
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
  }

  try {
    const ext = path.extname(filePath);
    const contentType = MIME[ext] || 'application/octet-stream';
    const content = fs.readFileSync(filePath);
    setCspHeaders(res);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store'
    });
    res.end(content);
  } catch (e) {
    setSecurityHeaders(res);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  }
}

// ==================== HTTP 服务器 ====================
const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = reqUrl.pathname;
  const ip = clientIP(req);

  // ==================== API 路由 ====================
  if (pathname.startsWith('/api/')) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    setSecurityHeaders(res);

    // 全局限流 (通用)
    const rl = rateCheck('api', ip);
    if (!rl.ok) {
      res.setHeader('Retry-After', String(rl.retryAfter));
      res.writeHead(429);
      res.end(JSON.stringify({ error: '请求过于频繁，请稍后再试' }));
      return;
    }

    log('REQ', `${req.method} ${pathname}`, 'blue');

    try {
      // ---------- 登录 ----------
      if (pathname === '/api/login' && req.method === 'POST') {
        const r = rateCheck('login', ip);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '登录尝试过于频繁，请稍后再试' }));
          return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username, password, totpCode } = body;

        if (!username || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请输入用户名和密码' })); log('AUTH', 'Login failed: missing username or password', 'yellow'); return;
        }

        // 无论用户是否存在, 先做一次哈希运算以抑制时序差异
        const users = loadUsers();
        const user = users[username];
        if (!user) {
          // 用户不存在, 仍执行一次空哈希
          crypto.scryptSync(password, crypto.randomBytes(16), 64);
          res.writeHead(401); res.end(JSON.stringify({ error: '用户名或密码错误' })); log('AUTH', `Login failed: ${username} (invalid credentials)`, 'yellow'); return;
        }
        if (!verifyPassword(password, user.passwordHash)) {
          res.writeHead(401); res.end(JSON.stringify({ error: '用户名或密码错误' })); log('AUTH', `Login failed: ${username} (invalid credentials)`, 'yellow'); return;
        }

        // 登录模式限制
        const settings = loadSettings();
        const loginMode = settings.loginMode || 'all';
        if (loginMode === 'superadmin' && user.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '当前仅允许超级管理员登录' })); log('AUTH', `Login denied: ${username} (loginMode=superadmin)`, 'yellow'); return;
        }
        if (loginMode === 'admin' && user.role !== 'superadmin' && user.role !== 'admin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '当前仅允许管理员及以上登录' })); log('AUTH', `Login denied: ${username} (loginMode=admin)`, 'yellow'); return;
        }

        // 2FA 检查 (带 ±1 窗口, timing-safe)
        if (user.twoFactorEnabled) {
          if (!totpCode) {
            res.writeHead(200); res.end(JSON.stringify({ need2FA: true, username })); log('AUTH', `Login: ${username} requires 2FA verification`, 'yellow'); return;
          }
          // 2FA 限流 (按 IP+用户名)
          const r2 = rateCheck('totp', `${ip}:${username}`);
          if (!r2.ok) {
            res.setHeader('Retry-After', String(r2.retryAfter));
            res.writeHead(429); res.end(JSON.stringify({ error: '2FA 验证尝试过于频繁' }));
            return;
          }
          if (!verifyTOTP(user.twoFactorSecret, totpCode)) {
            res.writeHead(401); res.end(JSON.stringify({ error: '2FA验证码错误' })); log('AUTH', `Login failed: ${username} (invalid 2FA code)`, 'yellow'); return;
          }
        }

        const rememberMe = body.rememberMe === true;
        const sessionTtl = rememberMe ? SESSION_TTL_LONG : SESSION_TTL;
        const { sessionId, csrfToken } = createSession(username, user.role, sessionTtl);
        // Secure 标志: 仅当请求是 https 时附加
        const isHttps = (req.socket && req.socket.encrypted) || (req.headers['x-forwarded-proto'] === 'https');
        // session_id 必须 HttpOnly (JS 不可读); csrf_token 必须可被 JS 读 (不放 HttpOnly)
        res.setHeader('Set-Cookie', [
          `session_id=${sessionId}; HttpOnly; Path=/; Max-Age=${sessionTtl / 1000}; SameSite=Lax${isHttps ? '; Secure' : ''}`,
          `csrf_token=${csrfToken}; Path=/; Max-Age=${sessionTtl / 1000}; SameSite=Lax${isHttps ? '; Secure' : ''}`
        ]);
        res.writeHead(200);
        res.end(JSON.stringify({
          success: true, username, role: user.role,
          forcePasswordChange: user.forcePasswordChange || false,
          twoFactorEnabled: user.twoFactorEnabled || false
        }));
        log('AUTH', `Login success: ${username} (${user.role})${rememberMe ? ' [rememberMe]' : ''}`, 'green');
        return;
      }

      // ---------- 注册 ----------
      if (pathname === '/api/register' && req.method === 'POST') {
        const r = rateCheck('register', ip);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '注册尝试过于频繁，请稍后再试' }));
          return;
        }
        const settings = loadSettings();
        if (!settings.registrationEnabled) {
          res.writeHead(403); res.end(JSON.stringify({ error: '注册功能已关闭，请联系管理员' })); log('REG ', 'Registration attempt blocked: registration disabled', 'yellow'); return;
        }

        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username, password } = body;

        if (!username || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名和密码不能为空' })); return;
        }
        if (username.length < 3 || username.length > 30) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名长度需在3-30个字符之间' })); return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名只能包含字母、数字和下划线' })); return;
        }
        const pwErr = validatePasswordStrength(password);
        if (pwErr) { res.writeHead(400); res.end(JSON.stringify({ error: pwErr })); return; }
        if (username === 'RyuWebAuth') {
          res.writeHead(400); res.end(JSON.stringify({ error: '该用户名已被系统保留' })); return;
        }

        const users = loadUsers();
        if (users[username]) {
          res.writeHead(409); res.end(JSON.stringify({ error: '用户名已存在' })); return;
        }

        users[username] = {
          passwordHash: hashPassword(password),
          role: 'user',
          forcePasswordChange: false,
          twoFactorEnabled: false,
          createdAt: Date.now()
        };
        saveUsers(users);

        const { sessionId, csrfToken } = createSession(username, 'user');
        const isHttps2 = (req.socket && req.socket.encrypted) || (req.headers['x-forwarded-proto'] === 'https');
        res.setHeader('Set-Cookie', [
          `session_id=${sessionId}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax${isHttps2 ? '; Secure' : ''}`,
          `csrf_token=${csrfToken}; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax${isHttps2 ? '; Secure' : ''}`
        ]);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, username, role: 'user', forcePasswordChange: false, twoFactorEnabled: false }));
        log('REG ', `Registration success: ${username}`, 'green');
        return;
      }

      // ---------- 退出登录 ----------
      if (pathname === '/api/logout' && req.method === 'POST') {
        const cookies = parseCookies(req);
        destroySession(cookies.session_id);
        const isHttps = (req.socket && req.socket.encrypted) || (req.headers['x-forwarded-proto'] === 'https');
        res.setHeader('Set-Cookie', [
          `session_id=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${isHttps ? '; Secure' : ''}`,
          `csrf_token=; Path=/; Max-Age=0; SameSite=Lax${isHttps ? '; Secure' : ''}`
        ]);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('AUTH', 'User logged out', 'green');
        return;
      }

      // ---------- 获取当前会话 ----------
      if (pathname === '/api/session' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const users = loadUsers();
        const user = users[session.username];
        res.writeHead(200);
        res.end(JSON.stringify({
          loggedIn: true,
          username: session.username,
          role: session.role,
          forcePasswordChange: user ? user.forcePasswordChange : false,
          twoFactorEnabled: user ? user.twoFactorEnabled : false
        }));
        return;
      }

      // ---------- 修改密码 ----------
      if (pathname === '/api/change-password' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const r = rateCheck('changePw', `${ip}:${session.username}`);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '改密尝试过于频繁' }));
          return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { currentPassword, newPassword } = body;
        const users = loadUsers();
        const user = users[session.username];

        if (!verifyPassword(currentPassword, user.passwordHash)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '当前密码错误' })); return;
        }
        const pwErr = validatePasswordStrength(newPassword);
        if (pwErr) { res.writeHead(400); res.end(JSON.stringify({ error: pwErr })); return; }

        user.passwordHash = hashPassword(newPassword);
        user.forcePasswordChange = false;
        saveUsers(users);
        // 自己改密后, 清除该用户所有 session, 强制重新登录 (与强制改密一致)
        destroyUserSessions(session.username);
        // 立即给当前 session 续一个新 id, 避免用户被立即登出导致"改密成功但又需重新登录"
        const newTtl = 24 * 60 * 60 * 1000;
        const { sessionId, csrfToken } = createSession(session.username, session.role, newTtl);
        const isHttps = (req.socket && req.socket.encrypted) || (req.headers['x-forwarded-proto'] === 'https');
        res.setHeader('Set-Cookie', [
          `session_id=${sessionId}; HttpOnly; Path=/; Max-Age=${newTtl / 1000}; SameSite=Lax${isHttps ? '; Secure' : ''}`,
          `csrf_token=${csrfToken}; Path=/; Max-Age=${newTtl / 1000}; SameSite=Lax${isHttps ? '; Secure' : ''}`
        ]);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('AUTH', `Password changed: ${session.username}`, 'green');
        return;
      }

      // ---------- 注销账号 ----------
      if (pathname === '/api/account/delete' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { password } = body;
        if (!password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请输入密码' })); return;
        }
        const users = loadUsers();
        const user = users[session.username];
        if (!user) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        if (session.username === 'RyuWebAuth') {
          res.writeHead(400); res.end(JSON.stringify({ error: '不能注销超级管理员账号' })); return;
        }
        if (session.role === 'superadmin') {
          res.writeHead(400); res.end(JSON.stringify({ error: '超级管理员账号不支持自助注销' })); return;
        }
        if (!verifyPassword(password, user.passwordHash)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '密码错误' })); return;
        }
        // 检查是否还有生成器
        const entries = load2FAEntries();
        const userEntries = entries[session.username];
        if (userEntries && userEntries.length > 0) {
          res.writeHead(400); res.end(JSON.stringify({ error: `请先删除所有生成器后再注销（当前 ${userEntries.length} 个）` })); return;
        }
        // 删除用户
        delete users[session.username];
        saveUsers(users);
        // 清理 sessions
        destroyUserSessions(session.username);
        // 清理 2FA entries
        delete entries[session.username];
        save2FAEntries(entries);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('AUTH', `User '${session.username}' deleted their account`, 'yellow');
        return;
      }

      // ---------- 管理员：用户列表 ----------
      if (pathname === '/api/admin/users' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const users = loadUsers();
        const list = Object.entries(users).map(([name, u]) => ({
          username: name,
          role: u.role,
          twoFactorEnabled: u.twoFactorEnabled || false,
          createdAt: u.createdAt
        })).sort((a, b) => b.createdAt - a.createdAt);
        res.writeHead(200); res.end(JSON.stringify({ users: list }));
        log('ADM ', `User '${session.username}' fetched user list (${list.length} users)`, 'cyan');
        return;
      }

      // ---------- 管理员：设置角色 ----------
      if (pathname === '/api/admin/set-role' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username, role } = body;
        if (username === 'RyuWebAuth') {
          res.writeHead(400); res.end(JSON.stringify({ error: '不能修改超级管理员的角色' })); return;
        }
        if (!['user', 'admin'].includes(role)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '无效的角色' })); return;
        }
        const users = loadUsers();
        if (!users[username]) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        users[username].role = role;
        saveUsers(users);
        // 角色变更后, 失效该用户所有 session
        destroyUserSessions(username);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' set role of '${username}' to '${role}'`, 'green');
        return;
      }

      // ---------- 管理员：获取设置 ----------
      if (pathname === '/api/admin/settings' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res, ['superadmin', 'admin']); if (!session) return;
        const settings = loadSettings();
        // 回传当前生效的限流, 方便前端显示
        const effectiveLimits = {};
        for (const [bucket, cfg] of Object.entries(RATE_LIMITS)) {
          effectiveLimits[bucket] = { windowMs: cfg.windowMs, max: cfg.max };
        }
        res.writeHead(200); res.end(JSON.stringify({ settings, rateLimits: effectiveLimits })); return;
      }

      // ---------- 管理员：更新设置 ----------
      if (pathname === '/api/admin/settings' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin', 'admin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const settings = loadSettings();
        if (typeof body.registrationEnabled === 'boolean') {
          settings.registrationEnabled = body.registrationEnabled;
        }
        if (body.loginMode && ['superadmin', 'admin', 'all'].includes(body.loginMode)) {
          settings.loginMode = body.loginMode;
        }
        // 2FA 验证限流 (默认 1 分钟, 次数可调, 超管/管理员都能改)
        if (body.totpRateLimit && typeof body.totpRateLimit === 'object') {
          if (!settings.rateLimits) settings.rateLimits = {};
          if (!settings.rateLimits.totp) settings.rateLimits.totp = {};
          const m = body.totpRateLimit.max;
          // 边界: 1-100 (0 = 紧急关停 2FA 验证)
          if (Number.isFinite(m) && m >= 0 && m <= 100) {
            settings.rateLimits.totp.max = Math.floor(m);
          }
          // 窗口: 默认 60000 (1 分钟), 允许 10s - 1h
          if (Number.isFinite(body.totpRateLimit.windowMs) && body.totpRateLimit.windowMs >= 10000 && body.totpRateLimit.windowMs <= 60 * 60 * 1000) {
            settings.rateLimits.totp.windowMs = Math.floor(body.totpRateLimit.windowMs);
          }
        }
        saveSettings(settings);
        // 立即应用新限流
        applyRateLimitOverrides(settings.rateLimits);
        const effectiveLimits = {};
        for (const [bucket, cfg] of Object.entries(RATE_LIMITS)) {
          effectiveLimits[bucket] = { windowMs: cfg.windowMs, max: cfg.max };
        }
        res.writeHead(200); res.end(JSON.stringify({ success: true, settings, rateLimits: effectiveLimits }));
        log('ADM ', `User '${session.username}' updated settings (totp: max=${RATE_LIMITS.totp.max}/${Math.round(RATE_LIMITS.totp.windowMs/1000)}s)`, 'green');
        return;
      }

      // ---------- 公共：About / README ----------
      if (pathname === '/api/about' && req.method === 'GET') {
        try {
          const readme = fs.readFileSync(path.join(__dirname, 'README.md'), 'utf8');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ content: readme }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: '无法读取 README.md' }));
        }
        return;
      }

      // ---------- 管理员：创建用户 ----------
      if (pathname === '/api/admin/create-user' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username, password } = body;
        if (!username || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名和密码不能为空' })); return;
        }
        if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名需3-30位字母、数字或下划线' })); return;
        }
        const pwErr = validatePasswordStrength(password);
        if (pwErr) { res.writeHead(400); res.end(JSON.stringify({ error: pwErr })); return; }
        const users = loadUsers();
        if (users[username]) {
          res.writeHead(409); res.end(JSON.stringify({ error: '用户名已存在' })); return;
        }
        users[username] = {
          passwordHash: hashPassword(password),
          role: 'user',
          twoFactorEnabled: false,
          createdAt: Date.now()
        };
        saveUsers(users);
        res.writeHead(201); res.end(JSON.stringify({ success: true, username }));
        log('ADM ', `User '${session.username}' created new user '${username}'`, 'green');
        return;
      }

      // ---------- 管理员：删除用户 ----------
      if (pathname === '/api/admin/delete-user' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username } = body;
        if (!username) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名不能为空' })); return;
        }
        if (username === session.username) {
          res.writeHead(400); res.end(JSON.stringify({ error: '不能删除自己' })); return;
        }
        if (username === 'RyuWebAuth') {
          res.writeHead(400); res.end(JSON.stringify({ error: '不能删除超级管理员账号' })); return;
        }
        const users = loadUsers();
        if (!users[username]) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        delete users[username];
        saveUsers(users);

        // 清理该用户的 sessions
        destroyUserSessions(username);

        // 清理该用户的 2FA entries
        const entries = load2FAEntries();
        delete entries[username];
        save2FAEntries(entries);

        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' deleted user '${username}'`, 'yellow');
        return;
      }

      // ---------- 管理员：强制改密 ----------
      if (pathname === '/api/admin/reset-password' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username, newPassword } = body;
        if (!username || !newPassword) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名和新密码不能为空' })); return;
        }
        const pwErr = validatePasswordStrength(newPassword);
        if (pwErr) { res.writeHead(400); res.end(JSON.stringify({ error: pwErr })); return; }
        const users = loadUsers();
        if (!users[username]) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        users[username].passwordHash = hashPassword(newPassword);
        users[username].forcePasswordChange = true;
        saveUsers(users);
        // 清除该用户所有 session，强制重新登录
        destroyUserSessions(username);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' reset password for '${username}'`, 'yellow');
        return;
      }

      // ---------- 管理员：获取用户2FA信息 ----------
      // 注意: 此接口返回明文 secret 是高权限信任设计, 在 README 已注明为信任假设
      if (pathname === '/api/admin/user-2fa' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const url = new URL(req.url, 'http://localhost');
        const username = url.searchParams.get('username');
        if (!username) {
          res.writeHead(400); res.end(JSON.stringify({ error: '缺少用户名参数' })); return;
        }
        const users = loadUsers();
        const user = users[username];
        if (!user) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        res.writeHead(200); res.end(JSON.stringify({
          username,
          twoFactorEnabled: user.twoFactorEnabled || false,
          secret: user.twoFactorSecret || '',
          uri: user.twoFactorSecret ? getTOTPUri(user.twoFactorSecret, username) : '',
          currentCode: user.twoFactorSecret ? generateTOTP(user.twoFactorSecret) : ''
        })); return;
      }

      // ---------- 管理员：强制关闭用户2FA ----------
      if (pathname === '/api/admin/force-disable-2fa' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res, ['superadmin']); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { username } = body;
        if (!username) {
          res.writeHead(400); res.end(JSON.stringify({ error: '缺少用户名参数' })); return;
        }
        if (username === 'RyuWebAuth') {
          res.writeHead(400); res.end(JSON.stringify({ error: '不能强制关闭超级管理员的2FA，请在个人设置中操作' })); return;
        }
        const users = loadUsers();
        const user = users[username];
        if (!user) {
          res.writeHead(404); res.end(JSON.stringify({ error: '用户不存在' })); return;
        }
        if (!user.twoFactorEnabled) {
          res.writeHead(400); res.end(JSON.stringify({ error: '该用户未启用2FA' })); return;
        }
        user.twoFactorEnabled = false;
        delete user.twoFactorSecret;
        saveUsers(users);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' force-disabled 2FA for '${username}'`, 'yellow');
        return;
      }

      // ---------- 2FA：生成密钥 ----------
      if (pathname === '/api/2fa/setup' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const users = loadUsers();
        const user = users[session.username];
        if (user.twoFactorEnabled) {
          res.writeHead(400); res.end(JSON.stringify({ error: '2FA已启用，请先禁用后再重新设置' })); return;
        }
        const secret = generateTOTPSecret();
        const uri = getTOTPUri(secret, session.username);
        user.twoFactorPendingSecret = secret;
        saveUsers(users);
        res.writeHead(200); res.end(JSON.stringify({ secret, uri }));
        log('2FA ', `User '${session.username}' generated 2FA secret (pending verification)`, 'cyan');
        return;
      }

      // ---------- 2FA：验证并激活 ----------
      if (pathname === '/api/2fa/verify-setup' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const r = rateCheck('totp', `${ip}:${session.username}`);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '2FA 验证尝试过于频繁' }));
          return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { code } = body;
        const users = loadUsers();
        const user = users[session.username];
        if (!user.twoFactorPendingSecret) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请先生成2FA密钥' })); return;
        }
        if (!verifyTOTP(user.twoFactorPendingSecret, code)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '验证码错误，请重试' })); return;
        }
        user.twoFactorSecret = user.twoFactorPendingSecret;
        user.twoFactorEnabled = true;
        delete user.twoFactorPendingSecret;
        saveUsers(users);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('2FA ', `User '${session.username}' activated 2FA`, 'green');
        return;
      }

      // ---------- 2FA：禁用 (需 TOTP 码 + 当前密码) ----------
      if (pathname === '/api/2fa/disable' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const r = rateCheck('totp', `${ip}:${session.username}`);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '2FA 操作过于频繁' }));
          return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { code, password } = body;
        if (!code || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请提供验证码和当前密码' })); return;
        }
        const users = loadUsers();
        const user = users[session.username];
        if (!user.twoFactorEnabled) {
          res.writeHead(400); res.end(JSON.stringify({ error: '2FA未启用' })); return;
        }
        // 既要 TOTP 也要密码 (防御 session 盗用)
        if (!verifyPassword(password, user.passwordHash)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '当前密码错误' })); return;
        }
        if (!verifyTOTP(user.twoFactorSecret, code)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '验证码错误' })); return;
        }
        user.twoFactorEnabled = false;
        delete user.twoFactorSecret;
        saveUsers(users);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('2FA ', `User '${session.username}' disabled 2FA`, 'yellow');
        return;
      }

      // ==================== TOTP 验证码生成器 ====================
      // 列出当前用户的 2FA 条目 (不再默认返回 secret, 前端按需调详情)
      if (pathname === '/api/2fa/generator/entries' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        if (session.role === 'superadmin') {
          res.writeHead(200); res.end(JSON.stringify({ entries: [] })); return;
        }
        const all = load2FAEntries();
        const entries = (all[session.username] || []).map(e => ({
          id: e.id,
          name: e.name,
          issuer: e.issuer,
          remark: e.remark || '',
          // 不再默认下发 secret, 避免一次 XSS/中间人就拿走所有种子
          hasSecret: true,
          createdAt: e.createdAt
        }));
        res.writeHead(200); res.end(JSON.stringify({ entries })); return;
      }

      // 按需获取单条 secret (限流 + 仅本人)
      if (pathname === '/api/2fa/generator/secret' && req.method === 'GET') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        if (session.role === 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '超级管理员不具备2FA功能' })); return;
        }
        const r = rateCheck('totp', `${ip}:${session.username}`);
        if (!r.ok) {
          res.setHeader('Retry-After', String(r.retryAfter));
          res.writeHead(429); res.end(JSON.stringify({ error: '请求过于频繁' }));
          return;
        }
        const url = new URL(req.url, 'http://localhost');
        const id = url.searchParams.get('id');
        if (!id) {
          res.writeHead(400); res.end(JSON.stringify({ error: '缺少条目ID' })); return;
        }
        const all = load2FAEntries();
        const list = all[session.username] || [];
        const e = list.find(x => x.id === id);
        if (!e) {
          res.writeHead(404); res.end(JSON.stringify({ error: '条目不存在' })); return;
        }
        res.writeHead(200); res.end(JSON.stringify({
          id: e.id, secret: e.secret, currentCode: generateTOTP(e.secret)
        }));
        return;
      }

      // 添加 2FA 条目（扫码 URI 或手动输入）
      if (pathname === '/api/2fa/generator/add' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        if (session.role === 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '超级管理员不具备2FA功能' })); return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        let secret, name, issuer;

        if (body.uri) {
          // 解析 otpauth URI
          try {
            const u = new URL(body.uri);
            if (u.protocol !== 'otpauth:') throw new Error('不是有效的 otpauth URI');
            const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
            const colonIdx = label.indexOf(':');
            issuer = colonIdx > -1 ? label.slice(0, colonIdx) : (u.searchParams.get('issuer') || '');
            name = colonIdx > -1 ? label.slice(colonIdx + 1) : label;
            secret = u.searchParams.get('secret');
            if (!secret) throw new Error('URI中未找到密钥');
            const issuerParam = u.searchParams.get('issuer');
            if (!issuer && issuerParam) issuer = issuerParam;
          } catch (e) {
            res.writeHead(400); res.end(JSON.stringify({ error: '二维码解析失败: ' + e.message })); return;
          }
        } else {
          secret = body.secret;
          name = body.name;
          issuer = body.issuer || '';
        }

        if (!secret || !name) {
          res.writeHead(400); res.end(JSON.stringify({ error: '密钥和名称不能为空' })); return;
        }
        // 验证 Base32
        secret = secret.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
        if (!/^[A-Z2-7]+$/.test(secret)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '密钥格式无效（需要Base32字符）' })); return;
        }

        const entry = {
          id: crypto.randomUUID(),
          name: String(name).slice(0, 50),
          issuer: String(issuer || '').slice(0, 30),
          secret,
          createdAt: Date.now()
        };
        const all = load2FAEntries();
        if (!all[session.username]) all[session.username] = [];
        all[session.username].push(entry);
        save2FAEntries(all);
        res.writeHead(201); res.end(JSON.stringify({ success: true, entry: { id: entry.id, name: entry.name, issuer: entry.issuer, remark: '', hasSecret: true, createdAt: entry.createdAt } }));
        log('2FA ', `User '${session.username}' added 2FA generator entry '${entry.name}' (${entry.issuer})`, 'green');
        return;
      }

      // 删除 2FA 条目
      if (pathname === '/api/2fa/generator/delete' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        if (session.role === 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '超级管理员不具备2FA功能' })); return;
        }
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { id } = body;
        if (!id) {
          res.writeHead(400); res.end(JSON.stringify({ error: '缺少条目ID' })); return;
        }
        const all = load2FAEntries();
        const entries = all[session.username];
        if (!entries) {
          res.writeHead(404); res.end(JSON.stringify({ error: '条目不存在' })); return;
        }
        const before = entries.length;
        all[session.username] = entries.filter(e => e.id !== id);
        if (all[session.username].length === before) {
          res.writeHead(404); res.end(JSON.stringify({ error: '条目不存在' })); return;
        }
        if (all[session.username].length === 0) delete all[session.username];
        save2FAEntries(all);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('2FA ', `User '${session.username}' deleted 2FA generator entry`, 'green');
        return;
      }

      // 更新 2FA 条目
      if (pathname === '/api/2fa/generator/update' && req.method === 'POST') {
        const session = requireSessionWithCsrf(req, res); if (!session) return;
        const body = await parseBody(req);
        if (body.__overflow) { res.writeHead(413); res.end(JSON.stringify({ error: '请求体过大' })); return; }
        const { id, name, issuer, remark } = body;
        if (!id) { res.writeHead(400); res.end(JSON.stringify({ error: '缺少条目ID' })); return; }
        const all = load2FAEntries();
        const entries = all[session.username];
        if (!entries) { res.writeHead(404); res.end(JSON.stringify({ error: '没有生成器条目' })); return; }
        const entry = entries.find(e => e.id === id);
        if (!entry) { res.writeHead(404); res.end(JSON.stringify({ error: '条目不存在' })); return; }
        if (name) entry.name = String(name).slice(0, 50);
        if (issuer) entry.issuer = String(issuer).slice(0, 30);
        if (remark !== undefined) entry.remark = String(remark).slice(0, 100);
        save2FAEntries(all);
        res.writeHead(200); res.end(JSON.stringify({ success: true, entry: { id: entry.id, name: entry.name, issuer: entry.issuer, remark: entry.remark || '' } }));
        log('2FA ', `User '${session.username}' updated generator entry '${entry.name}'`, 'green');
        return;
      }

      // 未匹配的 API
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'API not found' }));
      log('ERR ', `Unknown API: ${req.method} ${pathname}`, 'yellow');

    } catch (e) {
      log('ERR ', `API Error (${req.method} ${pathname}): ${e.message}`, 'red');
      res.writeHead(500);
      res.end(JSON.stringify({ error: '服务器内部错误' }));
    }
    return;
  }

  // ==================== 静态文件 ====================
  serveStatic(req, res);
});

// ==================== 启动 ====================
const adminInfo = initSuperAdmin();
// 启动时把 settings.json 里的限流覆盖应用到 RATE_LIMITS
try { applyRateLimitOverrides(loadSettings().rateLimits); } catch(_) {}

server.listen(PORT, () => {
  log('INFO', `RyuWebAuth server started on port ${PORT}`, 'green');
  // 收集本机 IPv4 地址
  const ips = [];
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }

  process.stdout.write('\n');
  process.stdout.write('  ================================================\n');
  process.stdout.write('          Welcome to RyuWebAuth\n');
  process.stdout.write('          A beautiful Web authentication service\n');
  process.stdout.write('          with 2FA / TOTP support\n');
  process.stdout.write('  ================================================\n');
  process.stdout.write('\n');
  process.stdout.write(`  Service starting on port ${PORT} ...\n`);
  process.stdout.write('  ================================================\n');
  process.stdout.write('\n');
  process.stdout.write('  Access URLs:\n');
  process.stdout.write(`    http://localhost:${PORT}\n`);
  ips.forEach(ip => process.stdout.write(`    http://${ip}:${PORT}\n`));
  process.stdout.write('\n');
});
