require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const crypto = require('crypto');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');

const db = require('./src/db');
const { encrypt, decrypt, sha256, hashPassword, verifyPassword } = require('./src/crypto');
const { validateUsername, validatePassword, validateEmail, validateAge } = require('./src/validation');
const { sendMail, devCodes } = require('./src/email');

// ===================== 环境配置 =====================
const PORT = parseInt(process.env.PORT || '3180', 10);
const NODE_ENV = process.env.NODE_ENV || 'development';
const ENABLE_CSRF = (process.env.ENABLE_CSRF || 'true') !== 'false';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const WEBHOOK_URL = process.env.WEBHOOK_URL || '';
const TEMP_TOKEN_TTL = parseInt(process.env.TEMP_TOKEN_TTL || '300000', 10);
const RECOVERY_TOKEN_TTL = parseInt(process.env.RECOVERY_TOKEN_TTL || '60000', 10);
const VERIFY_RATE_POINTS = parseInt(process.env.VERIFY_RATE_POINTS || '5', 10);
const VERIFY_RATE_DURATION = parseInt(process.env.VERIFY_RATE_DURATION || '60', 10);
const EMAIL_CODE_TTL = parseInt(process.env.EMAIL_CODE_TTL || '600', 10); // 10 分钟
// 邮箱验证是否强制：默认关闭（可不验证，预留后期接入）；设为 true 则注册必须完成邮箱验证
const REQUIRE_EMAIL_VERIFICATION = (process.env.REQUIRE_EMAIL_VERIFICATION || 'false') !== 'false';

const app = express();

// 安全响应头（生产级配置）
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
}));
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
  credentials: true
}));
app.use(express.json({ limit: '100kb' }));

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}
const isSecure = fs.existsSync(path.join(__dirname, 'certs', 'key.pem'));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '0');
  const cookies = parseCookies(req);
  let token = cookies.csrf_token;
  if (!token) {
    token = crypto.randomBytes(16).toString('hex');
    res.cookie('csrf_token', token, {
      httpOnly: false,
      sameSite: 'lax',
      path: '/',
      secure: isSecure
    });
  }
  if (ENABLE_CSRF && req.method !== 'GET' && req.method !== 'OPTIONS' && !req.path.startsWith('/api/totp/external/')) {
    const headerToken = req.headers['x-csrf-token'];
    if (!headerToken || !token || headerToken !== token) {
      return res.status(403).json({ error: 'CSRF token mismatch' });
    }
  }
  next();
});

// ===================== Session 系统 =====================
const SESSION_TTL = 24 * 60 * 60 * 1000;

function createSession(userId, role, res) {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL;
  db.prepare('INSERT INTO sessions (sessionId, userId, role, createdAt, expiresAt) VALUES (?, ?, ?, ?, ?)')
    .run(sessionId, userId, role || 'user', Date.now(), expiresAt);
  res.cookie('session_id', sessionId, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL
  });
  return sessionId;
}

function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.session_id) {
    db.prepare('DELETE FROM sessions WHERE sessionId = ?').run(cookies.session_id);
  }
  res.clearCookie('session_id', { path: '/' });
}

function getSession(req) {
  const cookies = parseCookies(req);
  if (!cookies.session_id) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE sessionId = ? AND expiresAt > ?')
    .get(cookies.session_id, Date.now());
  return row || null;
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: '请先登录' });
  req.user = { userId: session.userId, role: session.role };
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.user?.role !== 'superadmin') return res.status(403).json({ error: '需要超级管理员权限' });
  next();
}

function checkRegistrationEnabled(req, res, next) {
  const row = db.prepare("SELECT value FROM system_settings WHERE key = 'registration_enabled'").get();
  if (row && row.value === '0') return res.status(403).json({ error: '注册功能已关闭' });
  next();
}

function checkLoginEnabled(req, res, next) {
  const row = db.prepare("SELECT value FROM system_settings WHERE key = 'login_enabled'").get();
  if (row && row.value === '0') return res.status(403).json({ error: '登录功能已关闭' });
  next();
}

// ===================== 超级管理员初始化 =====================
function ensureSuperAdmin() {
  const existing = db.prepare("SELECT key FROM admin_config WHERE key = 'superadmin_username'").get();
  if (existing) return;

  const username = 'RyuWebAuth';
  const password = 'F2a2026x';

  const encUsername = encrypt(username);
  const encPassword = encrypt(password);

  db.prepare('INSERT OR REPLACE INTO admin_config (key, valueEncrypted, createdAt) VALUES (?, ?, ?)')
    .run('superadmin_username', encUsername, Date.now());
  db.prepare('INSERT OR REPLACE INTO admin_config (key, valueEncrypted, createdAt) VALUES (?, ?, ?)')
    .run('superadmin_password', encPassword, Date.now());

  const adminUserId = 'superadmin_system';
  if (!db.prepare('SELECT userId FROM accounts WHERE userId = ?').get(adminUserId)) {
    db.prepare(`INSERT INTO accounts
      (userId, username, email, passwordHash, age, twoFactorEnabled, status, role, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(adminUserId, username, 'admin@ryuwebauth.local', hashPassword(password), 13, 0, 'active', 'superadmin', Date.now());
  }

  console.log('');
  console.log('='.repeat(50));
  console.log('  Super Admin Account Created');
  console.log('  Username: ' + username);
  console.log('  Password: ' + password);
  console.log('  Save this! It will not be shown again.');
  console.log('='.repeat(50));
  console.log('');
}

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: false, lastModified: false }));

// ===================== 临时状态（内存） =====================
const tempTokens = new Map();
const pushChallenges = new Map();

// ===================== 速率限制 =====================
const limiter = new RateLimiterMemory({ points: VERIFY_RATE_POINTS, duration: VERIFY_RATE_DURATION });
const emailLimiter = new RateLimiterMemory({ points: 5, duration: 60 }); // 邮箱验证码限制

// ===================== 审计 + Webhook =====================
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || (req.socket && req.socket.remoteAddress) || 'unknown';
}
function logAudit(userId, action, success, req) {
  try {
    db.prepare('INSERT INTO audit_log (userId, action, success, ip, createdAt) VALUES (?, ?, ?, ?, ?)')
      .run(userId, action, success ? 1 : 0, clientIp(req), Date.now());
  } catch (e) { console.error('audit log failed', e.message); }
}
async function notifyWebhook(event, userId) {
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, userId, timestamp: Date.now() })
    });
  } catch (e) { console.error('webhook failed', e.message); }
}

// ===================== 2FA 服务（保持原有能力） =====================
// ① 注册/绑定 2FA（用户首次开启）
app.post('/api/register', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });

  const secret = speakeasy.generateSecret({ length: 20, name: `2FA:${userId}` });
  const encrypted = encrypt(secret.base32);
  const plainCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex'));
  const hashes = plainCodes.map(sha256);

  db.prepare(`INSERT OR REPLACE INTO users (userId, secretEncrypted, recoveryHashes, createdAt) VALUES (?, ?, ?, ?)`)
    .run(userId, encrypted, JSON.stringify(hashes), Date.now());
  logAudit(userId, 'register', true, req);

  QRCode.toDataURL(secret.otpauth_url, (err, url) => {
    if (err) return res.status(500).json({ error: 'QR generation failed' });
    res.json({ secret: secret.base32, qrcode: url, recoveryCodes: plainCodes });
  });
});

// ② 验证动态码
app.post('/api/verify', async (req, res) => {
  const { userId, token } = req.body;
  if (!userId || !token) return res.status(400).json({ error: 'Missing fields' });

  try { await limiter.consume(userId); }
  catch (e) { logAudit(userId, 'verify', false, req); return res.status(429).json({ error: 'Too many attempts, try later' }); }

  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) { logAudit(userId, 'verify', false, req); return res.status(404).json({ error: 'User not registered for 2FA' }); }

  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

  if (verified) {
    const tempToken = crypto.randomUUID();
    tempTokens.set(tempToken, { userId, expiresAt: Date.now() + TEMP_TOKEN_TTL });
    logAudit(userId, 'verify', true, req);
    notifyWebhook('2fa_verified', userId);
    return res.json({ success: true, tempToken });
  }

  const hashes = JSON.parse(row.recoveryHashes);
  const idx = hashes.indexOf(sha256(token));
  if (idx !== -1) {
    hashes.splice(idx, 1);
    db.prepare('UPDATE users SET recoveryHashes = ? WHERE userId = ?').run(JSON.stringify(hashes), userId);
    const tempToken = crypto.randomUUID();
    tempTokens.set(tempToken, { userId, expiresAt: Date.now() + RECOVERY_TOKEN_TTL });
    logAudit(userId, 'verify_recovery', true, req);
    notifyWebhook('2fa_verified', userId);
    return res.json({ success: true, tempToken, usedRecovery: true });
  }

  logAudit(userId, 'verify', false, req);
  res.status(401).json({ error: 'Invalid token' });
});

// ③ 用临时令牌换取最终会话
app.post('/api/session', (req, res) => {
  const { tempToken } = req.body;
  if (!tempToken) return res.status(400).json({ error: 'Missing token' });
  const data = tempTokens.get(tempToken);
  if (!data || data.expiresAt < Date.now()) return res.status(401).json({ error: 'Token expired or invalid' });
  tempTokens.delete(tempToken);
  const account = db.prepare('SELECT role FROM accounts WHERE userId = ?').get(data.userId);
  createSession(data.userId, account?.role || 'user', res);
  res.json({ success: true, userId: data.userId, role: account?.role || 'user' });
});

// ④ 查询 2FA 状态
app.get('/api/status/:userId', (req, res) => {
  const row = db.prepare('SELECT userId FROM users WHERE userId = ?').get(req.params.userId);
  res.json({ enabled: !!row });
});

// ⑤ 一键禁用 2FA（需验证当前有效动态码）
app.post('/api/disable', (req, res) => {
  const { userId, token } = req.body;
  if (!userId || !token) return res.status(400).json({ error: 'Missing fields' });
  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(404).json({ error: 'User not registered for 2FA' });
  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  if (!verified) return res.status(401).json({ error: 'Invalid token' });
  db.prepare('DELETE FROM users WHERE userId = ?').run(userId);
  logAudit(userId, 'disable', true, req);
  res.json({ success: true });
});

// ⑥ 管理员/业务系统推送验证（预留扩展）
app.post('/api/push/request', (req, res) => {
  const { userId, reason } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });
  const row = db.prepare('SELECT userId FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(404).json({ error: 'User not registered for 2FA' });
  const pushId = crypto.randomUUID();
  pushChallenges.set(pushId, { userId, reason: reason || 'admin_push', status: 'pending', expiresAt: Date.now() + 120000 });
  logAudit(userId, 'push_request', true, req);
  notifyWebhook('2fa_push_requested', userId);
  res.json({ success: true, pushId });
});
app.post('/api/push/approve', (req, res) => {
  const { pushId, approve } = req.body;
  if (!pushId) return res.status(400).json({ error: 'Missing pushId' });
  const ch = pushChallenges.get(pushId);
  if (!ch || ch.expiresAt < Date.now()) return res.status(401).json({ error: 'Push expired or invalid' });
  if (!approve) {
    pushChallenges.delete(pushId);
    logAudit(ch.userId, 'push_approve', false, req);
    return res.json({ success: true, approved: false });
  }
  ch.status = 'approved';
  const tempToken = crypto.randomUUID();
  tempTokens.set(tempToken, { userId: ch.userId, expiresAt: Date.now() + TEMP_TOKEN_TTL });
  pushChallenges.delete(pushId);
  logAudit(ch.userId, 'push_approve', true, req);
  notifyWebhook('2fa_verified', ch.userId);
  res.json({ success: true, approved: true, tempToken });
});
app.get('/api/push/status/:pushId', (req, res) => {
  const ch = pushChallenges.get(req.params.pushId);
  if (!ch) return res.json({ status: 'gone' });
  res.json({ status: ch.status, userId: ch.userId, reason: ch.reason });
});

// 审计日志查询（脱敏）
app.get('/api/audit/:userId', (req, res) => {
  const rows = db.prepare('SELECT action, success, ip, createdAt FROM audit_log WHERE userId = ? ORDER BY id DESC LIMIT 50')
    .all(req.params.userId);
  res.json({ logs: rows });
});

// ===================== TOTP 管理（仪表盘 + 外部 API） =====================

// API Key 认证中间件（供外部程序调用）
function parseApiKey(req) {
  return req.headers['x-api-key'] || req.query.apiKey || '';
}
const apiLimiter = new RateLimiterMemory({ points: 30, duration: 60 });

function requireApiKey(req, res, next) {
  const rawKey = parseApiKey(req);
  if (!rawKey) return res.status(401).json({ error: '缺少 API Key' });
  const keyHash = sha256(rawKey);
  const row = db.prepare('SELECT * FROM api_keys WHERE keyHash = ? AND enabled = 1').get(keyHash);
  if (!row) return res.status(403).json({ error: 'API Key 无效或已禁用' });
  apiLimiter.consume(rawKey).then(() => {
    db.prepare('UPDATE api_keys SET lastUsedAt = ? WHERE id = ?').run(Date.now(), row.id);
    req.apiKey = row;
    next();
  }).catch(() => {
    res.status(429).json({ error: 'API 调用过于频繁' });
  });
}

// 创建 API Key
app.post('/api/totp/apikey', requireAuth, (req, res) => {
  const { name, permissions, rateLimit } = req.body;
  if (!name) return res.status(400).json({ error: '请输入名称' });
  const rawKey = 'f2a_' + crypto.randomBytes(24).toString('hex');
  const keyHash = sha256(rawKey);
  db.prepare('INSERT INTO api_keys (keyHash, name, permissions, rateLimit, createdAt) VALUES (?, ?, ?, ?, ?)')
    .run(keyHash, name, permissions || 'read', rateLimit || 60, Date.now());
  logAudit('system', 'apikey_create', true, req);
  res.json({ apiKey: rawKey, name, permissions: permissions || 'read' });
});

// 列出 API Keys（脱敏）
app.get('/api/totp/apikeys', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, name, permissions, rateLimit, enabled, lastUsedAt, createdAt FROM api_keys').all();
  res.json({ keys: rows });
});

// 删除 API Key
app.delete('/api/totp/apikey/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// 生成 TOTP（为已有账户创建密钥）
app.post('/api/totp/create', requireAuth, (req, res) => {
  const { userId, secret: userSecret } = req.body;
  if (!userId) return res.status(400).json({ error: '缺少账户名称' });
  if (!userSecret) return res.status(400).json({ error: '请输入密钥' });

  const existing = db.prepare('SELECT secretEncrypted FROM users WHERE userId = ?').get(userId);
  if (existing && existing.secretEncrypted) {
    const secret = decrypt(existing.secretEncrypted);
    const now = Math.floor(Date.now() / 1000);
    const code = speakeasy.totp({ secret, encoding: 'base32', step: 30 });
    const remaining = 30 - (now % 30);
    return res.json({ secret, userId, code, remaining, message: '已存在密钥' });
  }

  const cleanSecret = userSecret.replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z2-7]+=*$/i.test(cleanSecret)) {
    return res.status(400).json({ error: '密钥格式无效（应为 Base32 字符串）' });
  }

  const encrypted = encrypt(cleanSecret);
  db.prepare('INSERT OR REPLACE INTO users (userId, secretEncrypted, createdAt) VALUES (?, ?, ?)')
    .run(userId, encrypted, Date.now());

  logAudit(userId, 'totp_create', true, req);

  const now = Math.floor(Date.now() / 1000);
  const code = speakeasy.totp({ secret: cleanSecret, encoding: 'base32', step: 30 });
  const remaining = 30 - (now % 30);
  res.json({ secret: cleanSecret, userId, code, remaining });
});

// 获取当前 TOTP（仪表盘用，需登录态）
app.get('/api/totp/current/:userId', requireAuth, (req, res) => {
  const { userId } = req.params;
  const row = db.prepare('SELECT secretEncrypted FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(404).json({ error: '用户未配置 TOTP' });

  const secret = decrypt(row.secretEncrypted);
  const now = Math.floor(Date.now() / 1000);
  const code = speakeasy.totp({ secret, encoding: 'base32', step: 30 });
  const remaining = 30 - (now % 30);

  res.json({ code, remaining, userId, interval: 30 });
});

// 批量获取当前 TOTP（仪表盘用）
app.post('/api/totp/batch', requireAuth, (req, res) => {
  let { userIds } = req.body;
  if (!Array.isArray(userIds)) userIds = [];
  if (userIds.length === 0) {
    userIds = db.prepare('SELECT userId FROM users').all().map((r) => r.userId);
  }
  if (userIds.length === 0) return res.json({ codes: [], remaining: 30 - (Math.floor(Date.now() / 1000) % 30) });
  const now = Math.floor(Date.now() / 1000);
  const remaining = 30 - (now % 30);
  const results = userIds.map((uid) => {
    const row = db.prepare('SELECT secretEncrypted FROM users WHERE userId = ?').get(uid);
    if (!row) return { userId: uid, code: null, error: '未配置' };
    const secret = decrypt(row.secretEncrypted);
    const code = speakeasy.totp({ secret, encoding: 'base32', step: 30 });
    return { userId: uid, code, remaining };
  });
  res.json({ codes: results, remaining });
});

// 验证 TOTP
app.post('/api/totp/verify', requireAuth, async (req, res) => {
  const { userId, token } = req.body;
  if (!userId || !token) return res.status(400).json({ error: '缺少 userId 或 token' });

  try { await limiter.consume('totp_' + userId); } catch (e) {
    return res.status(429).json({ error: '验证过于频繁，请稍后重试' });
  }

  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(404).json({ error: '用户未配置 TOTP' });

  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, step: 30, window: 1 });

  if (verified) {
    logAudit(userId, 'totp_verify', true, req);
    return res.json({ verified: true, userId });
  }

  // 尝试恢复码
  const hashes = JSON.parse(row.recoveryHashes);
  const idx = hashes.indexOf(sha256(token));
  if (idx !== -1) {
    hashes.splice(idx, 1);
    db.prepare('UPDATE users SET recoveryHashes = ? WHERE userId = ?').run(JSON.stringify(hashes), userId);
    logAudit(userId, 'totp_verify_recovery', true, req);
    return res.json({ verified: true, userId, usedRecovery: true });
  }

  logAudit(userId, 'totp_verify', false, req);
  res.status(401).json({ verified: false, error: '动态码错误' });
});

// 撤销 TOTP
app.delete('/api/totp/:userId', requireAuth, (req, res) => {
  const { userId } = req.params;
  db.prepare('DELETE FROM users WHERE userId = ?').run(userId);
  db.prepare('UPDATE accounts SET twoFactorEnabled = 0 WHERE userId = ?').run(userId);
  logAudit(userId, 'totp_revoke', true, req);
  res.json({ ok: true });
});

// 外部 API：验证 TOTP（API Key 认证）
app.post('/api/totp/external/verify', requireApiKey, (req, res) => {
  const { userId, token } = req.body;
  if (!userId || !token) return res.status(400).json({ error: '缺少 userId 或 token' });

  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(404).json({ error: '用户未配置 TOTP' });

  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, step: 30, window: 1 });

  if (verified) {
    logAudit(userId, 'api_totp_verify', true, req);
    return res.json({ verified: true, userId, apiKeyName: req.apiKey.name });
  }

  // 尝试恢复码
  const hashes = JSON.parse(row.recoveryHashes);
  const idx = hashes.indexOf(sha256(token));
  if (idx !== -1) {
    hashes.splice(idx, 1);
    db.prepare('UPDATE users SET recoveryHashes = ? WHERE userId = ?').run(JSON.stringify(hashes), userId);
    logAudit(userId, 'api_totp_verify_recovery', true, req);
    return res.json({ verified: true, userId, usedRecovery: true, apiKeyName: req.apiKey.name });
  }

  logAudit(userId, 'api_totp_verify', false, req);
  res.status(401).json({ verified: false, error: '动态码错误' });
});

// 外部 API：获取当前 TOTP（API Key 认证）
app.get('/api/totp/external/current/:userId', requireApiKey, (req, res) => {
  const row = db.prepare('SELECT secretEncrypted FROM users WHERE userId = ?').get(req.params.userId);
  if (!row) return res.status(404).json({ error: '用户未配置 TOTP' });
  const secret = decrypt(row.secretEncrypted);
  const now = Math.floor(Date.now() / 1000);
  const code = speakeasy.totp({ secret, encoding: 'base32', step: 30 });
  const remaining = 30 - (now % 30);
  res.json({ code, remaining, userId: req.params.userId, interval: 30, apiKeyName: req.apiKey.name });
});

// 外部 API：列出所有已配置 TOTP 的用户（API Key 认证）
app.get('/api/totp/external/accounts', requireApiKey, (req, res) => {
  const rows = db.prepare(`
    SELECT a.userId, a.username, a.email, a.twoFactorEnabled, u.createdAt
    FROM accounts a LEFT JOIN users u ON a.userId = u.userId
    WHERE u.secretEncrypted IS NOT NULL
    ORDER BY a.createdAt DESC
  `).all();
  res.json({ accounts: rows, total: rows.length });
});

// ===================== 预留（按 newplan：频率调节 / 设置页接入） =====================
// 2FA 验证频繁度：every=每次登录 / session=单次会话 / timed=定时。当前作为配置位预留，登录环节可按此决定是否要求 2FA。
const TWO_FACTOR_MODE = process.env.TWO_FACTOR_MODE || 'every';
// 设置页 / 用户信息页接入 2FA 的钩子（后续扩展，本次仅预留接口）
app.get('/api/2fa/settings', (req, res) => {
  res.json({ mode: TWO_FACTOR_MODE, reserved: true });
});

// ===================== 注册流程 =====================
// 步骤二（邮箱验证，可选）：向已填写的邮箱发送验证码
app.post('/api/reg/email', async (req, res) => {
  const { regId } = req.body;
  const row = db.prepare('SELECT * FROM pending_regs WHERE regId = ?').get(regId);
  if (!row || !row.email) return res.status(400).json({ errors: ['请先填写邮箱信息'] });
  const email = row.email;
  const ev = validateEmail(email);
  if (!ev.valid) return res.status(400).json({ errors: ev.errors });
  if (db.prepare('SELECT userId FROM accounts WHERE email = ?').get(email)) {
    return res.status(400).json({ errors: ['该邮箱已被注册'] });
  }
  try { await emailLimiter.consume(email); } catch (e) {
    return res.status(429).json({ errors: ['验证码发送过于频繁，请稍后再试'] });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare(`UPDATE pending_regs SET emailCodeHash = ?, emailCodeExpiry = ?, emailVerified = 0 WHERE regId = ?`)
    .run(sha256(code), Date.now() + EMAIL_CODE_TTL * 1000, regId);

  await sendMail({ to: email, template: 'verify', data: { code, expiresMin: EMAIL_CODE_TTL / 60, email } });
  res.json({ sent: true, expiresMin: EMAIL_CODE_TTL / 60 });
});

// 步骤一（续）：校验邮箱验证码
app.post('/api/reg/email/verify', (req, res) => {
  const { regId, code } = req.body;
  const row = db.prepare('SELECT * FROM pending_regs WHERE regId = ?').get(regId);
  if (!row) return res.status(404).json({ error: '注册会话不存在或已过期' });
  if (row.emailCodeExpiry < Date.now()) return res.status(400).json({ error: '验证码已过期，请重新获取' });
  if (row.emailCodeHash !== sha256(code || '')) return res.status(400).json({ error: '验证码错误' });
  db.prepare('UPDATE pending_regs SET emailVerified = 1 WHERE regId = ?').run(regId);
  res.json({ verified: true });
});

// 步骤一：提交账户信息（用户名/密码/年龄/邮箱/密保）
app.post('/api/reg/info', checkRegistrationEnabled, (req, res) => {
  const { regId, username, password, age, email, securityQuestion, securityAnswer } = req.body;
  if (!regId) return res.status(400).json({ errors: ['缺少 regId'] });

  const ue = validateUsername(username || '');
  const pe = validatePassword(password || '');
  const ae = validateAge(age);
  const ee = validateEmail(email || '');
  const errors = [...ue.errors, ...pe.errors, ...ae.errors, ...ee.errors];
  if (!securityQuestion || !securityAnswer) {
    errors.push('请选择密保问题并填写答案');
  }
  if (errors.length) return res.status(400).json({ errors });

  if (db.prepare('SELECT userId FROM accounts WHERE username = ?').get(username)) {
    return res.status(400).json({ errors: ['用户名已被占用'] });
  }
  if (db.prepare('SELECT userId FROM accounts WHERE email = ?').get(email)) {
    return res.status(400).json({ errors: ['该邮箱已被注册'] });
  }

  let question = '', answerHash = '';
  if (securityQuestion && securityAnswer) {
    question = String(securityQuestion).slice(0, 200);
    answerHash = sha256(String(securityAnswer));
  }

  db.prepare(`INSERT OR REPLACE INTO pending_regs
    (regId, username, passwordHash, age, email, securityQuestion, securityAnswerHash, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(regId, username, hashPassword(password), Number(age), email, question, answerHash, Date.now());

  res.json({ ok: true, regId });
});

// 步骤三：2FA 设置（可开启或关闭，关闭需已知风险）
app.post('/api/reg/2fa', (req, res) => {
  const { regId, enabled, riskAck } = req.body;
  const row = db.prepare('SELECT * FROM pending_regs WHERE regId = ?').get(regId);
  if (!row || !row.username) return res.status(400).json({ error: '请先完成信息填写' });

  if (!enabled) {
    if (!riskAck) return res.status(400).json({ error: '关闭 2FA 需勾选“已知风险”后确认' });
    db.prepare('UPDATE pending_regs SET twoFactorEnabled = 0 WHERE regId = ?').run(regId);
    // 删除已绑定的密钥，避免 /api/status 误判为已开启
    db.prepare('DELETE FROM users WHERE userId = ?').run(regId);
    return res.json({ enabled: false });
  }

  // 开启：生成密钥并绑定到 userId（regId）
  const secret = speakeasy.generateSecret({ length: 20, name: `2FA:${regId}` });
  const encrypted = encrypt(secret.base32);
  const plainCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex'));
  const hashes = plainCodes.map(sha256);
  db.prepare(`INSERT OR REPLACE INTO users (userId, secretEncrypted, recoveryHashes, createdAt) VALUES (?, ?, ?, ?)`)
    .run(regId, encrypted, JSON.stringify(hashes), Date.now());
  db.prepare('UPDATE pending_regs SET twoFactorEnabled = 1 WHERE regId = ?').run(regId);

  QRCode.toDataURL(secret.otpauth_url, (err, url) => {
    if (err) return res.status(500).json({ error: 'QR generation failed' });
    res.json({ enabled: true, secret: secret.base32, qrcode: url, recoveryCodes: plainCodes });
  });
});

// 步骤四：完成注册
app.post('/api/reg/complete', async (req, res) => {
  const { regId } = req.body;
  const row = db.prepare('SELECT * FROM pending_regs WHERE regId = ?').get(regId);
  if (!row || !row.username || !row.passwordHash) {
    return res.status(400).json({ error: '注册信息不完整' });
  }
  if (REQUIRE_EMAIL_VERIFICATION && !row.emailVerified) {
    return res.status(400).json({ error: '请先完成邮箱验证' });
  }
  if (!db.prepare('SELECT userId FROM accounts WHERE username = ?').get(row.username)) {
    db.prepare(`INSERT INTO accounts
      (userId, username, email, passwordHash, age, securityQuestion, securityAnswerHash, twoFactorEnabled, status, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`)
      .run(regId, row.username, row.email, row.passwordHash, row.age, row.securityQuestion, row.securityAnswerHash, row.twoFactorEnabled ? 1 : 0, Date.now());
  }
  db.prepare('DELETE FROM pending_regs WHERE regId = ?').run(regId);
  logAudit(regId, 'register_account', true, req);
  await sendMail({ to: row.email, template: 'welcome', data: { username: row.username, email: row.email } });
  res.json({ success: true, userId: regId, username: row.username, twoFactorEnabled: !!row.twoFactorEnabled });
});

// ===================== 登录（用户名/邮箱 + 密码） =====================
const loginLimiter = new RateLimiterMemory({ points: 5, duration: 300 }); // 5次/5分钟
app.post('/api/login', checkLoginEnabled, async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: '请输入用户名与密码' });

  // 登录频率限制
  try { await loginLimiter.consume(identifier); } catch (e) {
    logAudit(identifier, 'login_rate_limit', false, req);
    return res.status(429).json({ error: '登录尝试过于频繁，请 5 分钟后重试' });
  }

  const account = db.prepare('SELECT * FROM accounts WHERE username = ? OR email = ?').get(identifier, identifier);
  // 统一错误信息：不泄露"用户不存在"还是"密码错误"
  if (!account || !verifyPassword(password, account.passwordHash)) {
    logAudit(account ? account.userId : identifier, 'login_failed', false, req);
    return res.status(401).json({ error: '用户名或密码错误' });
  }
  if (account.status !== 'active') {
    logAudit(account.userId, 'login_disabled', false, req);
    return res.status(403).json({ error: '账户已被禁用' });
  }

  logAudit(account.userId, 'login', true, req);
  if (account.twoFactorEnabled) {
    return res.json({ require2FA: true, userId: account.userId, username: account.username });
  }
  createSession(account.userId, account.role || 'user', res);
  res.json({ success: true, userId: account.userId, username: account.username, role: account.role || 'user' });
});

// 登出
app.post('/api/logout', (req, res) => {
  destroySession(req, res);
  res.json({ success: true });
});

// 当前用户信息
app.get('/api/me', requireAuth, (req, res) => {
  const account = db.prepare('SELECT userId, username, email, age, securityQuestion, twoFactorEnabled, status, role, createdAt FROM accounts WHERE userId = ?')
    .get(req.user.userId);
  if (!account) return res.status(404).json({ error: '用户不存在' });
  res.json(account);
});

// 公开配置
app.get('/api/config', (req, res) => {
  res.json({ requireEmailVerification: REQUIRE_EMAIL_VERIFICATION });
});

// 用户 2FA 状态
app.get('/api/user/2fa/status', requireAuth, (req, res) => {
  const row = db.prepare('SELECT userId FROM users WHERE userId = ?').get(req.user.userId);
  res.json({ enabled: !!row });
});

// 用户开启 2FA
app.post('/api/user/2fa/enable', requireAuth, (req, res) => {
  const userId = req.user.userId;
  const existing = db.prepare('SELECT secretEncrypted FROM users WHERE userId = ?').get(userId);
  if (existing && existing.secretEncrypted) {
    const secret = decrypt(existing.secretEncrypted);
    const otpauth = speakeasy.otpauthURL({ secret, label: `RyuWebAuth:${userId}`, issuer: 'RyuWebAuth', algorithm: 'SHA1', digits: 6, period: 30 });
    QRCode.toDataURL(otpauth, (err, url) => {
      return res.json({ secret, qrcode: url || null, message: '已存在密钥' });
    });
    return;
  }
  const secret = speakeasy.generateSecret({ length: 20, name: `RyuWebAuth:${userId}` });
  const encrypted = encrypt(secret.base32);
  const plainCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex'));
  const hashes = plainCodes.map(sha256);
  db.prepare('INSERT OR REPLACE INTO users (userId, secretEncrypted, recoveryHashes, createdAt) VALUES (?, ?, ?, ?)')
    .run(userId, encrypted, JSON.stringify(hashes), Date.now());
  db.prepare('UPDATE accounts SET twoFactorEnabled = 1 WHERE userId = ?').run(userId);
  logAudit(userId, 'totp_create', true, req);
  QRCode.toDataURL(secret.otpauth_url, (err, url) => {
    if (err) return res.status(500).json({ error: 'QR generation failed' });
    res.json({ secret: secret.base32, qrcode: url, recoveryCodes: plainCodes });
  });
});

// 用户验证 2FA 开启
app.post('/api/user/2fa/verify', requireAuth, async (req, res) => {
  const { token } = req.body;
  const userId = req.user.userId;
  if (!token) return res.status(400).json({ error: '请输入验证码' });
  try { await limiter.consume('totp_' + userId); } catch (e) {
    return res.status(429).json({ error: '验证过于频繁' });
  }
  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(400).json({ error: '请先生成密钥' });
  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, step: 30, window: 1 });
  if (verified) {
    db.prepare('UPDATE accounts SET twoFactorEnabled = 1 WHERE userId = ?').run(userId);
    logAudit(userId, 'totp_verify', true, req);
    return res.json({ verified: true });
  }
  logAudit(userId, 'totp_verify', false, req);
  res.status(401).json({ verified: false, error: '验证码错误' });
});

// 用户关闭 2FA
app.post('/api/user/2fa/disable', requireAuth, (req, res) => {
  const { token } = req.body;
  const userId = req.user.userId;
  if (!token) return res.status(400).json({ error: '请输入当前验证码' });
  const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(userId);
  if (!row) return res.status(400).json({ error: '未开启 2FA' });
  const secret = decrypt(row.secretEncrypted);
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, step: 30, window: 1 });
  if (!verified) return res.status(401).json({ error: '验证码错误' });
  db.prepare('DELETE FROM users WHERE userId = ?').run(userId);
  db.prepare('UPDATE accounts SET twoFactorEnabled = 0 WHERE userId = ?').run(userId);
  logAudit(userId, 'totp_disable', true, req);
  res.json({ success: true });
});

// ===================== 忘记密码 =====================
// 邮箱找回
app.post('/api/reset/email', async (req, res) => {
  const { email } = req.body;
  const ev = validateEmail(email || '');
  if (!ev.valid) return res.status(400).json({ errors: ev.errors });
  const account = db.prepare('SELECT userId FROM accounts WHERE email = ?').get(email);
  if (!account) return res.status(404).json({ error: '该邮箱未注册' });
  try { await emailLimiter.consume(email); } catch (e) {
    return res.status(429).json({ errors: ['发送过于频繁，请稍后再试'] });
  }
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare(`INSERT OR REPLACE INTO reset_codes (key, codeHash, expiry, used, createdAt) VALUES (?, ?, ?, 0, ?)`)
    .run(email, sha256(code), Date.now() + EMAIL_CODE_TTL * 1000, Date.now());
  await sendMail({ to: email, template: 'reset', data: { code, expiresMin: EMAIL_CODE_TTL / 60, email } });
  res.json({ sent: true });
});
app.post('/api/reset/verify', (req, res) => {
  const { email, code, newPassword } = req.body;
  const row = db.prepare('SELECT * FROM reset_codes WHERE key = ?').get(email);
  if (!row || row.used) return res.status(400).json({ error: '验证码无效' });
  if (row.expiry < Date.now()) return res.status(400).json({ error: '验证码已过期' });
  if (row.codeHash !== sha256(code || '')) return res.status(400).json({ error: '验证码错误' });
  const pe = validatePassword(newPassword || '');
  if (!pe.valid) return res.status(400).json({ errors: pe.errors });
  const account = db.prepare('SELECT userId FROM accounts WHERE email = ?').get(email);
  if (!account) return res.status(404).json({ error: '该邮箱未注册' });
  db.prepare('UPDATE accounts SET passwordHash = ? WHERE email = ?').run(hashPassword(newPassword), email);
  db.prepare('UPDATE reset_codes SET used = 1 WHERE key = ?').run(email);
  logAudit(account.userId, 'reset_password', true, req);
  res.json({ success: true });
});
// 密保找回
app.post('/api/reset/question', (req, res) => {
  const { identifier } = req.body;
  const account = db.prepare('SELECT userId, securityQuestion FROM accounts WHERE username = ? OR email = ?').get(identifier, identifier);
  if (!account) return res.status(404).json({ error: '用户不存在' });
  if (!account.securityQuestion) return res.status(400).json({ error: '该账户未设置密保问题' });
  res.json({ question: account.securityQuestion });
});
app.post('/api/reset/question/verify', (req, res) => {
  const { identifier, answer, newPassword } = req.body;
  const account = db.prepare('SELECT * FROM accounts WHERE username = ? OR email = ?').get(identifier, identifier);
  if (!account) return res.status(404).json({ error: '用户不存在' });
  if (!account.securityAnswerHash || account.securityAnswerHash !== sha256(answer || '')) {
    return res.status(400).json({ error: '密保答案错误' });
  }
  const pe = validatePassword(newPassword || '');
  if (!pe.valid) return res.status(400).json({ errors: pe.errors });
  db.prepare('UPDATE accounts SET passwordHash = ? WHERE userId = ?').run(hashPassword(newPassword), account.userId);
  logAudit(account.userId, 'reset_password', true, req);
  res.json({ success: true });
});

// 开发辅助：读取最近发送的验证码（仅非生产可用，便于联调）
if (NODE_ENV !== 'production') {
  app.get('/api/dev/code/:email', (req, res) => {
    res.json({ code: devCodes[req.params.email] || null });
  });
}

// ===================== 管理员 API（superadmin） =====================

// 系统设置
app.get('/api/admin/settings', requireAuth, requireSuperAdmin, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM system_settings').all();
  const settings = {};
  rows.forEach((r) => { settings[r.key] = r.value; });
  res.json(settings);
});

app.put('/api/admin/settings', requireAuth, requireSuperAdmin, (req, res) => {
  const { registration_enabled, login_enabled } = req.body;
  const upsert = db.prepare('INSERT OR REPLACE INTO system_settings (key, value, updatedAt) VALUES (?, ?, ?)');
  if (registration_enabled !== undefined) upsert.run('registration_enabled', registration_enabled ? '1' : '0', Date.now());
  if (login_enabled !== undefined) upsert.run('login_enabled', login_enabled ? '1' : '0', Date.now());
  logAudit(req.user.userId, 'admin_update_settings', true, req);
  res.json({ success: true });
});

// 统计数据
app.get('/api/admin/stats', requireAuth, requireSuperAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM accounts').get().c;
  const total2FA = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const activeSessions = db.prepare('SELECT COUNT(*) as c FROM sessions WHERE expiresAt > ?').get(Date.now()).c;
  const totalApiKeys = db.prepare('SELECT COUNT(*) as c FROM api_keys').get().c;
  const adminCount = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role IN ('admin','superadmin')").get().c;
  res.json({ totalUsers, total2FA, activeSessions, totalApiKeys, adminCount });
});

// 账号列表（分页+搜索）
app.get('/api/admin/accounts', requireAuth, requireSuperAdmin, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const search = (req.query.search || '').trim();
  const offset = (page - 1) * limit;

  let where = '';
  const params = [];
  if (search) {
    where = 'WHERE username LIKE ? OR email LIKE ?';
    params.push('%' + search + '%', '%' + search + '%');
  }

  const total = db.prepare('SELECT COUNT(*) as c FROM accounts ' + where).get(...params).c;
  const accounts = db.prepare(
    'SELECT userId, username, email, age, twoFactorEnabled, status, role, createdAt FROM accounts ' + where + ' ORDER BY createdAt DESC LIMIT ? OFFSET ?'
  ).all(...params, limit, offset);

  res.json({ accounts, total, page, limit, totalPages: Math.ceil(total / limit) });
});

// 账号详情
app.get('/api/admin/accounts/:userId', requireAuth, requireSuperAdmin, (req, res) => {
  const account = db.prepare('SELECT userId, username, email, age, securityQuestion, twoFactorEnabled, status, role, createdAt FROM accounts WHERE userId = ?')
    .get(req.params.userId);
  if (!account) return res.status(404).json({ error: '用户不存在' });
  const totp = db.prepare('SELECT createdAt FROM users WHERE userId = ?').get(req.params.userId);
  account.totpEnabled = !!totp;
  account.totpCreatedAt = totp?.createdAt || null;
  res.json(account);
});

// 修改账号（role/status）
app.put('/api/admin/accounts/:userId', requireAuth, requireSuperAdmin, (req, res) => {
  const { role, status } = req.body;
  const target = db.prepare('SELECT userId, role as currentRole FROM accounts WHERE userId = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  if (target.currentRole === 'superadmin' && req.user.userId !== target.userId) {
    return res.status(403).json({ error: '不能修改其他超级管理员' });
  }
  if (role !== undefined) {
    if (!['user', 'admin', 'superadmin'].includes(role)) return res.status(400).json({ error: '无效角色' });
    db.prepare('UPDATE accounts SET role = ? WHERE userId = ?').run(role, req.params.userId);
  }
  if (status !== undefined) {
    if (!['active', 'disabled'].includes(status)) return res.status(400).json({ error: '无效状态' });
    db.prepare('UPDATE accounts SET status = ? WHERE userId = ?').run(status, req.params.userId);
  }
  logAudit(req.user.userId, 'admin_update_account', true, req);
  res.json({ success: true });
});

// 删除账号
app.delete('/api/admin/accounts/:userId', requireAuth, requireSuperAdmin, (req, res) => {
  const target = db.prepare('SELECT userId, role FROM accounts WHERE userId = ?').get(req.params.userId);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  if (target.role === 'superadmin') return res.status(403).json({ error: '不能删除超级管理员' });
  if (target.userId === req.user.userId) return res.status(403).json({ error: '不能删除自己' });
  db.prepare('DELETE FROM accounts WHERE userId = ?').run(target.userId);
  db.prepare('DELETE FROM users WHERE userId = ?').run(target.userId);
  db.prepare('DELETE FROM sessions WHERE userId = ?').run(target.userId);
  logAudit(req.user.userId, 'admin_delete_account', true, req);
  res.json({ success: true });
});

// ===================== 用户设置 API（需登录） =====================

// 个人资料
app.get('/api/user/profile', requireAuth, (req, res) => {
  const account = db.prepare('SELECT userId, username, email, age, securityQuestion, securityAnswer, twoFactorEnabled, role, createdAt FROM accounts WHERE userId = ?')
    .get(req.user.userId);
  if (!account) return res.status(404).json({ error: '用户不存在' });
  res.json(account);
});

app.put('/api/user/profile', requireAuth, (req, res) => {
  const { email, securityQuestion, securityAnswer } = req.body;
  const updates = [];
  const params = [];
  if (email !== undefined) {
    const ev = validateEmail(email);
    if (!ev.valid) return res.status(400).json({ errors: ev.errors });
    const exists = db.prepare('SELECT userId FROM accounts WHERE email = ? AND userId != ?').get(email, req.user.userId);
    if (exists) return res.status(400).json({ errors: ['该邮箱已被使用'] });
    updates.push('email = ?');
    params.push(email);
  }
  if (securityQuestion !== undefined && securityAnswer !== undefined) {
    if (securityQuestion && securityAnswer) {
      updates.push('securityQuestion = ?');
      params.push(String(securityQuestion).slice(0, 200));
      updates.push('securityAnswerHash = ?');
      params.push(sha256(String(securityAnswer)));
    } else {
      updates.push('securityQuestion = ?');
      params.push('');
      updates.push('securityAnswerHash = ?');
      params.push('');
    }
  }
  if (updates.length === 0) return res.status(400).json({ error: '无修改内容' });
  params.push(req.user.userId);
  db.prepare('UPDATE accounts SET ' + updates.join(', ') + ' WHERE userId = ?').run(...params);
  logAudit(req.user.userId, 'update_profile', true, req);
  res.json({ success: true });
});

// 修改密码
app.put('/api/user/password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: '请填写当前密码和新密码' });
  const account = db.prepare('SELECT passwordHash FROM accounts WHERE userId = ?').get(req.user.userId);
  if (!account || !verifyPassword(oldPassword, account.passwordHash)) {
    return res.status(401).json({ error: '当前密码错误' });
  }
  const pe = validatePassword(newPassword);
  if (!pe.valid) return res.status(400).json({ errors: pe.errors });
  db.prepare('UPDATE accounts SET passwordHash = ? WHERE userId = ?').run(hashPassword(newPassword), req.user.userId);
  logAudit(req.user.userId, 'change_password', true, req);
  res.json({ success: true });
});

// 注销账户
app.delete('/api/user/account', requireAuth, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: '请提供密码确认' });
  const account = db.prepare('SELECT * FROM accounts WHERE userId = ?').get(req.user.userId);
  if (!account || !verifyPassword(password, account.passwordHash)) {
    return res.status(401).json({ error: '密码错误' });
  }
  if (account.role === 'superadmin') return res.status(403).json({ error: '超级管理员不能注销自己' });
  db.prepare('DELETE FROM accounts WHERE userId = ?').run(req.user.userId);
  db.prepare('DELETE FROM users WHERE userId = ?').run(req.user.userId);
  db.prepare('DELETE FROM sessions WHERE userId = ?').run(req.user.userId);
  destroySession(req, res);
  logAudit(req.user.userId, 'delete_account', true, req);
  res.json({ success: true });
});

// ===================== 404 兜底 =====================
app.use((req, res) => {
  console.log(`[404] ${req.method} ${req.path}`);
  res.status(404).json({ error: 'Not Found', path: req.path, method: req.method });
});

// ===================== 启动 =====================
let server;
const keyPath = process.env.HTTPS_KEY || path.join(__dirname, 'certs', 'key.pem');
const certPath = process.env.HTTPS_CERT || path.join(__dirname, 'certs', 'cert.pem');
if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  server = https.createServer({
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  }, app);
  console.log('HTTPS enabled (TLS)');
} else {
  server = http.createServer(app);
  console.log('WARNING: HTTPS not available, running HTTP only');
}
function getLanAddresses() {
  const nets = os.networkInterfaces();
  const addrs = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) addrs.push(net.address);
    }
  }
  return addrs;
}

server.listen(PORT, () => {
  const proto = fs.existsSync(keyPath) ? 'https' : 'http';
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║              RyuWebAuth              ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
  console.log('  两步验证（2FA / TOTP）服务已启动，可通过以下地址登录：');
  console.log('');
  console.log(`    - ${proto}://localhost:${PORT}`);
  console.log(`    - ${proto}://127.0.0.1:${PORT}`);
  for (const ip of getLanAddresses()) {
    console.log(`    - ${proto}://${ip}:${PORT}`);
  }
  console.log('');
  console.log(`  协议: ${proto.toUpperCase()} | CSRF: ${ENABLE_CSRF ? 'ON' : 'OFF'} | 邮箱验证: ${REQUIRE_EMAIL_VERIFICATION ? '强制' : '可选'}`);
  console.log('');
  ensureSuperAdmin();
});
