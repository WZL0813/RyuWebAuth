// ====================================================================
//  RyuWebAuth — Web 认证服务 (Node.js 原生 http 模块)
//  注册 / 登录 / 2FA TOTP 双因素验证 / 用户管理
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

// ==================== JSON 数据持久化 ====================
function readJSON(filename) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, filename), 'utf8')); }
  catch { return null; }
}

function writeJSON(filename, data) {
  fs.writeFileSync(path.join(DATA_DIR, filename), JSON.stringify(data, null, 2), 'utf8');
}

// ==================== 密码哈希 (scrypt) ====================
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  return hashPassword(password, salt) === stored;
}

// ==================== TOTP 实现 (RFC 6238) ====================
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

function generateTOTP(secret, timeStep = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / timeStep);
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

function generateTOTPSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  for (let i = 0; i < 32; i++) secret += alphabet[Math.floor(Math.random() * alphabet.length)];
  return secret;
}

function getTOTPUri(secret, label, issuer = 'RyuWebAuth') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
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
  const sessionId = crypto.randomUUID();
  sessions[sessionId] = { username, role, expiresAt: Date.now() + (ttl || SESSION_TTL) };
  saveSessions(sessions);
  return sessionId;
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
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < 8; i++) password += chars[Math.floor(Math.random() * chars.length)];

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

// ==================== 请求解析 ====================
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
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
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    // SPA fallback: serve index.html
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  try {
    const ext = path.extname(filePath);
    const contentType = MIME[ext] || 'application/octet-stream';
    const content = fs.readFileSync(filePath);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store'
    });
    res.end(content);
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  }
}

// ==================== HTTP 服务器 ====================
const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const reqUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = reqUrl.pathname;

  // ==================== API 路由 ====================
  if (pathname.startsWith('/api/')) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    log('REQ', `${req.method} ${pathname}`, 'blue');

    try {
      // ---------- 登录 ----------
      if (pathname === '/api/login' && req.method === 'POST') {
        const body = await parseBody(req);
        const { username, password, totpCode } = body;

        if (!username || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请输入用户名和密码' })); log('AUTH', 'Login failed: missing username or password', 'yellow'); return;
        }

        const users = loadUsers();
        const user = users[username];
        if (!user || !verifyPassword(password, user.passwordHash)) {
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

      // 2FA 检查
      if (user.twoFactorEnabled) {
          if (!totpCode) {
            res.writeHead(200); res.end(JSON.stringify({ need2FA: true, username })); log('AUTH', `Login: ${username} requires 2FA verification`, 'yellow'); return;
          }
          if (generateTOTP(user.twoFactorSecret) !== totpCode) {
            res.writeHead(401); res.end(JSON.stringify({ error: '2FA验证码错误' })); log('AUTH', `Login failed: ${username} (invalid 2FA code)`, 'yellow'); return;
          }
        }

        const rememberMe = body.rememberMe === true;
        const sessionTtl = rememberMe ? SESSION_TTL_LONG : SESSION_TTL;
        const sessionId = createSession(username, user.role, sessionTtl);
        res.setHeader('Set-Cookie', `session_id=${sessionId}; HttpOnly; Path=/; Max-Age=${sessionTtl / 1000}; SameSite=Lax`);
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
        const settings = loadSettings();
        if (!settings.registrationEnabled) {
          res.writeHead(403); res.end(JSON.stringify({ error: '注册功能已关闭，请联系管理员' })); log('REG ', 'Registration attempt blocked: registration disabled', 'yellow'); return;
        }

        const body = await parseBody(req);
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
        if (password.length < 6) {
          res.writeHead(400); res.end(JSON.stringify({ error: '密码长度不能少于6位' })); return;
        }
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

        const sessionId = createSession(username, 'user');
        res.setHeader('Set-Cookie', `session_id=${sessionId}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax`);
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, username, role: 'user', forcePasswordChange: false, twoFactorEnabled: false }));
        log('REG ', `Registration success: ${username}`, 'green');
        return;
      }

      // ---------- 退出登录 ----------
      if (pathname === '/api/logout' && req.method === 'POST') {
        const cookies = parseCookies(req);
        destroySession(cookies.session_id);
        res.setHeader('Set-Cookie', 'session_id=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('AUTH', 'User logged out', 'green');
        return;
      }

      // ---------- 获取当前会话 ----------
      if (pathname === '/api/session' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(200); res.end(JSON.stringify({ loggedIn: false })); return;
        }
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        const body = await parseBody(req);
        const { currentPassword, newPassword } = body;
        const users = loadUsers();
        const user = users[session.username];

        if (!verifyPassword(currentPassword, user.passwordHash)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '当前密码错误' })); return;
        }
        if (newPassword.length < 6) {
          res.writeHead(400); res.end(JSON.stringify({ error: '新密码长度不能少于6位' })); return;
        }

        user.passwordHash = hashPassword(newPassword);
        user.forcePasswordChange = false;
        saveUsers(users);
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('AUTH', `Password changed: ${session.username}`, 'green');
        return;
      }

      // ---------- 管理员：用户列表 ----------
      if (pathname === '/api/admin/users' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
        const body = await parseBody(req);
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
        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' set role of '${username}' to '${role}'`, 'green');
        return;
      }

      // ---------- 管理员：获取设置 ----------
      if (pathname === '/api/admin/settings' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || (session.role !== 'superadmin' && session.role !== 'admin')) {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要管理员权限' })); return;
        }
        res.writeHead(200); res.end(JSON.stringify({ settings: loadSettings() })); return;
      }

      // ---------- 管理员：更新设置 ----------
      if (pathname === '/api/admin/settings' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || (session.role !== 'superadmin' && session.role !== 'admin')) {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要管理员权限' })); return;
        }
        const body = await parseBody(req);
        const settings = loadSettings();
        if (typeof body.registrationEnabled === 'boolean') {
          settings.registrationEnabled = body.registrationEnabled;
        }
        if (body.loginMode && ['superadmin', 'admin', 'all'].includes(body.loginMode)) {
          settings.loginMode = body.loginMode;
        }
        saveSettings(settings);
        res.writeHead(200); res.end(JSON.stringify({ success: true, settings }));
        log('ADM ', `User '${session.username}' updated settings`, 'green');
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
        const body = await parseBody(req);
        const { username, password } = body;
        if (!username || !password) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名和密码不能为空' })); return;
        }
        if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
          res.writeHead(400); res.end(JSON.stringify({ error: '用户名需3-30位字母、数字或下划线' })); return;
        }
        if (password.length < 6) {
          res.writeHead(400); res.end(JSON.stringify({ error: '密码不能少于6位' })); return;
        }
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
        const body = await parseBody(req);
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
        const sessions = loadSessions();
        for (const [sid, s] of Object.entries(sessions)) {
          if (s.username === username) delete sessions[sid];
        }
        saveSessions(sessions);

        // 清理该用户的 2FA entries
        const entries = load2FAEntries();
        delete entries[username];
        save2FAEntries(entries);

        res.writeHead(200); res.end(JSON.stringify({ success: true }));
        log('ADM ', `User '${session.username}' deleted user '${username}'`, 'yellow');
        return;
      }

      // ---------- 管理员：获取用户2FA信息 ----------
      if (pathname === '/api/admin/user-2fa' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session || session.role !== 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '需要超级管理员权限' })); return;
        }
        const body = await parseBody(req);
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
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
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        const body = await parseBody(req);
        const { code } = body;
        const users = loadUsers();
        const user = users[session.username];
        if (!user.twoFactorPendingSecret) {
          res.writeHead(400); res.end(JSON.stringify({ error: '请先生成2FA密钥' })); return;
        }
        if (generateTOTP(user.twoFactorPendingSecret) !== code) {
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

      // ---------- 2FA：禁用 ----------
      if (pathname === '/api/2fa/disable' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        const body = await parseBody(req);
        const { code } = body;
        const users = loadUsers();
        const user = users[session.username];
        if (!user.twoFactorEnabled) {
          res.writeHead(400); res.end(JSON.stringify({ error: '2FA未启用' })); return;
        }
        if (generateTOTP(user.twoFactorSecret) !== code) {
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
      // 列出当前用户的 2FA 条目
      if (pathname === '/api/2fa/generator/entries' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        if (session.role === 'superadmin') {
          res.writeHead(200); res.end(JSON.stringify({ entries: [] })); return;
        }
        const all = load2FAEntries();
        const entries = (all[session.username] || []).map(e => ({ id: e.id, name: e.name, issuer: e.issuer, secret: e.secret, createdAt: e.createdAt }));
        res.writeHead(200); res.end(JSON.stringify({ entries })); return;
      }

      // 添加 2FA 条目（扫码 URI 或手动输入）
      if (pathname === '/api/2fa/generator/add' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        if (session.role === 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '超级管理员不具备2FA功能' })); return;
        }
        const body = await parseBody(req);
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
          name: name.slice(0, 50),
          issuer: issuer.slice(0, 30),
          secret,
          createdAt: Date.now()
        };
        const all = load2FAEntries();
        if (!all[session.username]) all[session.username] = [];
        all[session.username].push(entry);
        save2FAEntries(all);
        res.writeHead(201); res.end(JSON.stringify({ success: true, entry: { id: entry.id, name: entry.name, issuer: entry.issuer, secret: entry.secret, createdAt: entry.createdAt } }));
        log('2FA ', `User '${session.username}' added 2FA generator entry '${entry.name}' (${entry.issuer})`, 'green');
        return;
      }

      // 删除 2FA 条目
      if (pathname === '/api/2fa/generator/delete' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const session = getSession(cookies.session_id);
        if (!session) {
          res.writeHead(401); res.end(JSON.stringify({ error: '请先登录' })); return;
        }
        if (session.role === 'superadmin') {
          res.writeHead(403); res.end(JSON.stringify({ error: '超级管理员不具备2FA功能' })); return;
        }
        const body = await parseBody(req);
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
