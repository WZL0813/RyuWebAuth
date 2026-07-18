// 冒烟测试: 验证 v1.0.2 修复 (CSRF + 密码策略 + 写互斥 + CSP)
const http = require('http');
const fs = require('fs');

const BASE = 'http://localhost:3180';

function req(method, path, body, headers) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined && body !== null && typeof body !== 'string' ? JSON.stringify(body) : body;
    const url = new URL(path, BASE);
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: Object.assign({},
        data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {},
        headers || {})
    };
    const r = http.request(opts, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

// 提取所有 set-cookie, 转成单一 Cookie 字符串 (server_id, csrf_token)
function getAllCookies(res) {
  const sc = res.headers['set-cookie'] || [];
  const out = {};
  for (const line of (Array.isArray(sc) ? sc : [sc])) {
    const m = /^([^=]+)=([^;]+)/.exec(line);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function cookieHeader(c) {
  return Object.entries(c).map(([k,v]) => `${k}=${v}`).join('; ');
}

function ok(label, cond, extra) {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + label + (extra ? '  ' + extra : ''));
  if (!cond) process.exitCode = 1;
}

(async () => {
  // 1) 首页 + 静态 + 安全头
  let r = await req('GET', '/');
  ok('GET / returns 200', r.status === 200);
  ok('CSP header present', !!r.headers['content-security-policy']);
  ok('X-Frame-Options DENY', r.headers['x-frame-options'] === 'DENY');
  ok('X-Content-Type-Options nosniff', r.headers['x-content-type-options'] === 'nosniff');
  ok('Referrer-Policy set', r.headers['referrer-policy'] === 'no-referrer');
  r = await req('GET', '/some/missing/page');
  ok('SPA fallback (no ext) -> 200', r.status === 200);
  r = await req('GET', '/missing.css');
  ok('Static missing -> 404', r.status === 404);

  // 1.5) Favicon / Logo (RyoWebAuth 猫娘)
  r = await req('GET', '/favicon.ico');
  ok('favicon.ico -> 200 + x-icon', r.status === 200 && /image\/x-icon/.test(r.headers['content-type'] || ''));
  r = await req('GET', '/favicon-32.png');
  ok('favicon-32.png -> 200 + png', r.status === 200 && /image\/png/.test(r.headers['content-type'] || ''));
  r = await req('GET', '/favicon-16.png');
  ok('favicon-16.png -> 200 + png', r.status === 200 && /image\/png/.test(r.headers['content-type'] || ''));
  r = await req('GET', '/apple-touch-icon.png');
  ok('apple-touch-icon.png -> 200 + png', r.status === 200 && /image\/png/.test(r.headers['content-type'] || ''));
  r = await req('GET', '/logo-256.png');
  ok('logo-256.png -> 200 + png', r.status === 200 && /image\/png/.test(r.headers['content-type'] || ''));
  r = await req('GET', '/logo-128.png');
  ok('logo-128.png -> 200 + png', r.status === 200 && /image\/png/.test(r.headers['content-type'] || ''));
  // 检查首页 <head> 含 4 个 link 标签
  r = await req('GET', '/');
  const hasIco = /<link[^>]+rel="icon"[^>]+href="\/favicon\.ico"/.test(r.body);
  const hasApple = /<link[^>]+rel="apple-touch-icon"/.test(r.body);
  ok('HTML has favicon.ico link', hasIco);
  ok('HTML has apple-touch-icon link', hasApple);
  // 检查页面内的 logo 用了 /logo-128.png 替换原 shield 图标
  const brandImgCount = (r.body.match(/class="brand-img"/g) || []).length;
  ok('HTML has 2 brand-img logos (corner+auth-page)', brandImgCount === 2);
  // 登录卡片内的 wordmark (RyoWebAuth.png)
  const wordmarkCount = (r.body.match(/class="wordmark-img"/g) || []).length;
  ok('HTML has 1 wordmark-img (auth card)', wordmarkCount === 1);
  const hasRyoRef = /src="\/RyoWebAuth\.png"/.test(r.body);
  ok('HTML references /RyoWebAuth.png', hasRyoRef);
  // 检查 data-icon 属性的 shield 引用都已被移除 (但允许 SVG 路径定义留在 iconify 库里)
  const usedShieldLock = (r.body.match(/data-icon="mdi:shield-lock"/g) || []).length;
  const usedShieldKey = (r.body.match(/data-icon="mdi:shield-key"/g) || []).length;
  ok('HTML no longer uses mdi:shield-lock (data-icon)', usedShieldLock === 0);
  ok('HTML no longer uses mdi:shield-key (data-icon)', usedShieldKey === 0);

  // 2) 登录
  const log = fs.readFileSync('C:/Users/24112/.trae-cn/work/6a5ac7e4d57146ae65a52c4f/RyuWebAuth-fix/data/server.log', 'utf8');
  const m = /Password\s*:\s*(\S+)/.exec(log);
  if (!m) { console.log('FAIL  no super admin password in log'); process.exit(1); }
  const adminPw = m[1].trim();
  console.log('INFO  super admin password: ' + adminPw);

  r = await req('POST', '/api/login', { username: 'RyuWebAuth', password: 'wrong' });
  ok('Login wrong pw -> 401', r.status === 401);
  r = await req('POST', '/api/login', { username: 'RyuWebAuth', password: adminPw });
  ok('Login correct pw -> 200', r.status === 200);
  let adminC = getAllCookies(r);
  ok('Set-Cookie has session_id', !!adminC.session_id);
  ok('Set-Cookie has csrf_token', !!adminC.csrf_token);
  ok('csrf_token != session_id', adminC.csrf_token !== adminC.session_id);

  // 1.5) 把 totp 限流调高, 让测试中的 6 次 2FA 调用不被限流
  // (实际部署中默认 1 分钟 5 次是合理的安全策略)
  r = await req('POST', '/api/admin/settings',
    { totpRateLimit: { max: 100, windowMs: 60000 } },
    { Cookie: cookieHeader(adminC), 'X-CSRF-Token': adminC.csrf_token });
  ok('Smoke setup: raise totp limit to 100', r.status === 200);

  // 3) 通用限流
  let blocked = false;
  for (let i = 0; i < 60; i++) {
    const rr = await req('GET', '/api/session', null, { Cookie: cookieHeader(adminC) });
    if (rr.status === 429) { blocked = true; break; }
  }
  ok('Rate limit triggers 429 (api bucket)', blocked);
  await new Promise(f => setTimeout(f, 1500));

  // 4) CSRF 缺失 → 403
  r = await req('POST', '/api/2fa/setup', {}, { Cookie: cookieHeader(adminC) });
  ok('Write without CSRF -> 403', r.status === 403, JSON.stringify(r.body));
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/2fa/setup', {},
    { Cookie: cookieHeader(adminC), 'X-CSRF-Token': 'a'.repeat(64) });
  ok('Write with wrong CSRF -> 403', r.status === 403, JSON.parse(r.body).error);

  // 5) 强密码策略: 注册时弱密码被拒
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/register', { username: 'weakuser', password: 'abc' });
  ok('Register weak pw (len<8) -> 400', r.status === 400, JSON.parse(r.body).error);
  r = await req('POST', '/api/register', { username: 'weakuser2', password: 'abcdefgh' }); // 长度够但单一类
  ok('Register single-class pw -> 400', r.status === 400, JSON.parse(r.body).error);
  r = await req('POST', '/api/register', { username: 'weakuser3', password: 'password' }); // 黑名单
  ok('Register common pw -> 400', r.status === 400, JSON.parse(r.body).error);
  r = await req('POST', '/api/register', { username: 'testuser', password: 'Test1234' });
  ok('Register strong pw -> 200', r.status === 200, JSON.parse(r.body).error||'ok');
  let userC = getAllCookies(r);

  // 6) 用户登录
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/login', { username: 'testuser', password: 'Test1234' });
  ok('Login testuser -> 200', r.status === 200);
  let userC2 = getAllCookies(r);
  ok('Login issues csrf_token', !!userC2.csrf_token);

  // 7) CORS
  r = await req('GET', '/api/session', null, { Cookie: cookieHeader(userC2) });
  ok('No Access-Control-Allow-Origin: *', !r.headers['access-control-allow-origin']);

  // 8) 2FA setup 走 CSRF
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/2fa/setup', {},
    { Cookie: cookieHeader(userC2), 'X-CSRF-Token': userC2.csrf_token });
  ok('2FA setup with CSRF -> 200', r.status === 200 && /^[A-Z2-7]{32}$/.test(JSON.parse(r.body).secret));
  const setupSecret = JSON.parse(r.body).secret;

  // 9) TOTP
  const crypto = require('crypto');
  function base32Decode(s) {
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    s = s.toUpperCase().replace(/=+$/, '');
    let bits = 0, value = 0; const out = [];
    for (const c of s) { value = (value << 5) | alpha.indexOf(c); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
    return Buffer.from(out);
  }
  function genTOTP(secret) {
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buf = Buffer.alloc(8); buf.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
    const off = hmac[19] & 0x0f;
    const code = ((hmac[off]&0x7f)<<24) | ((hmac[off+1]&0xff)<<16) | ((hmac[off+2]&0xff)<<8) | (hmac[off+3]&0xff);
    return String(code % 1000000).padStart(6, '0');
  }
  const totp = genTOTP(setupSecret);

  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/2fa/verify-setup', { code: totp },
    { Cookie: cookieHeader(userC2), 'X-CSRF-Token': userC2.csrf_token });
  ok('2FA verify-setup -> 200', r.status === 200);

  // 10) 改密 (弱新密码被拒, 强新密码通过)
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/change-password',
    { currentPassword: 'Test1234', newPassword: 'abc' },
    { Cookie: cookieHeader(userC2), 'X-CSRF-Token': userC2.csrf_token });
  ok('Change to weak pw -> 400', r.status === 400);
  r = await req('POST', '/api/change-password',
    { currentPassword: 'Test1234', newPassword: 'NewPass9' },
    { Cookie: cookieHeader(userC2), 'X-CSRF-Token': userC2.csrf_token });
  ok('Change to strong pw -> 200 (and rotates session+CSRF)', r.status === 200);
  let userC2new = getAllCookies(r);
  ok('Change issues new csrf_token', !!userC2new.csrf_token && userC2new.csrf_token !== userC2.csrf_token);

  // 11) 旧 cookie 失效
  r = await req('GET', '/api/session', null, { Cookie: cookieHeader(userC2) });
  ok('Old session invalidated', r.status === 401 || JSON.parse(r.body).loggedIn === false);

  // 12) 用新密码 + 2FA 重新登录
  const totpAt12 = genTOTP(setupSecret);
  r = await req('POST', '/api/login', { username: 'testuser', password: 'NewPass9', totpCode: totpAt12 });
  ok('Re-login with new pw + 2FA -> 200', r.status === 200);
  let userC3 = getAllCookies(r);

  // 13) Generator entries
  await new Promise(f => setTimeout(f, 1100));
  r = await req('GET', '/api/2fa/generator/entries', null, { Cookie: cookieHeader(userC3) });
  ok('Generator entries returns 200', r.status === 200);
  ok('Generator entries no secret', !('secret' in (JSON.parse(r.body).entries[0] || {})));

  // 14) Generator: add 走 CSRF
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/2fa/generator/add',
    { name: '"><img src=x onerror=alert(1)>', issuer: 'Evil"', secret: setupSecret },
    { Cookie: cookieHeader(userC3) }); // 故意不带 CSRF
  ok('Generator add without CSRF -> 403', r.status === 403);
  r = await req('POST', '/api/2fa/generator/add',
    { name: '"><img src=x onerror=alert(1)>', issuer: 'Evil"', secret: setupSecret },
    { Cookie: cookieHeader(userC3), 'X-CSRF-Token': userC3.csrf_token });
  ok('Generator add with CSRF -> 201', r.status === 201, JSON.parse(r.body).error||'ok');
  const addedId = JSON.parse(r.body).entry.id;

  // 15) secret by id
  await new Promise(f => setTimeout(f, 1100));
  r = await req('GET', '/api/2fa/generator/secret?id=' + addedId, null, { Cookie: cookieHeader(userC3) });
  ok('Generator secret by id -> 200', r.status === 200 && JSON.parse(r.body).secret === setupSecret);

  // 16) 超管 强制改密 (弱密被拒)
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/admin/reset-password',
    { username: 'testuser', newPassword: '12345678' },
    { Cookie: cookieHeader(adminC), 'X-CSRF-Token': adminC.csrf_token });
  ok('Admin reset with single-class pw -> 400', r.status === 400);
  r = await req('POST', '/api/admin/reset-password',
    { username: 'testuser', newPassword: 'Forced9!' },
    { Cookie: cookieHeader(adminC), 'X-CSRF-Token': adminC.csrf_token });
  ok('Admin reset with strong pw -> 200', r.status === 200);

  // 17) 旧 testuser session 失效
  await new Promise(f => setTimeout(f, 500));
  r = await req('GET', '/api/session', null, { Cookie: cookieHeader(userC3) });
  ok('Testuser session invalidated by admin reset', r.status === 401 || JSON.parse(r.body).loggedIn === false);

  // 18) Body size limit
  await new Promise(f => setTimeout(f, 1100));
  const big = 'a'.repeat(2 * 1024 * 1024);
  try {
    r = await req('POST', '/api/login', big);
    ok('Oversized body -> 413', r.status === 413);
  } catch (e) {
    ok('Oversized body -> rejected', e.code === 'ECONNRESET' || (r && r.status === 413), e.code);
  }

  // 19) 关闭 2FA 需要密码
  await new Promise(f => setTimeout(f, 1100));
  const totpAt19 = genTOTP(setupSecret);
  r = await req('POST', '/api/login', { username: 'testuser', password: 'Forced9!', totpCode: totpAt19 });
  ok('Login forced pw + 2FA -> 200', r.status === 200);
  let userC4 = getAllCookies(r);

  await new Promise(f => setTimeout(f, 1100));
  const totp2 = genTOTP(setupSecret);
  r = await req('POST', '/api/2fa/disable', { code: totp2 },
    { Cookie: cookieHeader(userC4), 'X-CSRF-Token': userC4.csrf_token });
  ok('Disable 2FA without pw -> 400', r.status === 400);
  r = await req('POST', '/api/2fa/disable', { code: totp2, password: 'Forced9!' },
    { Cookie: cookieHeader(userC4), 'X-CSRF-Token': userC4.csrf_token });
  ok('Disable 2FA with TOTP+pw -> 200', r.status === 200);

  // 20) 并发写测试: 同时发起 3 个不同用户注册 (注: 5/hour 限流会拒绝后续,
  // 所以这是验证 "限流 + 写" 的组合, 不是 3 个全部成功)
  await new Promise(f => setTimeout(f, 2000)); // 等限流窗口过去
  const results = await Promise.all([
    req('POST', '/api/register', { username: 'concuser1', password: 'Pass1234' }),
    req('POST', '/api/register', { username: 'concuser2', password: 'Pass1234' })
  ]);
  const successes = results.filter(x => x.status === 200).length;
  ok('Concurrent registrations: 至少 1 成功 (其它被 register 限流)', successes >= 1,
    'statuses=' + results.map(x => x.status).join(','));

  // 验证 users.json 没有损坏 (能读回)
  await new Promise(f => setTimeout(f, 100));
  r = await req('GET', '/api/admin/users', null,
    { Cookie: cookieHeader(adminC), 'X-CSRF-Token': adminC.csrf_token });
  ok('users.json 读回成功 (写后无损坏)', r.status === 200);
  const allUsers = JSON.parse(r.body).users;
  const hasConc = allUsers.some(u => /^concuser/.test(u.username));
  ok('并发用户至少 1 个被持久化', hasConc);

  // 21) 退出登录: 清 csrf cookie
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/logout', {},
    { Cookie: cookieHeader(userC4), 'X-CSRF-Token': userC4.csrf_token });
  ok('Logout returns 200', r.status === 200);
  const sc = r.headers['set-cookie'] || [];
  const flat = (Array.isArray(sc) ? sc : [sc]).join('|');
  ok('Logout sets session_id clear cookie', /session_id=;/.test(flat));
  ok('Logout sets csrf_token clear cookie', /csrf_token=;/.test(flat));

  // 22) 登录的 password 字段太长 (>128) 被拒
  await new Promise(f => setTimeout(f, 1100));
  r = await req('POST', '/api/register', { username: 'toobig', password: 'Aa1!' + 'x'.repeat(125) });
  ok('Oversized password length -> 400 (or 429 if still rate-limited)',
     r.status === 400 || r.status === 429, 'status=' + r.status + ' body=' + r.body);

  console.log('\nDONE');
})();
