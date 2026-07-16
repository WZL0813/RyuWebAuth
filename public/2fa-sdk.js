(function () {
  'use strict';

  const script = document.currentScript;
  const apiBase = (script && script.dataset.apiBase) || '/api';

  const state = { resolve: null, reject: null };
  let currentSecret = null; // 本次会话绑定拿到的 secret（仅用于测试演示生成动态码）

  // ---- 浏览器端 RFC 6238 TOTP（仅用于测试页“演示”按钮，证明服务端动态码校验）----
  function base32ToBytes(str) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, value = 0;
    const out = [];
    for (let i = 0; i < str.length; i++) {
      const idx = alphabet.indexOf(str[i].toUpperCase());
      if (idx === -1) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }
  async function hotp(secretBase32, counter) {
    const key = base32ToBytes(secretBase32);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buf));
    const offset = sig[19] & 0xf;
    const code = ((sig[offset] & 0x7f) << 24) |
      ((sig[offset + 1] & 0xff) << 16) |
      ((sig[offset + 2] & 0xff) << 8) |
      (sig[offset + 3] & 0xff);
    return (code % 1000000).toString().padStart(6, '0');
  }
  function totpNow(secretBase32) {
    return hotp(secretBase32, Math.floor(Date.now() / 30000));
  }

  window.__2FA = {
    // 现有网站登录成功后调用此方法
    // 返回 Promise，resolve 时会拿到临时令牌 tempToken
    require: function (userId) {
      return new Promise((resolve, reject) => {
        state.resolve = resolve;
        state.reject = reject;

        fetch(`${apiBase}/status/${encodeURIComponent(userId)}`)
          .then((r) => r.json())
          .then((data) => {
            if (!data.enabled) {
              showBindUI(userId);
            } else {
              showVerifyUI(userId);
            }
          })
          .catch((err) => {
            cleanup();
            reject(err);
          });
      });
    }
  };

  function cleanup() {
    state.resolve = null;
    state.reject = null;
    const existing = document.getElementById('2fa-overlay');
    if (existing) existing.remove();
  }

  // 读取 cookie（用于 CSRF 双重提交）
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[2]) : '';
  }

  // 统一的 POST 请求：自动带上 CSRF 头
  function safeJson(res) {
    return res.text().then((t) => {
      try { return JSON.parse(t); }
      catch (e) { return { __notJson: true, text: t.slice(0, 120) }; }
    });
  }
  function postJson(url, body) {
    const headers = { 'Content-Type': 'application/json' };
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(url, { method: 'POST', headers, body: JSON.stringify(body) })
      .then((r) => safeJson(r).then((d) => ({ status: r.status, data: d })));
  }

  function createOverlay() {
    const existing = document.getElementById('2fa-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = '2fa-overlay';
    overlay.style.cssText =
      'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);' +
      'z-index:9999;display:flex;justify-content:center;align-items:center;font-family:sans-serif;';
    const inner = document.createElement('div');
    inner.style.cssText =
      'background:#fff;padding:30px;border-radius:8px;max-width:420px;width:90%;' +
      'text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.3);';
    overlay.appendChild(inner);
    document.body.appendChild(overlay);
    return inner;
  }

  function showBindUI(userId) {
    const box = createOverlay();
    box.innerHTML = `
      <h3 style="margin-top:0;">绑定两步验证</h3>
      <p>请用验证器 App（如 Google Authenticator）扫描下方二维码</p>
      <div id="2fa-qr" style="margin:16px 0;"></div>
      <p>或手动输入密钥：<code id="2fa-secret" style="background:#f0f0f0;padding:4px 8px;border-radius:4px;word-break:break-all;"></code></p>
      <button id="2fa-bind-done" style="margin-top:16px;padding:8px 24px;cursor:pointer;background:#374151;color:#fff;border:none;border-radius:8px;font-size:14px;">我已绑定，下一步</button>
      <div id="2fa-recovery" style="margin-top:16px;text-align:left;font-size:13px;"></div>
    `;

    postJson(`${apiBase}/register`, { userId })
      .then((r) => { const data = r.data;
        currentSecret = data.secret; // 仅用于测试演示
        document.getElementById('2fa-qr').innerHTML = `<img src="${data.qrcode}" alt="qr" style="max-width:200px;" />`;
        document.getElementById('2fa-secret').textContent = data.secret;
        document.getElementById('2fa-recovery').innerHTML = `
          <p style="color:#b00;">注意：请保存以下恢复码（每个只能用一次）：</p>
          <pre style="background:#f7f7f7;padding:10px;border-radius:4px;overflow:auto;">${data.recoveryCodes.join('\n')}</pre>
        `;
      });

    document.getElementById('2fa-bind-done').onclick = () => {
      cleanup();
      showVerifyUI(userId);
    };
  }

  function showVerifyUI(userId) {
    const box = createOverlay();
    box.innerHTML = `
      <h3 style="margin-top:0;">输入两步验证码</h3>
      <input type="text" id="2fa-token" maxlength="6" placeholder="6位数字"
        style="width:200px;padding:10px;font-size:18px;text-align:center;letter-spacing:4px;border:1px solid #d1d5db;border-radius:8px;outline:none;" />
      <div style="margin-top:16px;display:flex;gap:8px;justify-content:center;">
        <button id="2fa-submit" style="padding:8px 24px;cursor:pointer;background:#374151;color:#fff;border:none;border-radius:8px;font-size:14px;">验证</button>
        <button id="2fa-cancel" style="padding:8px 24px;cursor:pointer;background:#f3f4f6;color:#374151;border:none;border-radius:8px;font-size:14px;">取消</button>
      </div>
      ${currentSecret ? '<button id="2fa-demo" style="margin-top:12px;padding:6px 12px;cursor:pointer;font-size:12px;background:#eef;color:#135;border:none;border-radius:6px;">（测试）生成当前动态码并验证</button>' : ''}
      <p id="2fa-error" style="color:red;min-height:18px;margin-top:8px;"></p>
    `;

    const submit = () => {
      const token = document.getElementById('2fa-token').value.trim();
      const errEl = document.getElementById('2fa-error');
      errEl.textContent = '';
      postJson(`${apiBase}/verify`, { userId, token })
        .then((r) => { const data = r.data;
          if (data.success) {
            errEl.style.color = 'green';
            errEl.textContent = data.usedRecovery
              ? '恢复码校验通过（服务端确认）'
              : '动态码（TOTP）校验通过（服务端确认）';
            cleanup();
            if (state.resolve) state.resolve(data.tempToken);
          } else {
            errEl.textContent = data.error || '验证失败';
          }
        })
        .catch((err) => {
          errEl.textContent = '请求失败';
          if (state.reject) state.reject(err);
        });
    };

    document.getElementById('2fa-submit').onclick = submit;
    document.getElementById('2fa-cancel').onclick = () => {
      cleanup();
      if (state.reject) state.reject(new Error('cancelled'));
    };
    document.getElementById('2fa-token').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submit();
    });

    const demoBtn = document.getElementById('2fa-demo');
    if (demoBtn) {
      demoBtn.onclick = async () => {
        try {
          const code = await totpNow(currentSecret);
          document.getElementById('2fa-token').value = code;
          submit();
        } catch (e) {
          document.getElementById('2fa-error').textContent = '演示生成失败: ' + e.message;
        }
      };
    }
  }
})();
