(function () {
  'use strict';

  const BASE = '/api';
  let regId = null;
  let tfaData = null;
  let tfaVerified = false;
  let resendTimer = null;

  function $(id) { return document.getElementById(id); }

  function showStep(n) {
    document.querySelectorAll('.step').forEach((s) => s.classList.remove('active'));
    $('step-' + n).classList.add('active');
    document.querySelectorAll('.steps .s').forEach((el) => {
      const step = Number(el.dataset.step);
      el.classList.toggle('active', step === n);
      el.classList.toggle('done', step < n);
    });
  }

  function msg(elId, text, ok) {
    const el = $(elId);
    el.style.display = 'block';
    el.className = 'msg ' + (ok ? 'ok' : 'err');
    el.textContent = text;
  }
  function clearMsg(elId) { $(elId).style.display = 'none'; }

  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[2]) : '';
  }
  function safeJson(res) {
    return res.text().then((t) => {
      try { return JSON.parse(t); }
      catch (e) { return { __notJson: true, text: t.slice(0, 160) }; }
    });
  }
  function postJson(url, body) {
    const headers = { 'Content-Type': 'application/json' };
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(url, { method: 'POST', headers, body: JSON.stringify(body) })
      .then((r) => safeJson(r).then((d) => ({ status: r.status, data: d })));
  }
  function errText(r) {
    const d = r.data;
    if (d && d.__notJson) return '服务返回异常（可能服务未启动或版本不匹配）';
    return (d && (d.errors || [d.error || d.message])) ? (Array.isArray(d.errors) ? d.errors.join('\n') : d.errors) : '请求失败';
  }
  function maskEmail(e) {
    const [u, d] = e.split('@');
    return (u.length > 2 ? u[0] + '***' + u[u.length - 1] : u) + '@' + d;
  }

  // ---- 开始 ----
  $('btn-start').onclick = () => {
    regId = (crypto.randomUUID && crypto.randomUUID()) ||
      ('id-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    showStep(1);
  };

  // ---- ① 填写信息 ----
  function updatePwChecks() {
    const pw = $('password').value;
    const checks = {
      len: pw.length >= 8,
      lower: /[a-z]/.test(pw),
      upper: /[A-Z]/.test(pw),
      symbol: /[^A-Za-z0-9]/.test(pw),
      emoji: !/\p{Extended_Pictographic}/u.test(pw)
    };
    document.querySelectorAll('#pw-checks li').forEach((li) => li.classList.toggle('pass', !!checks[li.dataset.k]));
  }
  $('password').addEventListener('input', updatePwChecks);

  // 小眼睛：显示/隐藏密码（单色 SVG，无 emoji）
  const EYE_OPEN = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/></svg>";
  const EYE_OFF = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M17.94 17.94A10.07 10.07 0 0 1 12 20C5 20 1 12 1 12a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24'/><line x1='1' y1='1' x2='23' y2='23'/></svg>";
  $('pw-toggle').onclick = () => {
    const inp = $('password');
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    $('pw-toggle').innerHTML = show ? EYE_OFF : EYE_OPEN;
  };

  // 自定义下拉框
  const secQWrap = $('secQ-wrap');
  const secQTrigger = $('secQ-trigger');
  const secQOptions = $('secQ-options');
  secQTrigger.onclick = (e) => {
    e.stopPropagation();
    const isOpen = secQOptions.classList.contains('show');
    secQOptions.classList.toggle('show', !isOpen);
    secQTrigger.classList.toggle('open', !isOpen);
  };
  secQOptions.querySelectorAll('.select-option').forEach((opt) => {
    opt.onclick = () => {
      const val = opt.dataset.value;
      secQWrap.dataset.value = val;
      secQTrigger.textContent = opt.textContent;
      secQTrigger.classList.toggle('has-value', !!val);
      secQOptions.classList.remove('show');
      secQTrigger.classList.remove('open');
      secQOptions.querySelectorAll('.select-option').forEach((o) => o.classList.toggle('selected', o.dataset.value === val));
    };
  });
  document.addEventListener('click', () => {
    secQOptions.classList.remove('show');
    secQTrigger.classList.remove('open');
  });

  $('form-info').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMsg('info-msg');
    const body = {
      regId,
      username: $('username').value.trim(),
      password: $('password').value,
      age: $('age').value.trim(),
      email: $('email').value.trim(),
      securityQuestion: secQWrap.dataset.value,
      securityAnswer: $('secA').value.trim()
    };
    if (!body.username || !body.password || !body.age || !body.email) {
      return msg('info-msg', '请填写用户名、密码、年龄与邮箱', false);
    }
    if (!body.securityQuestion || !body.securityAnswer) {
      return msg('info-msg', '请选择密保问题并填写答案', false);
    }
    const r = await postJson(`${BASE}/reg/info`, body);
    if (r.status === 200 && r.data.ok) {
      msg('info-msg', '信息已保存，服务端校验通过', true);
      setTimeout(() => { $('email-display').textContent = maskEmail(body.email); showStep(2); }, 600);
    } else {
      msg('info-msg', errText(r), false);
    }
  });

  // ---- ② 邮箱验证（可选） ----
  $('form-email').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMsg('email-msg');
    const r = await postJson(`${BASE}/reg/email`, { regId });
    if (r.status === 200 && r.data.sent) {
      $('email-code-box').style.display = 'block';
      msg('email-msg', `验证码已发送至 ${$('email-display').textContent}（有效期 ${r.data.expiresMin} 分钟）`, true);
      startResendCountdown();
    } else {
      msg('email-msg', errText(r), false);
    }
  });

  function startResendCountdown() {
    let left = 60;
    const btn = $('btn-send');
    btn.disabled = true;
    const tick = () => {
      $('resend-hint').textContent = `可重新发送倒计时：${left}s`;
      if (left-- <= 0) { btn.disabled = false; $('resend-hint').textContent = '可重新发送验证码'; clearInterval(resendTimer); }
    };
    tick();
    resendTimer = setInterval(tick, 1000);
  }

  $('btn-verify-email').onclick = async () => {
    clearMsg('email-msg');
    const code = $('code').value.trim();
    if (!code) return msg('email-msg', '请输入验证码', false);
    const r = await postJson(`${BASE}/reg/email/verify`, { regId, code });
    if (r.status === 200 && r.data.verified) {
      msg('email-msg', '邮箱验证通过', true);
      clearInterval(resendTimer);
      setTimeout(() => showStep(3), 500);
    } else {
      msg('email-msg', errText(r), false);
    }
  };

  $('btn-skip-email').onclick = () => {
    clearInterval(resendTimer);
    showStep(3);
  };

  // ---- ③ 两步验证 ----
  document.querySelectorAll('input[name="tfa"]').forEach((radio) => {
    radio.onchange = () => {
      const val = document.querySelector('input[name="tfa"]:checked').value;
      if (val === 'enable') {
        $('tfa-enable-box').style.display = 'block';
        $('tfa-disable-box').style.display = 'none';
        tfaVerified = false;
        $('btn-complete').disabled = true;
        loadTfa();
      } else {
        $('tfa-enable-box').style.display = 'none';
        $('tfa-disable-box').style.display = 'block';
        postJson(`${BASE}/reg/2fa`, { regId, enabled: false, riskAck: true });
        tfaData = null; tfaVerified = false;
        $('btn-complete').disabled = !$('riskAck').checked;
      }
    };
  });
  $('riskAck').onchange = () => { $('btn-complete').disabled = !$('riskAck').checked; };

  async function loadTfa() {
    const r = await postJson(`${BASE}/reg/2fa`, { regId, enabled: true });
    if (r.status === 200) {
      tfaData = r.data;
      $('tfa-enable-box').innerHTML = `
        <p>请用验证器 App 扫描二维码（或手动输入密钥）：</p>
        <div class="qr"><img src="${r.data.qrcode}" alt="qr" style="max-width:200px;" /></div>
        <p class="hint">密钥：<code>${r.data.secret}</code></p>
        <p style="color:#b91c1c;font-size:13px;">注意：请保存以下恢复码（每个仅能用一次）：</p>
        <div class="recovery">${r.data.recoveryCodes.join('\n')}</div>
        <label for="tfa-code" style="margin-top:14px;">绑定后，请输入验证器当前动态码以完成验证</label>
        <input type="text" id="tfa-code" maxlength="6" inputmode="numeric" placeholder="6 位动态码" />
        <button type="button" id="btn-tfa-verify" class="secondary">验证动态码</button>
        <div id="tfa-verify-msg" class="msg"></div>`;
      $('btn-tfa-verify').onclick = verifyTfa;
    } else {
      msg('tfa-msg', errText(r), false);
    }
  }

  async function verifyTfa() {
    clearMsg('tfa-verify-msg');
    const token = $('tfa-code').value.trim();
    if (!token) return msg('tfa-verify-msg', '请输入动态码', false);
    const r = await postJson(`${BASE}/verify`, { userId: regId, token });
    if (r.status === 200 && r.data.success) {
      tfaVerified = true;
      msg('tfa-verify-msg', '动态码校验通过（服务端确认），2FA 已生效', true);
      $('btn-complete').disabled = false;
    } else {
      msg('tfa-verify-msg', (r.data && r.data.error) || '动态码错误', false);
    }
  }

  $('btn-complete').onclick = async () => {
    clearMsg('tfa-msg');
    const val = document.querySelector('input[name="tfa"]:checked').value;
    if (val === 'enable' && !tfaVerified) {
      return msg('tfa-msg', '开启 2FA 需先通过动态码验证', false);
    }
    if (val === 'disable' && !$('riskAck').checked) {
      return msg('tfa-msg', '关闭 2FA 需勾选“已知风险”', false);
    }
    if (val === 'disable') {
      const r = await postJson(`${BASE}/reg/2fa`, { regId, enabled: false, riskAck: true });
      if (r.status !== 200) return msg('tfa-msg', errText(r), false);
    }
    const c = await postJson(`${BASE}/reg/complete`, { regId });
    if (c.status === 200) {
      $('done-msg').textContent = `注册成功！\n用户名：${c.data.username}\n两步验证：${c.data.twoFactorEnabled ? '已开启并验证' : '未开启'}`;
      // 保存到本地，供仪表盘使用
      try {
        const saved = JSON.parse(localStorage.getItem('f2a_users') || '[]');
        if (!saved.includes(c.data.userId)) saved.push(c.data.userId);
        localStorage.setItem('f2a_users', JSON.stringify(saved));
      } catch (e) { /* ignore */ }
      showStep(4);
    } else {
      msg('tfa-msg', errText(c), false);
    }
  };
})();
