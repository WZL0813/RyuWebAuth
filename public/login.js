(function () {
  'use strict';

  const BASE = '/api';
  function $(id) { return document.getElementById(id); }
  function showResult(text, ok) {
    const el = $('result');
    el.style.display = 'block';
    el.className = 'msg ' + (ok ? 'ok' : 'err');
    el.textContent = text;
  }
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[2]) : '';
  }
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

  // 小眼睛
  const EYE_OPEN = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/></svg>";
  const EYE_OFF = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M17.94 17.94A10.07 10.07 0 0 1 12 20C5 20 1 12 1 12a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24'/><line x1='1' y1='1' x2='23' y2='23'/></svg>";
  $('pw-toggle').onclick = () => {
    const inp = $('password');
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    $('pw-toggle').innerHTML = show ? EYE_OFF : EYE_OPEN;
  };

  $('btn-login').onclick = async () => {
    const identifier = $('identifier').value.trim();
    const password = $('password').value;
    if (!identifier || !password) return showResult('请输入用户名/邮箱与密码', false);
    if (!window.__2FA) return showResult('2FA SDK 未加载，请通过 http://localhost:3000/login.html 访问', false);

    showResult('正在登录…', true);
    const r = await postJson(`${BASE}/login`, { identifier, password });
    if (r.status !== 200) return showResult(r.data.error || '登录失败', false);

    if (r.data.require2FA) {
      try {
        const tempToken = await window.__2FA.require(r.data.userId);
        const s = await postJson(`${BASE}/session`, { tempToken });
        if (s.data.success) {
          window.location.href = '/dashboard.html';
        } else {
          showResult('换取会话失败：' + (s.data.error || ''), false);
        }
      } catch (e) {
        showResult((e.message || e), false);
      }
      return;
    }
    window.location.href = '/dashboard.html';
  };
})();
