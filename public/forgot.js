(function () {
  'use strict';

  const BASE = '/api';
  let mode = 'email';
  let questionIdentifier = null;

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

  // 小眼睛（统一绑定所有 .pw-toggle-new）
  const EYE_OPEN = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/></svg>";
  const EYE_OFF = "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#6b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M17.94 17.94A10.07 10.07 0 0 1 12 20C5 20 1 12 1 12a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24'/><line x1='1' y1='1' x2='23' y2='23'/></svg>";
  document.querySelectorAll('.pw-toggle-new').forEach((btn) => {
    btn.onclick = () => {
      const inp = btn.parentElement.querySelector('input');
      if (!inp) return;
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      btn.innerHTML = show ? EYE_OFF : EYE_OPEN;
    };
  });

  // Tab 切换
  document.querySelectorAll('.tab').forEach((t) => {
    t.onclick = () => {
      mode = t.dataset.tab;
      document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
      document.querySelectorAll('.pane').forEach((p) => p.classList.toggle('active', p.id === 'pane-' + mode));
    };
  });

  // 邮箱找回
  $('btn-send').onclick = async () => {
    const email = $('f-email').value.trim();
    if (!email) return showResult('请输入邮箱', false);
    const r = await postJson(`${BASE}/reset/email`, { email });
    if (r.status === 200) {
      $('code-box').style.display = 'block';
      showResult('验证码已发送（开发模式见服务器控制台）', true);
    } else {
      showResult((r.data.errors || [r.data.error || '发送失败']).join('\n'), false);
    }
  };

  // 密保找回
  $('btn-q').onclick = async () => {
    const identifier = $('identifier').value.trim();
    if (!identifier) return showResult('请输入用户名/邮箱', false);
    const r = await postJson(`${BASE}/reset/question`, { identifier });
    if (r.status === 200) {
      questionIdentifier = identifier;
      $('question').textContent = r.data.question;
      $('q-box').style.display = 'block';
    } else {
      showResult(r.data.error || '获取失败', false);
    }
  };

  // 重置密码
  $('btn-reset').onclick = async () => {
    if (mode === 'email') {
      const body = { email: $('f-email').value.trim(), code: $('f-code').value.trim(), newPassword: $('newpw1').value };
      if (!body.email || !body.code || !body.newPassword) return showResult('请填写邮箱、验证码与新密码', false);
      const r = await postJson(`${BASE}/reset/verify`, body);
      if (r.status === 200) showResult('密码已重置，请前往登录', true);
      else showResult((r.data.errors || [r.data.error || '重置失败']).join('\n'), false);
    } else {
      const body = { identifier: questionIdentifier, answer: $('answer').value.trim(), newPassword: $('newpw2').value };
      if (!body.identifier || !body.answer || !body.newPassword) return showResult('请填写答案与新密码', false);
      const r = await postJson(`${BASE}/reset/question/verify`, body);
      if (r.status === 200) showResult('密码已重置，请前往登录', true);
      else showResult((r.data.errors || [r.data.error || '重置失败']).join('\n'), false);
    }
  };
})();
