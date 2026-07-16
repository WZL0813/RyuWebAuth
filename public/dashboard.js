(function () {
  'use strict';

  const BASE = '/api';
  let currentUser = null;
  let currentTab = 'totp';

  function $(id) { return document.getElementById(id); }
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.remove('show');
    void t.offsetWidth;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 1500);
  }
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[2]) : '';
  }
  function toggleVisibility(displayId, hiddenId) {
    const display = $(displayId);
    const hidden = $(hiddenId);
    if (!display || !hidden) return;
    const isMasked = display.value === '••••••••' || display.dataset.masked === 'true';
    if (isMasked) {
      display.value = hidden.value || '未设置';
      display.dataset.masked = 'false';
    } else {
      display.value = '••••••••';
      display.dataset.masked = 'true';
    }
  }
  window.toggleVisibility = toggleVisibility;
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
  function putJson(url, body) {
    const headers = { 'Content-Type': 'application/json' };
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(url, { method: 'PUT', headers, body: JSON.stringify(body) })
      .then((r) => safeJson(r).then((d) => ({ status: r.status, data: d })));
  }
  function delJson(url) {
    const headers = {};
    const csrf = getCookie('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return fetch(url, { method: 'DELETE', headers })
      .then((r) => safeJson(r).then((d) => ({ status: r.status, data: d })));
  }
  function msg(elId, text, ok) {
    const el = $(elId);
    if (!el) return;
    el.style.display = 'block';
    el.className = 'msg ' + (ok ? 'ok' : 'err');
    el.textContent = text;
  }
  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ===================== 登录检查 =====================
  async function checkAuth() {
    try {
      const r = await fetch(`${BASE}/me`).then((res) => safeJson(res));
      if (r.error || !r.userId) {
        window.location.href = '/login.html';
        return false;
      }
      currentUser = r;
      $('display-user').textContent = r.username;
      const roleTag = $('display-role');
      roleTag.textContent = r.role === 'superadmin' ? '超级管理员' : r.role === 'admin' ? '管理员' : '用户';
      if (r.role === 'superadmin') roleTag.classList.add('superadmin');
      if (r.role === 'superadmin' || r.role === 'admin') {
        $('nav-settings').style.display = '';
        $('nav-accounts').style.display = '';
        $('nav-divider-admin').style.display = '';
      }
      return true;
    } catch (e) {
      window.location.href = '/login.html';
      return false;
    }
  }

  // ===================== Tab 切换 =====================
  document.querySelectorAll('.sidebar a[data-tab]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = a.dataset.tab;
      switchTab(tab);
    });
  });

  function switchTab(tab) {
    if (currentTab === 'profile' && tab !== 'profile') {
      const verifySection = $('2fa-verify-section');
      if (verifySection && verifySection.style.display !== 'none') {
        verifySection.style.display = 'none';
        $('2fa-enable-section').style.display = '';
        $('2fa-qr').innerHTML = '';
        $('2fa-secret-display').innerHTML = '';
        $('2fa-recovery-codes').style.display = 'none';
        $('2fa-token-input').value = '';
        pendingSecret = null;
        pendingRecoveryCodes = null;
      }
    }
    currentTab = tab;
    document.querySelectorAll('.sidebar a').forEach((a) => a.classList.remove('active'));
    document.querySelector(`.sidebar a[data-tab="${tab}"]`)?.classList.add('active');
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    $(`panel-${tab}`)?.classList.add('active');
    if (tab === 'settings') loadSettings();
    if (tab === 'accounts') loadAdminAccounts();
    if (tab === 'profile') loadProfile();
  }

  // ===================== 登出 =====================
  $('btn-logout').onclick = async () => {
    await postJson(`${BASE}/logout`, {});
    window.location.href = '/login.html';
  };

  // ===================== TOTP 管理 =====================
  let accounts = [];

  async function loadAccounts() {
    const r = await postJson(`${BASE}/totp/batch`, { userIds: accounts.map((a) => a.userId) });
    if (r.status !== 200) return;
    renderCodes(r.data.codes, r.data.remaining);
  }

  async function loadAccountList() {
    const regUsers = [];
    try {
      const saved = localStorage.getItem('f2a_users');
      if (saved) {
        const list = JSON.parse(saved);
        list.forEach((u) => { if (!regUsers.includes(u)) regUsers.push(u); });
      }
    } catch (e) { /* ignore */ }
    if (regUsers.length > 0) {
      accounts = regUsers.map((u) => ({ userId: u }));
    }
    const r = await postJson(`${BASE}/totp/batch`, { userIds: accounts.map((a) => a.userId) });
    if (r.status === 200 && r.data.codes && r.data.codes.length > 0) {
      accounts = r.data.codes.filter((c) => c.code).map((c) => ({ userId: c.userId }));
      renderCodes(r.data.codes, r.data.remaining);
    } else {
      $('totp-list').innerHTML = '<div class="empty">暂无账户，请在上方输入用户 ID 生成密钥</div>';
    }
  }

  function renderCodes(codes, globalRemaining) {
    if (!codes || codes.length === 0) {
      $('totp-list').innerHTML = '<div class="empty">暂无账户，请在上方添加</div>';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const remaining = globalRemaining || (30 - (now % 30));
    const pct = (remaining / 30) * 100;
    const urgent = remaining <= 5;

    $('totp-list').innerHTML = codes.map((c) => {
      if (c.error) {
        return `<div class="totp-card">
          <div class="user">${esc(c.userId)}</div>
          <div style="color:#dc2626; font-size:13px; padding:12px 0;">${c.error}</div>
        </div>`;
      }
      const display = c.code ? c.code.replace(/(.{3})/g, '$1 ').trim() : '---';
      return `<div class="totp-card">
        <div class="user">${esc(c.userId)}</div>
        <div class="code-display" id="code-${esc(c.userId)}">${display}</div>
        <div class="timer-bar"><div class="fill ${urgent ? 'urgent' : ''}" style="width:${pct}%"></div></div>
        <div class="meta">
          <span>${remaining}s 后刷新</span>
          <div class="actions">
            <button class="btn btn-copy" onclick="dashboardApp.copyCode('${c.code}')">复制</button>
            <button class="btn btn-danger" onclick="dashboardApp.revokeTOTP('${c.userId}')">删除</button>
          </div>
        </div>
      </div>`;
    }).join('');
  }

  $('btn-create').onclick = async () => {
    const userId = $('new-userId').value.trim();
    const secret = $('new-secret').value.trim();
    if (!userId) return msg('create-msg', '请输入账户名称', false);
    if (!secret) return msg('create-msg', '请输入密钥', false);
    const r = await postJson(`${BASE}/totp/create`, { userId, secret });
    if (r.status === 200) {
      if (r.data.message === '已存在密钥') {
        msg('create-msg', `账户 ${userId} 已存在`, true);
      } else {
        msg('create-msg', `账户 ${userId} 已添加，当前验证码: ${r.data.code}`, true);
      }
      $('new-userId').value = '';
      $('new-secret').value = '';
      loadAccounts();
    } else {
      msg('create-msg', r.data.error || '添加失败', false);
    }
  };

  // ===================== API Key 管理 =====================
  $('btn-genkey').onclick = async () => {
    const name = $('apikey-name').value.trim();
    if (!name) return;
    const r = await postJson(`${BASE}/totp/apikey`, { name });
    if (r.status === 200) {
      $('apikey-result').innerHTML = `<div class="api-key-display">${r.data.apiKey}</div><p style="font-size:12px; color:#dc2626;">请立即复制保存，此密钥仅显示一次</p>`;
      loadApiKeys();
    }
  };

  async function loadApiKeys() {
    const r = await fetch(`${BASE}/totp/apikeys`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    if (!r.keys || r.keys.length === 0) {
      $('apikey-list').innerHTML = '<tr><td colspan="4" style="text-align:center; color:#9ca3af;">暂无密钥</td></tr>';
      return;
    }
    $('apikey-list').innerHTML = r.keys.map((k) => `<tr>
      <td>${esc(k.name)}</td>
      <td><span class="tag">${k.permissions}</span></td>
      <td>${k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : '从未'}</td>
      <td><button class="btn btn-danger" onclick="dashboardApp.deleteKey(${k.id})">删除</button></td>
    </tr>`).join('');
  }

  // ===================== 系统设置 =====================
  async function loadSettings() {
    const r = await fetch(`${BASE}/admin/settings`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    if (r.registration_enabled !== undefined) $('opt-registration').checked = r.registration_enabled === '1';
    if (r.login_enabled !== undefined) $('opt-login').checked = r.login_enabled === '1';

    const sr = await fetch(`${BASE}/admin/stats`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    if (sr.totalUsers !== undefined) {
      $('stats-grid').innerHTML = [
        { n: sr.totalUsers, l: '总用户' },
        { n: sr.total2FA, l: '已配置 2FA' },
        { n: sr.activeSessions, l: '活跃会话' },
        { n: sr.totalApiKeys, l: 'API 密钥' },
        { n: sr.adminCount, l: '管理员' }
      ].map((s) => `<div class="stat-item"><div class="num">${s.n}</div><div class="lbl">${s.l}</div></div>`).join('');
    }
  }

  $('btn-save-settings').onclick = async () => {
    const r = await putJson(`${BASE}/admin/settings`, {
      registration_enabled: $('opt-registration').checked,
      login_enabled: $('opt-login').checked
    });
    if (r.status === 200) msg('settings-msg', '设置已保存', true);
    else msg('settings-msg', r.data.error || '保存失败', false);
  };

  // ===================== 账号管理 =====================
  let adminPage = 1;
  let adminSearch = '';

  async function loadAdminAccounts() {
    const params = new URLSearchParams({ page: adminPage, limit: 15 });
    if (adminSearch) params.set('search', adminSearch);
    const r = await fetch(`${BASE}/admin/accounts?${params}`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    if (!r.accounts) return;
    if (r.accounts.length === 0) {
      $('account-list').innerHTML = '<tr><td colspan="6" class="empty">暂无账号</td></tr>';
      $('account-pagination').innerHTML = '';
      return;
    }
    $('account-list').innerHTML = r.accounts.map((a) => `<tr>
      <td><b>${esc(a.username)}</b></td>
      <td style="color:#6b7280;">${esc(a.email)}</td>
      <td><span class="tag">${a.role}</span></td>
      <td><span class="tag" style="${a.status === 'disabled' ? 'color:#dc2626;background:#fef2f2;' : ''}">${a.status}</span></td>
      <td><span class="tag" style="${a.twoFactorEnabled ? 'color:#059669;background:#ecfdf5;' : 'color:#9ca3af;'}">${a.twoFactorEnabled ? 'ON' : 'OFF'}</span></td>
      <td>
        <div class="action-cell">
          <select onchange="dashboardApp.changeRole('${a.userId}', this.value)">
            <option value="user" ${a.role === 'user' ? 'selected' : ''}>user</option>
            <option value="admin" ${a.role === 'admin' ? 'selected' : ''}>admin</option>
            <option value="superadmin" ${a.role === 'superadmin' ? 'selected' : ''}>superadmin</option>
          </select>
          <button class="btn btn-danger" onclick="dashboardApp.deleteAccount('${a.userId}')">删除</button>
        </div>
      </td>
    </tr>`).join('');

    let paginationHtml = '';
    for (let i = 1; i <= r.totalPages; i++) {
      paginationHtml += `<button class="${i === r.page ? 'active' : ''}" onclick="dashboardApp.goAdminPage(${i})">${i}</button>`;
    }
    $('account-pagination').innerHTML = paginationHtml;
  }

  $('btn-search-account').onclick = () => {
    adminSearch = $('account-search').value.trim();
    adminPage = 1;
    loadAdminAccounts();
  };
  $('account-search').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      adminSearch = $('account-search').value.trim();
      adminPage = 1;
      loadAdminAccounts();
    }
  });

  // ===================== 个人设置 =====================
  let requireEmailVerification = false;
  let pendingSecret = null;
  let pendingRecoveryCodes = null;

  async function loadProfile() {
    const r = await fetch(`${BASE}/user/profile`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    const username = r.username || currentUser?.username || '';
    const email = r.email || '';
    const sq = r.securityQuestion || '';
    const sa = r.securityAnswer || '';

    $('profile-username').value = username;

    $('profile-email-display').value = '••••••••';
    $('profile-email-display').dataset.masked = 'true';
    $('profile-email-hidden').value = email;
    $('profile-email').value = '';

    if (sq) {
      $('profile-question-display').value = '••••••••';
      $('profile-question-display').dataset.masked = 'true';
      $('profile-question-hidden').value = sq;
      $('profile-question').value = sq;
    } else {
      $('profile-question-display').value = '未设置';
      $('profile-question-display').dataset.masked = 'false';
      $('profile-question-hidden').value = '';
      $('profile-question').value = '';
    }
    if (sa) {
      $('profile-answer-display').value = '••••••••';
      $('profile-answer-display').dataset.masked = 'true';
      $('profile-answer-hidden').value = sa;
    } else {
      $('profile-answer-display').value = '未设置';
      $('profile-answer-display').dataset.masked = 'false';
      $('profile-answer-hidden').value = '';
    }

    const cfg = await fetch(`${BASE}/config`).then((res) => safeJson(res));
    requireEmailVerification = cfg.requireEmailVerification;
    if (!requireEmailVerification) {
      $('btn-save-email').style.display = 'none';
      $('profile-email').style.display = 'none';
      const emailLabel = $('profile-email').previousElementSibling;
      if (emailLabel && emailLabel.tagName === 'LABEL') emailLabel.style.display = 'none';
    }
    load2FAStatus();
  }

  async function load2FAStatus() {
    const r = await fetch(`${BASE}/user/2fa/status`, {
      headers: { 'X-CSRF-Token': getCookie('csrf_token') }
    }).then((res) => safeJson(res));
    const enabled = r.enabled;
    $('2fa-status-display').innerHTML = enabled
      ? '<span style="color:#059669; font-weight:600;">已开启</span> — 登录时需要动态验证码'
      : '<span style="color:#9ca3af;">未开启</span>';
    $('2fa-enable-section').style.display = enabled ? 'none' : '';
    $('2fa-disable-section').style.display = enabled ? '' : 'none';
    $('2fa-verify-section').style.display = 'none';
    pendingSecret = null;
    pendingRecoveryCodes = null;
  }

  $('btn-enable-2fa').onclick = async () => {
    const r = await postJson(`${BASE}/user/2fa/enable`, {});
    if (r.status === 200 && r.data.secret) {
      pendingSecret = r.data.secret;
      pendingRecoveryCodes = r.data.recoveryCodes;
      if (r.data.qrcode) {
        $('2fa-qr').innerHTML = `<img src="${r.data.qrcode}" alt="QR" style="max-width:220px; border-radius:10px;" />`;
      }
      $('2fa-secret-display').innerHTML = `<div style="background:#f9fafb; padding:12px; border-radius:8px; line-height:1.6;"><b>密钥：</b>${r.data.secret}</div>`;
      $('2fa-recovery-codes').style.display = 'block';
      $('2fa-recovery-list').textContent = r.data.recoveryCodes.join('  ');
      $('2fa-verify-section').style.display = '';
      $('2fa-enable-section').style.display = 'none';
    } else {
      msg('2fa-verify-msg', r.data.error || '生成失败', false);
    }
  };

  $('btn-verify-2fa').onclick = async () => {
    const token = $('2fa-token-input').value.trim();
    if (!token || token.length !== 6) return msg('2fa-verify-msg', '请输入6位验证码', false);
    const r = await postJson(`${BASE}/user/2fa/verify`, { token });
    if (r.status === 200 && r.data.verified) {
      msg('2fa-verify-msg', '2FA 已成功开启', true);
      load2FAStatus();
    } else {
      msg('2fa-verify-msg', r.data.error || '验证码错误', false);
    }
  };

  $('btn-disable-2fa').onclick = async () => {
    const token = $('2fa-disable-token').value.trim();
    if (!token || token.length !== 6) return msg('2fa-disable-msg', '请输入6位验证码', false);
    if (!confirm('确定要关闭 2FA？')) return;
    const r = await postJson(`${BASE}/user/2fa/disable`, { token });
    if (r.status === 200) {
      msg('2fa-disable-msg', '2FA 已关闭', true);
      load2FAStatus();
    } else {
      msg('2fa-disable-msg', r.data.error || '验证码错误', false);
    }
  };

  $('btn-save-email').onclick = async () => {
    const email = $('profile-email').value.trim();
    if (!email) return msg('email-msg', '请输入邮箱', false);
    const r = await putJson(`${BASE}/user/profile`, { email });
    if (r.status === 200) {
      msg('email-msg', '邮箱已更新', true);
      $('profile-email-hidden').value = email;
      $('profile-email-display').value = '••••••••';
      $('profile-email-display').dataset.masked = 'true';
      $('profile-email').value = '';
    } else {
      msg('email-msg', r.data.errors?.join(', ') || r.data.error || '更新失败', false);
    }
  };

  $('btn-save-question').onclick = async () => {
    const q = $('profile-question').value;
    const a = $('profile-answer').value.trim();
    const r = await putJson(`${BASE}/user/profile`, { securityQuestion: q, securityAnswer: a });
    if (r.status === 200) {
      msg('question-msg', '密保已更新', true);
      $('profile-question-hidden').value = q;
      $('profile-question-display').value = '••••••••';
      $('profile-question-display').dataset.masked = 'true';
      $('profile-answer-hidden').value = a;
      $('profile-answer-display').value = '••••••••';
      $('profile-answer-display').dataset.masked = 'true';
      $('profile-answer').value = '';
    } else {
      msg('question-msg', r.data.error || '更新失败', false);
    }
  };

  $('btn-save-password').onclick = async () => {
    const oldPw = $('old-password').value;
    const newPw = $('new-password').value;
    const newPw2 = $('new-password2').value;
    if (!oldPw || !newPw) return msg('password-msg', '请填写所有密码字段', false);
    if (newPw !== newPw2) return msg('password-msg', '两次输入的新密码不一致', false);
    const r = await putJson(`${BASE}/user/password`, { oldPassword: oldPw, newPassword: newPw });
    if (r.status === 200) {
      msg('password-msg', '密码已修改', true);
      $('old-password').value = '';
      $('new-password').value = '';
      $('new-password2').value = '';
    } else {
      msg('password-msg', r.data.errors?.join(', ') || r.data.error || '修改失败', false);
    }
  };

  $('btn-delete-account').onclick = async () => {
    const pw = $('delete-password').value;
    if (!pw) return msg('delete-msg', '请输入密码确认', false);
    if (!confirm('确定要注销账户？此操作不可恢复！')) return;
    const r = await delJson(`${BASE}/user/account`);
    if (r.status === 200) {
      window.location.href = '/login.html';
    } else {
      msg('delete-msg', r.data.error || '注销失败', false);
    }
  };

  // ===================== 30s 倒计时 =====================
  function startCountdown() {
    setInterval(async () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      const pct = (remaining / 30) * 100;
      const urgent = remaining <= 5;
      document.querySelectorAll('.timer-bar .fill').forEach((el) => {
        el.style.width = pct + '%';
        el.classList.toggle('urgent', urgent);
      });
      document.querySelectorAll('.meta span:first-child').forEach((el) => {
        el.textContent = remaining + 's 后刷新';
      });
      const tag = $('countdown-tag');
      if (tag) tag.textContent = remaining + 's';
      if (remaining === 1) await loadAccounts();
    }, 1000);
  }

  // ===================== 全局操作 =====================
  window.dashboardApp = {
    copyCode(code) { if (code) navigator.clipboard.writeText(code).then(() => toast('已复制')); },
    async revokeTOTP(userId) {
      if (!confirm(`确定要撤销 ${userId} 的 TOTP？`)) return;
      const r = await delJson(`${BASE}/totp/${userId}`);
      if (r.status === 200) {
        toast('已撤销');
        accounts = accounts.filter((a) => a.userId !== userId);
        loadAccounts();
      }
    },
    async deleteKey(id) {
      if (!confirm('确定删除此 API 密钥？')) return;
      await delJson(`${BASE}/totp/apikey/${id}`);
      toast('已删除');
      loadApiKeys();
    },
    async changeRole(userId, role) {
      const r = await putJson(`${BASE}/admin/accounts/${userId}`, { role });
      if (r.status === 200) toast('角色已更新');
      else toast(r.data.error || '更新失败');
    },
    async deleteAccount(userId) {
      if (!confirm(`确定要删除 ${userId}？此操作不可恢复！`)) return;
      const r = await delJson(`${BASE}/admin/accounts/${userId}`);
      if (r.status === 200) {
        toast('已删除');
        loadAdminAccounts();
      } else toast(r.data.error || '删除失败');
    },
    goAdminPage(p) { adminPage = p; loadAdminAccounts(); }
  };

  // ===================== 初始化 =====================
  (async () => {
    const ok = await checkAuth();
    if (!ok) return;
    loadAccountList();
    loadApiKeys();
    startCountdown();
  })();
})();
