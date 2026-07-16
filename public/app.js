// 登录（模拟）+ 两步验证测试页逻辑
(function () {
  'use strict';

  const resultEl = document.getElementById('result');

  function showResult(msg, ok) {
    resultEl.style.display = 'block';
    resultEl.className = ok ? 'ok' : 'err';
    resultEl.textContent = msg;
  }

  // 模拟原有登录成功回调
  async function loginSuccess(userId) {
    // 原有登录逻辑...（此处省略）

    // 注入 2FA 验证
    const tempToken = await window.__2FA.require(userId);

    // 用 tempToken 换取正式 session
    const sessionRes = await fetch('/api/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken })
    });
    const sessionData = await sessionRes.json();
    if (sessionData.success) {
      showResult('登录成功并已通过 2FA！\nuserId: ' + sessionData.userId, true);
    } else {
      showResult('❌ 换取会话失败: ' + (sessionData.error || ''), false);
    }
  }

  document.getElementById('loginBtn').addEventListener('click', async () => {
    const userId = document.getElementById('user').value.trim();
    if (!userId) {
      showResult('请输入用户 ID', false);
      return;
    }
    if (!window.__2FA) {
      showResult(
        '❌ 2FA SDK 未加载。请确认：\n' +
        '1) 服务已启动（npm start）\n' +
        '2) 通过 http://localhost:3000/ 访问本页（不要直接双击打开文件）\n' +
        '3) 若集成到你自己的站点，需在 CSP 的 script-src 中加入 2FA 服务域名',
        false
      );
      return;
    }
    resultEl.style.display = 'none';
    try {
      await loginSuccess(userId);
    } catch (e) {
      showResult('❌ ' + (e.message || e), false);
    }
  });
})();
