'use strict';

const nodemailer = require('nodemailer');

// 若配置了 SMTP 则使用真实发送，否则进入开发模式（仅打印到控制台）
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined
  });
}

const FROM = process.env.MAIL_FROM || 'no-reply@ryuwebauth.local';

// 开发模式下记录最近发送的验证码，便于本地联调（仅 NODE_ENV!=='production' 可被读取）
const devCodes = {};

function renderTemplate(name, data) {
  if (name === 'verify') {
    return {
      subject: '【RyuWebAuth】请验证你的邮箱',
      text: `你的邮箱验证码是：${data.code}（${data.expiresMin} 分钟内有效，请勿泄露）。`,
      html: `<p>你好，</p><p>你的邮箱验证码是：<b style="font-size:20px;letter-spacing:4px;">${data.code}</b></p><p>该验证码在 ${data.expiresMin} 分钟内有效，请勿告知他人。</p>`
    };
  }
  if (name === 'welcome') {
    return {
      subject: '【RyuWebAuth】注册成功',
      text: `欢迎，${data.username}！你的账户已创建成功。`,
      html: `<p>欢迎 <b>${data.username}</b>，你的账户已创建成功。</p>`
    };
  }
  if (name === 'reset') {
    return {
      subject: '【RyuWebAuth】密码重置验证码',
      text: `你的密码重置验证码是：${data.code}（${data.expiresMin} 分钟内有效）。`,
      html: `<p>你的密码重置验证码是：<b style="font-size:20px;letter-spacing:4px;">${data.code}</b></p><p>${data.expiresMin} 分钟内有效。</p>`
    };
  }
  return { subject: 'RyuWebAuth 通知', text: '', html: '' };
}

// to 支持 string 或 string[]，可同时发送给多个不同厂家的邮箱
async function sendMail({ to, template, data }) {
  const tpl = renderTemplate(template, data);
  const recipients = Array.isArray(to) ? to : [to];

  if (transporter) {
    await transporter.sendMail({
      from: FROM, to: recipients, subject: tpl.subject, text: tpl.text, html: tpl.html
    });
  } else {
    console.log('[EMAIL:MOCK] to=%s subject=%s', recipients.join(','), tpl.subject);
    console.log('[EMAIL:MOCK] ' + tpl.text);
  }

  if (!transporter && (process.env.NODE_ENV || 'development') !== 'production') {
    if (Array.isArray(data.email)) {
      data.email.forEach((e) => { devCodes[e] = data.code; });
    } else if (data.email) {
      devCodes[data.email] = data.code;
    }
  }
  return { sent: true, mock: !transporter };
}

module.exports = { sendMail, renderTemplate, FROM, devCodes };
