'use strict';

// emoji / 颜文字（kaomoji）检测
const EMOJI_RE = /\p{Extended_Pictographic}/u;

// 颜文字特征字符（日文片假名表情、方框线、特殊符号等）
const KAOMOJI_CHARS = /[ヮヵﾂﾉﾟ･ｰ╯╰╮╭└┘├┤┬┴┼─━│┏┓┗┛┣┫┳┻╋◜◝◞◟ᴖᴥᴗᘳᘰ˃˂˄˟ᵕ﹏▰▱◔◕●◉○°∆¨¬×÷‰♡]/;

function hasEmoji(s) {
  return EMOJI_RE.test(s);
}

function hasKaomoji(s) {
  if (KAOMOJI_CHARS.test(s)) return true;
  // 括号包裹的表情序列，例如 (^_^) (>_<) (T_T) \(^o^)/
  if (/\([^)]{0,8}[_^~•·\-=+*<>/\\|][^)]{0,8}\)/.test(s)) return true;
  // 常见 ASCII 颜文字 :-) ;^) xD 等
  if (/[:;][\-^vV]?[\)(\/\\]/.test(s)) return true;
  return false;
}

// 用户名：3-32 位，支持多语言（任意 \p{L}），仅含字母/数字/下划线/点/连字符
function validateUsername(username) {
  const errors = [];
  if (typeof username !== 'string' || username.length < 3 || username.length > 32) {
    errors.push('用户名长度需为 3-32 个字符');
  }
  if (hasEmoji(username)) errors.push('用户名不能包含 emoji');
  if (hasKaomoji(username)) errors.push('用户名不能包含颜文字');
  if (username && !/^[\p{L}\p{N}_.\-]+$/u.test(username)) {
    errors.push('用户名只能包含字母、数字、下划线、点或连字符');
  }
  return { valid: errors.length === 0, errors };
}

// 密码强度明细
function passwordStrength(pw) {
  pw = pw || '';
  return {
    hasLower: /[a-z]/.test(pw),
    hasUpper: /[A-Z]/.test(pw),
    hasSymbol: /[^A-Za-z0-9]/.test(pw),
    hasNum: /[0-9]/.test(pw),
    len: pw.length
  };
}

// 密码：不允许 emoji/颜文字；强制长度>=8。大/小写/符号仅作为“增强安全性”的建议，非必须
function validatePassword(pw) {
  const errors = [];
  const suggestions = [];
  if (typeof pw !== 'string' || pw.length < 8) errors.push('密码长度至少 8 位');
  if (hasEmoji(pw)) errors.push('密码不能包含 emoji');
  if (hasKaomoji(pw)) errors.push('密码不能包含颜文字');
  const s = passwordStrength(pw);
  if (!s.hasLower) suggestions.push('建议包含小写字母');
  if (!s.hasUpper) suggestions.push('建议包含大写字母');
  if (!s.hasSymbol) suggestions.push('建议包含符号（如 !@#$%^&*）');
  return { valid: errors.length === 0, errors, suggestions, strength: s };
}

// 一次性/虚假邮箱域名（可按需扩展）
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
  'trashmail.com', 'yopmail.com', 'temp-mail.org', 'dispostable.com', 'getnada.com'
]);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// 邮箱：格式正确 + 非一次性域名；真实性由“发送验证码并回填”环节保证
function validateEmail(email) {
  const errors = [];
  if (typeof email !== 'string' || !EMAIL_RE.test(email)) {
    errors.push('邮箱格式不正确');
    return { valid: false, errors };
  }
  const domain = email.split('@')[1].toLowerCase();
  if (DISPOSABLE_DOMAINS.has(domain)) errors.push('不支持使用一次性/虚假邮箱');
  return { valid: errors.length === 0, errors, domain };
}

// 年龄：13-120 整数
function validateAge(age) {
  const errors = [];
  const n = Number(age);
  if (!Number.isInteger(n) || n < 13 || n > 120) {
    errors.push('年龄需为 13-120 之间的整数');
  }
  return { valid: errors.length === 0, errors };
}

module.exports = {
  hasEmoji, hasKaomoji,
  validateUsername, validatePassword, passwordStrength,
  validateEmail, validateAge, DISPOSABLE_DOMAINS
};
