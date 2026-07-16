'use strict';

const crypto = require('crypto');

const NODE_ENV = process.env.NODE_ENV || 'development';

// AES-256-GCM 密钥：生产环境必须来自环境变量
let ENCRYPTION_KEY;
if (process.env.ENCRYPTION_KEY) {
  ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  if (ENCRYPTION_KEY.length !== 32) {
    console.error('ENCRYPTION_KEY 必须是 32 字节的 hex 字符串');
    process.exit(1);
  }
} else if (NODE_ENV === 'production') {
  console.error('生产环境必须通过环境变量 ENCRYPTION_KEY 提供 32 字节 hex 密钥');
  process.exit(1);
} else {
  ENCRYPTION_KEY = crypto.randomBytes(32);
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted + ':' + cipher.getAuthTag().toString('hex');
}

function decrypt(encrypted) {
  const parts = encrypted.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const tag = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// 密码哈希：使用内置 scrypt，无需额外依赖
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(pw, salt, 64);
  return salt.toString('hex') + ':' + derived.toString('hex');
}

function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const derived = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  const expected = Buffer.from(hash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

module.exports = { encrypt, decrypt, sha256, hashPassword, verifyPassword };
