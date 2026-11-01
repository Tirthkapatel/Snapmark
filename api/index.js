/* Snapmark Server — auth + stamps sync (Vercel + Turso ready)
   Security mirrors Scribly: signup OTP (email), login = email+password only,
   forgot-password via OTP, scrypt password hashing, OTP hashed at rest,
   rate limits, temp-mail block, HMAC-signed session tokens.
   DB: Turso (libSQL) when TURSO_DATABASE_URL is set; otherwise a local
   libSQL file (server/data/snapmark.db) for development.
   Mail: Gmail SMTP via App Password when SENDER_EMAIL + GMAIL_APP_PASSWORD env set;
   otherwise DEV mode (OTP printed to server console). */
const http = require('node:http');
const crypto = require('node:crypto');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');
const { createClient } = require('@libsql/client');

const PORT = process.env.PORT || 8792;
const SECRET = process.env.SESSION_SECRET || 'dev-secret-change-in-prod';
const SENDER = process.env.SENDER_EMAIL || '';
const APP_PASS = process.env.GMAIL_APP_PASSWORD || '';

const db = process.env.TURSO_DATABASE_URL
  ? createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN })
  : createClient({ url: 'file:' + path.join(__dirname, '..', 'server', 'data', 'snapmark.db') });

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS otps (
  email TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'signup',
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  sent_at INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  sent_count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL,
  PRIMARY KEY (email, purpose)
);
CREATE TABLE IF NOT EXISTS stamps (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  img TEXT NOT NULL,
  label TEXT NOT NULL,
  coll TEXT NOT NULL,
  dk TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_data (
  user_id INTEGER PRIMARY KEY,
  colls TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS login_fails (
  email TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);`;
let schemaReady = null;
function ensureSchema() {
  if (!schemaReady) schemaReady = db.executeMultiple(SCHEMA).catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}
async function one(sql, args = []) { const r = await db.execute({ sql, args }); return r.rows[0]; }
async function allRows(sql, args = []) { const r = await db.execute({ sql, args }); return r.rows; }
async function run(sql, args = []) { const r = await db.execute({ sql, args }); return { lastInsertRowid: r.lastInsertRowid }; }

const TEMP_MAIL = ['tempmail.com','temp-mail.org','10minutemail.com','guerrillamail.com','mailinator.com',
  'yopmail.com','throwaway.email','getnada.com','maildrop.cc','dispostable.com','sharklasers.com',
  'fakeinbox.com','trashmail.com','moakt.com','tempail.com','emailondeck.com','minutemail.com'];
const now = () => Date.now();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
}
function makeToken(user) {
  const payload = Buffer.from(JSON.stringify({ uid: user.id, email: user.email, exp: now() + 7 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function readToken(tok) {
  if (!tok || !tok.includes('.')) return null;
  const [payload, sig] = tok.split('.');
  const expect = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (sig !== expect) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (data.exp < now()) return null;
    return data;
  } catch { return null; }
}
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e || '');
const isTempMail = e => TEMP_MAIL.includes((e.split('@')[1] || '').toLowerCase());

/* ---------- Gmail SMTP (App Password) ---------- */
function smtpSend(to, subject, text) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect(465, 'smtp.gmail.com', { servername: 'smtp.gmail.com' }, () => {
      let step = 0;
      const b64 = s => Buffer.from(s).toString('base64');
      const lines = [
        'EHLO snapmark.app', 'AUTH LOGIN', b64(SENDER), b64(APP_PASS),
        'MAIL FROM:<' + SENDER + '>', 'RCPT TO:<' + to + '>', 'DATA',
        'From: Snapmark <' + SENDER + '>\r\nTo: ' + to + '\r\nSubject: ' + subject + '\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n' + text + '\r\n.',
        'QUIT'
      ];
      let buf = '';
      sock.on('data', d => {
        buf += d.toString();
        if (/\r\n$/.test(buf)) {
          buf = '';
          if (step < lines.length) sock.write(lines[step++] + '\r\n');
          else { sock.end(); resolve(true); }
        }
      });
      sock.on('error', reject);
    });
    sock.on('error', reject);
  });
}
async function sendCodeMail(email, code, purpose) {
  const subject = purpose === 'reset' ? 'Snapmark — password reset code' : 'Snapmark — your signup code';
  const text = 'Hello!\n\nYour Snapmark code is: ' + code + '\nThis code is valid for 10 minutes.\n\nIf you did not request this, please ignore this email.\n\n— Team Snapmark';
  if (SENDER && APP_PASS) { await smtpSend(email, subject, text); return true; }
  console.log('[DEV OTP:' + purpose + '] ' + email + ' -> ' + code);
  return false;
}

/* ---------- OTP engine (shared by signup + reset) ---------- */
async function issueOtp(email, purpose) {
  const row = await one('SELECT * FROM otps WHERE email=? AND purpose=?', [email, purpose]);
  const t = now();
  if (row) {
    if (t - Number(row.sent_at) < 60 * 1000) return { ok: false, error: 'Please wait a minute before requesting a new code' };
    if (t - Number(row.window_start) < 3600 * 1000 && Number(row.sent_count) >= 5)
      return { ok: false, error: 'Too many codes requested — please try again in an hour' };
  }
  const code = String(crypto.randomInt(100000, 1000000));
  const sameWindow = row && (t - Number(row.window_start) < 3600 * 1000);
  await run(`INSERT INTO otps (email, purpose, code_hash, expires_at, sent_at, tries, sent_count, window_start)
    VALUES (?,?,?,?,?,0,?,?) ON CONFLICT(email, purpose) DO UPDATE SET code_hash=excluded.code_hash,
    expires_at=excluded.expires_at, sent_at=excluded.sent_at, tries=0,
    sent_count=excluded.sent_count, window_start=excluded.window_start`,
    [email, purpose, sha(code), t + 10 * 60 * 1000, t, sameWindow ? Number(row.sent_count) + 1 : 1, sameWindow ? Number(row.window_start) : t]);
  const mailed = await sendCodeMail(email, code, purpose);
  return { ok: true, mailed, message: mailed ? 'Code sent to your email' : 'Email verification is not set up yet' };
}
async function checkOtp(email, purpose, code) {
  const row = await one('SELECT * FROM otps WHERE email=? AND purpose=?', [email, purpose]);
  if (!row) return 'Request a code first';
  if (Number(row.expires_at) < now()) return 'Code expired — request a new one';
  if (Number(row.tries) >= 5) return 'Too many wrong attempts — request a new code';
  if (sha(String(code || '')) !== row.code_hash) {
    await run('UPDATE otps SET tries=tries+1 WHERE email=? AND purpose=?', [email, purpose]);
    return 'Incorrect code — please check and try again';
  }
  await run('DELETE FROM otps WHERE email=? AND purpose=?', [email, purpose]);
  return null;
}

/* ---------- actions ---------- */
const actions = {
  async requestSignupOtp({ email }) {
    email = (email || '').trim().toLowerCase();
    if (!validEmail(email)) return { ok: false, error: 'Enter a valid email address' };
    if (isTempMail(email)) return { ok: false, error: 'Disposable emails are not allowed — please use your real email' };
    if (await one('SELECT id FROM users WHERE email=?', [email]))
      return { ok: false, error: 'An account with this email already exists — please log in' };
    return issueOtp(email, 'signup');
  },

  async register({ name, email, password, code }) {
    name = (name || '').trim();
    email = (email || '').trim().toLowerCase();
    if (name.length < 2) return { ok: false, error: 'Please enter your name' };
    if (!validEmail(email) || isTempMail(email)) return { ok: false, error: 'Enter a valid email address' };
    if ((password || '').length < 6) return { ok: false, error: 'Password must be at least 6 characters' };
    if (await one('SELECT id FROM users WHERE email=?', [email]))
      return { ok: false, error: 'An account with this email already exists — please log in' };
    const err = await checkOtp(email, 'signup', code);
    if (err) return { ok: false, error: err };
    const info = await run('INSERT INTO users (name, email, pass_hash, created_at) VALUES (?,?,?,?)',
      [name, email, hashPassword(password), now()]);
    const user = { id: Number(info.lastInsertRowid), name, email };
    await run('INSERT INTO user_data (user_id, colls) VALUES (?,?)', [user.id, JSON.stringify(['My Collection'])]);
    return { ok: true, token: makeToken(user), user };
  },

  async verifyOtp({ email, code, purpose }) {
    email = (email || '').trim().toLowerCase();
    if (!['signup', 'reset'].includes(purpose)) return { ok: false, error: 'Invalid request' };
    const row = await one('SELECT * FROM otps WHERE email=? AND purpose=?', [email, purpose]);
    if (!row) return { ok: false, error: 'Request a code first' };
    if (Number(row.expires_at) < now()) return { ok: false, error: 'Code expired — request a new one' };
    if (Number(row.tries) >= 5) return { ok: false, error: 'Too many wrong attempts — request a new code' };
    if (sha(String(code || '')) !== row.code_hash) {
      await run('UPDATE otps SET tries=tries+1 WHERE email=? AND purpose=?', [email, purpose]);
      return { ok: false, error: 'Incorrect code — please check and try again' };
    }
    return { ok: true };
  },

  async requestResetOtp({ email }) {
    email = (email || '').trim().toLowerCase();
    if (!validEmail(email)) return { ok: false, error: 'Enter a valid email address' };
    if (!await one('SELECT id FROM users WHERE email=?', [email]))
      return { ok: false, error: 'No account found for this email' };
    return issueOtp(email, 'reset');
  },

  async resetPassword({ email, code, newPassword }) {
    email = (email || '').trim().toLowerCase();
    if ((newPassword || '').length < 6) return { ok: false, error: 'Password must be at least 6 characters' };
    const err = await checkOtp(email, 'reset', code);
    if (err) return { ok: false, error: err };
    await run('UPDATE users SET pass_hash=? WHERE email=?', [hashPassword(newPassword), email]);
    await run('DELETE FROM login_fails WHERE email=?', [email]);
    return { ok: true, message: 'Password changed — log in with your new password' };
  },

  async login({ email, password }) {
    email = (email || '').trim().toLowerCase();
    const t = now();
    const fail = await one('SELECT * FROM login_fails WHERE email=?', [email]);
    if (fail && t - Number(fail.window_start) < 3600 * 1000 && Number(fail.count) >= 10)
      return { ok: false, error: 'Too many failed attempts — please try again in an hour' };
    const user = await one('SELECT * FROM users WHERE email=?', [email]);
    if (!user || !verifyPassword(password || '', user.pass_hash)) {
      const sameWindow = fail && (t - Number(fail.window_start) < 3600 * 1000);
      await run(`INSERT INTO login_fails (email, count, window_start) VALUES (?,?,?)
        ON CONFLICT(email) DO UPDATE SET count=excluded.count, window_start=excluded.window_start`,
        [email, sameWindow ? Number(fail.count) + 1 : 1, sameWindow ? Number(fail.window_start) : t]);
      return { ok: false, error: 'Incorrect email or password' };
    }
    await run('DELETE FROM login_fails WHERE email=?', [email]);
    const pub = { id: Number(user.id), name: user.name, email: user.email };
    return { ok: true, token: makeToken(pub), user: pub };
  },

  async me({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Session expired — please log in again' };
    const user = await one('SELECT id, name, email FROM users WHERE id=?', [data.uid]);
    if (!user) return { ok: false, error: 'User not found' };
    return { ok: true, user: { id: Number(user.id), name: user.name, email: user.email } };
  },

  async saveStamp({ token, stamp }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    if (!stamp || !stamp.img) return { ok: false, error: 'Stamp data missing' };
    await run(`INSERT INTO stamps (id, user_id, img, label, coll, dk, created_at) VALUES (?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET img=excluded.img, label=excluded.label, coll=excluded.coll`,
      [String(stamp.id), data.uid, stamp.img, stamp.label || '', stamp.coll || 'My Collection', stamp.dk || '', Number(stamp.id) || now()]);
    return { ok: true };
  },

  async listStamps({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const rows = await allRows('SELECT id, img, label, coll, dk FROM stamps WHERE user_id=? ORDER BY created_at DESC', [data.uid]);
    const ud = await one('SELECT colls FROM user_data WHERE user_id=?', [data.uid]);
    return { ok: true, stamps: rows.map(r => ({ id: isNaN(+r.id) ? r.id : +r.id, img: r.img, label: r.label, coll: r.coll, dk: r.dk, cloud: true })),
      colls: ud ? JSON.parse(ud.colls) : ['My Collection'] };
  },

  async deleteStamp({ token, id }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    await run('DELETE FROM stamps WHERE id=? AND user_id=?', [String(id), data.uid]);
    return { ok: true };
  },

  async setCollections({ token, colls }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    await run('INSERT INTO user_data (user_id, colls) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET colls=excluded.colls',
      [data.uid, JSON.stringify(Array.isArray(colls) ? colls : ['My Collection'])]);
    return { ok: true };
  }
};

/* ---------- HTTP handler (local server + Vercel function) ---------- */
async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/api/health')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, app: 'snapmark-server' }));
  }
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch { res.writeHead(500); return res.end('app file missing'); }
  }
  if (req.method !== 'POST') { res.writeHead(404); return res.end('{}'); }
  let body = '';
  req.on('data', c => { body += c; if (body.length > 8e6) req.destroy(); });
  req.on('end', async () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    try {
      await ensureSchema();
      const { action, ...params } = JSON.parse(body || '{}');
      if (!actions[action]) return res.end(JSON.stringify({ ok: false, error: 'Unknown action' }));
      const out = await actions[action](params);
      res.end(JSON.stringify(out));
    } catch (e) {
      res.end(JSON.stringify({ ok: false, error: 'Server error: ' + e.message }));
    }
  });
}

if (require.main === module) {
  http.createServer(handler).listen(PORT, () =>
    console.log('Snapmark server on :' + PORT + ' (mailer ' + (SENDER && APP_PASS ? 'ON' : 'DEV') + ', db ' + (process.env.TURSO_DATABASE_URL ? 'Turso' : 'local file') + ')'));
}
module.exports = handler;
