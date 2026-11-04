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
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '671328811115-3c30cuorrj44lc46948c2bem2ieug36b.apps.googleusercontent.com';
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
);
CREATE TABLE IF NOT EXISTS backup_codes (
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  used_at INTEGER,
  PRIMARY KEY (user_id, code_hash)
);
CREATE TABLE IF NOT EXISTS security_q (
  user_id INTEGER PRIMARY KEY,
  question TEXT NOT NULL,
  answer_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rec_fails (
  email TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS letters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  stamp_img TEXT,
  created_at INTEGER NOT NULL,
  read_at INTEGER
);`;

/* ---------- recovery helpers (backup codes + security question) ---------- */
const CODE_ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function newBackupCode() {
  let s = '';
  for (let i = 0; i < 8; i++) s += CODE_ALPHA[crypto.randomInt(CODE_ALPHA.length)];
  return s.slice(0, 4) + '-' + s.slice(4);
}
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const normAnswer = a => String(a || '').trim().toLowerCase().replace(/\s+/g, ' ');
async function recFailHit(email) {
  const t = now();
  const f = await one('SELECT * FROM rec_fails WHERE email=?', [email]);
  const same = f && (t - Number(f.window_start) < 3600 * 1000);
  await run(`INSERT INTO rec_fails (email, count, window_start) VALUES (?,?,?)
    ON CONFLICT(email) DO UPDATE SET count=excluded.count, window_start=excluded.window_start`,
    [email, same ? Number(f.count) + 1 : 1, same ? Number(f.window_start) : t]);
}
async function recFailCount(email) {
  const f = await one('SELECT * FROM rec_fails WHERE email=?', [email]);
  if (f && now() - Number(f.window_start) < 3600 * 1000) return Number(f.count);
  return 0;
}
/* ---------- usernames (Instagram-style: ek username, ek hi user) ---------- */
const normUsername = u => String(u || '').trim().replace(/^@+/, '').toLowerCase();
const validUsername = u => /^[a-z][a-z0-9._]{2,19}$/.test(u) && !u.includes('..') && !u.endsWith('.');
async function usernameTaken(u, exceptId) {
  const r = await one('SELECT id FROM users WHERE username=?', [u]);
  return !!r && Number(r.id) !== Number(exceptId || 0);
}
function usernameBase(email, name) {
  let b = normUsername((email || '').split('@')[0] || '');
  if (!validUsername(b)) b = normUsername((name || '').replace(/\s+/g, '.'));
  if (!validUsername(b)) b = 'user' + b.replace(/[^a-z0-9._]/g, '');
  if (!validUsername(b)) b = 'snapmark.user';
  return b.slice(0, 20);
}
async function backfillUsernames() {
  const rows = await allRows('SELECT id, name, email FROM users WHERE username IS NULL OR username=?', ['']);
  for (const u of rows) {
    let base = usernameBase(u.email, u.name), cand = base, n = 1;
    while (await usernameTaken(cand, u.id)) { n++; cand = (base.slice(0, 17) + n).slice(0, 20); }
    await run('UPDATE users SET username=? WHERE id=?', [cand, u.id]);
  }
}

let schemaReady = null;
function ensureSchema() {
  if (!schemaReady) schemaReady = (async () => {
    await db.executeMultiple(SCHEMA);
    try { await db.execute('ALTER TABLE users ADD COLUMN username TEXT'); } catch (e) { /* column already there */ }
    try { await db.execute("ALTER TABLE letters ADD COLUMN paper TEXT DEFAULT 'plain'"); } catch (e) { /* column already there */ }
    try { await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)'); } catch (e) {}
    try { await db.execute("ALTER TABLE users ADD COLUMN provider TEXT DEFAULT 'email'"); } catch (e) {}
    try { await db.execute('ALTER TABLE users ADD COLUMN wa_cred TEXT'); } catch (e) {}
    try { await db.execute('CREATE TABLE IF NOT EXISTS wa_chal (k TEXT PRIMARY KEY, challenge TEXT, exp INTEGER)'); } catch (e) {}
    try { await db.execute('ALTER TABLE users ADD COLUMN invite_token TEXT'); } catch (e) {}
    try { await db.execute('CREATE TABLE IF NOT EXISTS invite_claims (id INTEGER PRIMARY KEY AUTOINCREMENT, inviter INTEGER, claimer INTEGER UNIQUE, ts INTEGER)'); } catch (e) {}
    await backfillUsernames();
  })().catch(e => { schemaReady = null; throw e; });
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
    if (t - Number(row.sent_at) < 30 * 1000) return { ok: false, error: 'Please wait 30 seconds before requesting a new code' };
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
/* ---------- WebAuthn (fingerprint / face passkey) ---------- */
const b64url = buf => Buffer.from(buf).toString('base64url');
const b64urlToBuf = str => Buffer.from(String(str || ''), 'base64url');
function cborDecode(buf, off) {
  const b = buf[off]; const mt = b >> 5; let ai = b & 31; let pos = off + 1; let len;
  if (ai < 24) len = ai;
  else if (ai === 24) { len = buf[pos]; pos += 1; }
  else if (ai === 25) { len = buf.readUInt16BE(pos); pos += 2; }
  else if (ai === 26) { len = buf.readUInt32BE(pos); pos += 4; }
  else if (ai === 27) { len = Number(buf.readBigUInt64BE(pos)); pos += 8; }
  else throw new Error('cbor ai');
  if (mt === 0) return [len, pos];
  if (mt === 1) return [-1 - len, pos];
  if (mt === 2) return [buf.subarray(pos, pos + len), pos + len];
  if (mt === 3) return [buf.toString('utf8', pos, pos + len), pos + len];
  if (mt === 4) { const arr = []; for (let i = 0; i < len; i++) { const [v, np] = cborDecode(buf, pos); arr.push(v); pos = np; } return [arr, pos]; }
  if (mt === 5) { const obj = {}; for (let i = 0; i < len; i++) { const [k, np1] = cborDecode(buf, pos); const [v, np2] = cborDecode(buf, np1); obj[k] = v; pos = np2; } return [obj, pos]; }
  if (mt === 7) { if (ai === 20) return [true, pos]; if (ai === 21) return [false, pos]; if (ai === 22) return [null, pos]; if (ai === 23) return [undefined, pos]; throw new Error('cbor mt7'); }
  throw new Error('cbor mt');
}
function parseAuthData(buf) {
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  let off = 37, attested = null;
  if (flags & 0x40) {
    off += 16;
    const credIdLen = buf.readUInt16BE(off); off += 2;
    const credId = buf.subarray(off, off + credIdLen); off += credIdLen;
    const [coseKey] = cborDecode(buf, off);
    attested = { credId, coseKey };
  }
  return { rpIdHash, flags, signCount, attested };
}
async function saveChal(k, challenge) {
  await run('INSERT INTO wa_chal (k, challenge, exp) VALUES (?,?,?) ON CONFLICT(k) DO UPDATE SET challenge=excluded.challenge, exp=excluded.exp', [k, challenge, now() + 5 * 60 * 1000]);
}
async function takeChal(k) {
  const row = await one('SELECT * FROM wa_chal WHERE k=?', [k]);
  if (!row) return null;
  await run('DELETE FROM wa_chal WHERE k=?', [k]);
  return Number(row.exp) < now() ? null : row.challenge;
}

const actions = {
  async requestSignupOtp({ email }) {
    email = (email || '').trim().toLowerCase();
    if (!validEmail(email)) return { ok: false, error: 'Enter a valid email address' };
    if (isTempMail(email)) return { ok: false, error: 'Disposable emails are not allowed — please use your real email' };
    if (await one('SELECT id FROM users WHERE email=?', [email]))
      return { ok: false, error: 'An account with this email already exists — please log in' };
    return issueOtp(email, 'signup');
  },

  async checkUsername({ username }) {
    const u = normUsername(username);
    if (!validUsername(u)) return { ok: true, available: false, error: 'Use 3-20 characters: letters, numbers, dot or underscore, starting with a letter' };
    return { ok: true, available: !(await usernameTaken(u)) };
  },

  async register({ name, email, password, code, username }) {
    name = (name || '').trim();
    email = (email || '').trim().toLowerCase();
    const uname = normUsername(username);
    if (name.length < 2) name = uname ? uname[0].toUpperCase() + uname.slice(1) : email.split('@')[0];
    if (!validUsername(uname)) return { ok: false, error: 'Please choose a valid username (3-20 characters: letters, numbers, dot or underscore)' };
    if (await usernameTaken(uname)) return { ok: false, error: 'That username is taken — please try another' };
    if (!validEmail(email) || isTempMail(email)) return { ok: false, error: 'Enter a valid email address' };
    if ((password || '').length < 8) return { ok: false, error: 'Password must be at least 8 characters' };
    if (await one('SELECT id FROM users WHERE email=?', [email]))
      return { ok: false, error: 'An account with this email already exists — please log in' };
    const err = await checkOtp(email, 'signup', code);
    if (err) return { ok: false, error: err };
    const info = await run('INSERT INTO users (name, email, pass_hash, created_at, username) VALUES (?,?,?,?,?)',
      [name, email, hashPassword(password), now(), uname]);
    const user = { id: Number(info.lastInsertRowid), name, email, username: uname };
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
    if ((newPassword || '').length < 8) return { ok: false, error: 'Password must be at least 8 characters' };
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
    if (user && user.provider === 'google')
      return { ok: false, error: 'This account uses Google sign-in — please use the Google button below' };
    if (!user || !verifyPassword(password || '', user.pass_hash)) {
      const sameWindow = fail && (t - Number(fail.window_start) < 3600 * 1000);
      await run(`INSERT INTO login_fails (email, count, window_start) VALUES (?,?,?)
        ON CONFLICT(email) DO UPDATE SET count=excluded.count, window_start=excluded.window_start`,
        [email, sameWindow ? Number(fail.count) + 1 : 1, sameWindow ? Number(fail.window_start) : t]);
      return { ok: false, error: 'Incorrect email or password' };
    }
    await run('DELETE FROM login_fails WHERE email=?', [email]);
    const pub = { id: Number(user.id), name: user.name, email: user.email, username: user.username || null };
    return { ok: true, token: makeToken(pub), user: pub };
  },

  async googleAuth({ idToken }) {
    if (!GOOGLE_CLIENT_ID) return { ok: false, error: 'Google sign-in is not set up yet' };
    if (!idToken) return { ok: false, error: 'Google sign-in failed — please try again' };
    let info;
    try {
      const resp = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
      info = await resp.json();
    } catch (e) { return { ok: false, error: 'Could not verify with Google — check your connection' }; }
    if (!info || info.aud !== GOOGLE_CLIENT_ID || !info.email || info.email_verified !== 'true')
      return { ok: false, error: 'Google sign-in could not be verified' };
    const email = String(info.email).toLowerCase();
    if (isTempMail(email)) return { ok: false, error: 'Disposable emails are not allowed — please use your real email' };
    let user = await one('SELECT id, name, email, username FROM users WHERE email=?', [email]);
    let isNew = false;
    if (!user) {
      let uname = normUsername(String(email.split('@')[0] || ''));
      if (!validUsername(uname)) uname = 'user' + crypto.randomInt(1000, 9999);
      let cand = uname, n = 1;
      while (await usernameTaken(cand)) { n++; cand = (uname.slice(0, 17) + n).slice(0, 20); }
      uname = cand;
      const gname = (info.name || '').trim() || (uname[0].toUpperCase() + uname.slice(1));
      const ins = await run('INSERT INTO users (name, email, pass_hash, created_at, username, provider) VALUES (?,?,?,?,?,?)',
        [gname, email, hashPassword(crypto.randomBytes(24).toString('hex')), now(), uname, 'google']);
      const uid = Number(ins.lastInsertRowid);
      await run('INSERT INTO user_data (user_id, colls) VALUES (?,?)', [uid, JSON.stringify(['My Collection'])]);
      user = { id: uid, name: gname, email, username: uname };
      isNew = true;
    }
    const pub = { id: Number(user.id), name: user.name, email: user.email, username: user.username || null };
    return { ok: true, token: makeToken(pub), user: pub, isNew };
  },

  async me({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Session expired — please log in again' };
    const user = await one('SELECT id, name, email, username FROM users WHERE id=?', [data.uid]);
    if (!user) return { ok: false, error: 'User not found' };
    return { ok: true, user: { id: Number(user.id), name: user.name, email: user.email, username: user.username || null } };
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
  },

  /* ----- backup codes + security question (Scribly-style recovery) ----- */
  async backupStatus({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const rows = await allRows('SELECT used_at FROM backup_codes WHERE user_id=?', [data.uid]);
    const sq = await one('SELECT question FROM security_q WHERE user_id=?', [data.uid]);
    return { ok: true, total: rows.length, remaining: rows.filter(r => !r.used_at).length,
      hasQuestion: !!sq, question: sq ? sq.question : null };
  },

  async generateBackupCodes({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    await run('DELETE FROM backup_codes WHERE user_id=?', [data.uid]);
    const codes = [];
    for (let i = 0; i < 8; i++) {
      const c = newBackupCode();
      codes.push(c);
      await run('INSERT INTO backup_codes (user_id, code_hash) VALUES (?,?)', [data.uid, sha(normCode(c))]);
    }
    return { ok: true, codes };
  },

  async loginWithBackupCode({ email, code }) {
    email = (email || '').trim().toLowerCase();
    if (await recFailCount(email) >= 10) return { ok: false, error: 'Too many failed attempts — please try again in an hour' };
    const user = await one('SELECT * FROM users WHERE email=?', [email]);
    const row = user && await one('SELECT * FROM backup_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL',
      [user.id, sha(normCode(code))]);
    if (!row) { await recFailHit(email); return { ok: false, error: 'That backup code is not valid or was already used' }; }
    await run('UPDATE backup_codes SET used_at=? WHERE user_id=? AND code_hash=?', [now(), user.id, sha(normCode(code))]);
    await run('DELETE FROM rec_fails WHERE email=?', [email]);
    const pub = { id: Number(user.id), name: user.name, email: user.email, username: user.username || null };
    return { ok: true, token: makeToken(pub), user: pub };
  },

  async resetWithBackupCode({ email, code, newPassword }) {
    email = (email || '').trim().toLowerCase();
    if ((newPassword || '').length < 8) return { ok: false, error: 'Password must be at least 8 characters' };
    if (await recFailCount(email) >= 10) return { ok: false, error: 'Too many failed attempts — please try again in an hour' };
    const user = await one('SELECT * FROM users WHERE email=?', [email]);
    const row = user && await one('SELECT * FROM backup_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL',
      [user.id, sha(normCode(code))]);
    if (!row) { await recFailHit(email); return { ok: false, error: 'That backup code is not valid or was already used' }; }
    await run('UPDATE backup_codes SET used_at=? WHERE user_id=? AND code_hash=?', [now(), user.id, sha(normCode(code))]);
    await run('UPDATE users SET pass_hash=? WHERE email=?', [hashPassword(newPassword), email]);
    await run('DELETE FROM login_fails WHERE email=?', [email]);
    await run('DELETE FROM rec_fails WHERE email=?', [email]);
    return { ok: true, message: 'Password changed — log in with your new password' };
  },

  async setSecurityQuestion({ token, question, answer, currentPassword }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    question = (question || '').trim();
    if (question.length < 8) return { ok: false, error: 'Please choose a security question' };
    if (normAnswer(answer).length < 2) return { ok: false, error: 'Please enter your answer' };
    const user = await one('SELECT * FROM users WHERE id=?', [data.uid]);
    if (!user || !verifyPassword(currentPassword || '', user.pass_hash))
      return { ok: false, error: 'Current password is incorrect' };
    await run(`INSERT INTO security_q (user_id, question, answer_hash) VALUES (?,?,?)
      ON CONFLICT(user_id) DO UPDATE SET question=excluded.question, answer_hash=excluded.answer_hash`,
      [data.uid, question, sha(normAnswer(answer))]);
    return { ok: true };
  },

  async securityQuestion({ email }) {
    email = (email || '').trim().toLowerCase();
    const user = await one('SELECT id FROM users WHERE email=?', [email]);
    if (!user) return { ok: false, error: 'No account found for this email' };
    const sq = await one('SELECT question FROM security_q WHERE user_id=?', [user.id]);
    if (!sq) return { ok: false, error: 'No security question is set on this account — use an email code or a backup code instead' };
    return { ok: true, question: sq.question };
  },

  async resetWithAnswer({ email, answer, newPassword }) {
    email = (email || '').trim().toLowerCase();
    if ((newPassword || '').length < 8) return { ok: false, error: 'Password must be at least 8 characters' };
    if (await recFailCount(email) >= 10) return { ok: false, error: 'Too many failed attempts — please try again in an hour' };
    const user = await one('SELECT id FROM users WHERE email=?', [email]);
    const sq = user && await one('SELECT * FROM security_q WHERE user_id=?', [user.id]);
    if (!sq) return { ok: false, error: 'No security question is set on this account' };
    if (sha(normAnswer(answer)) !== sq.answer_hash) {
      await recFailHit(email);
      return { ok: false, error: 'That answer does not match — please try again' };
    }
    await run('UPDATE users SET pass_hash=? WHERE email=?', [hashPassword(newPassword), email]);
    await run('DELETE FROM login_fails WHERE email=?', [email]);
    await run('DELETE FROM rec_fails WHERE email=?', [email]);
    return { ok: true, message: 'Password changed — log in with your new password' };
  },

  async changePassword({ token, currentPassword, newPassword }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    if ((newPassword || '').length < 8) return { ok: false, error: 'Password must be at least 8 characters' };
    const user = await one('SELECT * FROM users WHERE id=?', [data.uid]);
    if (!user || !verifyPassword(currentPassword || '', user.pass_hash))
      return { ok: false, error: 'Current password is incorrect' };
    await run('UPDATE users SET pass_hash=? WHERE id=?', [hashPassword(newPassword), data.uid]);
    return { ok: true };
  },

  /* ----- usernames + letters (asli delivery, server par) ----- */
  async inviteLink({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const u = await one('SELECT id, invite_token FROM users WHERE id=?', [data.uid]);
    let t = u && u.invite_token;
    if (!t) { t = require('crypto').randomBytes(14).toString('hex'); await run('UPDATE users SET invite_token=? WHERE id=?', [t, data.uid]); }
    const c = await one('SELECT COUNT(*) AS n FROM invite_claims WHERE inviter=?', [data.uid]);
    return { ok: true, inviteToken: t, joined: c ? Number(c.n) : 0 };
  },
  async inviteInfo({ inviteToken }) {
    if (!inviteToken) return { ok: false };
    const u = await one('SELECT username FROM users WHERE invite_token=?', [String(inviteToken).slice(0, 64)]);
    if (!u) return { ok: false };
    return { ok: true, username: u.username };
  },
  async claimInvite({ token, inviteToken }) {
    const data = readToken(token);
    if (!data || !inviteToken) return { ok: false };
    const inv = await one('SELECT id, username FROM users WHERE invite_token=?', [String(inviteToken).slice(0, 64)]);
    if (!inv || inv.id === data.uid) return { ok: false };
    await run('INSERT OR IGNORE INTO invite_claims (inviter, claimer, ts) VALUES (?,?,?)', [inv.id, data.uid, Date.now()]);
    return { ok: true, inviter: inv.username };
  },
  async setName({ token, name }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    name = (name || '').trim().replace(/\s+/g, ' ');
    if (name.length < 2 || name.length > 50) return { ok: false, error: 'Please enter your name (2-50 characters)' };
    await run('UPDATE users SET name=? WHERE id=?', [name, data.uid]);
    return { ok: true, name };
  },

  async webauthnRegOptions({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const user = await one('SELECT id, name, email FROM users WHERE id=?', [data.uid]);
    if (!user) return { ok: false, error: 'User not found' };
    const challenge = b64url(crypto.randomBytes(32));
    await saveChal('reg:' + user.id, challenge);
    return { ok: true, options: { challenge, user: { id: b64url(Buffer.from(String(user.id))), name: user.email, displayName: user.name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
      attestation: 'none', timeout: 60000 } };
  },

  async webauthnRegister({ token, cred }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const chal = await takeChal('reg:' + data.uid);
    if (!chal) return { ok: false, error: 'Session expired — please try again' };
    try {
      const clientData = JSON.parse(b64urlToBuf(cred.response.clientDataJSON).toString('utf8'));
      if (clientData.type !== 'webauthn.create' || clientData.challenge !== chal) return { ok: false, error: 'Verification failed' };
      const [att] = cborDecode(b64urlToBuf(cred.response.attestationObject), 0);
      if (att.fmt !== 'none') return { ok: false, error: 'Unsupported authenticator type' };
      const auth = parseAuthData(Buffer.from(att.authData));
      const rpHash = crypto.createHash('sha256').update(new URL(clientData.origin).hostname).digest();
      if (!auth.rpIdHash.equals(rpHash) || !auth.attested) return { ok: false, error: 'Verification failed' };
      const cose = auth.attested.coseKey;
      const jwk = { kty: 'EC', crv: 'P-256', x: b64url(cose['-2']), y: b64url(cose['-3']) };
      const credId = b64url(auth.attested.credId);
      await run('UPDATE users SET wa_cred=? WHERE id=?', [JSON.stringify({ credId, jwk, counter: auth.signCount }), data.uid]);
      return { ok: true };
    } catch (e) { return { ok: false, error: 'Could not enable fingerprint — please try again' }; }
  },

  async webauthnStatus({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const user = await one('SELECT wa_cred FROM users WHERE id=?', [data.uid]);
    return { ok: true, enabled: !!(user && user.wa_cred) };
  },

  async webauthnDisable({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    await run('UPDATE users SET wa_cred=NULL WHERE id=?', [data.uid]);
    return { ok: true };
  },

  async webauthnAuthOptions({ email }) {
    email = (email || '').trim().toLowerCase();
    const user = await one('SELECT id, wa_cred FROM users WHERE email=?', [email]);
    if (!user || !user.wa_cred) return { ok: false, error: 'Fingerprint is not enabled for this account' };
    const wc = JSON.parse(user.wa_cred);
    const challenge = b64url(crypto.randomBytes(32));
    await saveChal('auth:' + email, challenge);
    return { ok: true, options: { challenge, allowCredentials: [{ type: 'public-key', id: wc.credId }], userVerification: 'required', timeout: 60000 } };
  },

  async webauthnAuth({ email, cred }) {
    email = (email || '').trim().toLowerCase();
    const user = await one('SELECT * FROM users WHERE email=?', [email]);
    if (!user || !user.wa_cred) return { ok: false, error: 'Fingerprint is not enabled for this account' };
    const wc = JSON.parse(user.wa_cred);
    const chal = await takeChal('auth:' + email);
    if (!chal) return { ok: false, error: 'Session expired — please try again' };
    try {
      if (!cred || cred.id !== wc.credId) return { ok: false, error: 'Verification failed' };
      const clientDataRaw = b64urlToBuf(cred.response.clientDataJSON);
      const clientData = JSON.parse(clientDataRaw.toString('utf8'));
      if (clientData.type !== 'webauthn.get' || clientData.challenge !== chal) return { ok: false, error: 'Verification failed' };
      const authData = b64urlToBuf(cred.response.authenticatorData);
      const rpHash = crypto.createHash('sha256').update(new URL(clientData.origin).hostname).digest();
      if (!authData.subarray(0, 32).equals(rpHash)) return { ok: false, error: 'Verification failed' };
      const signCount = authData.readUInt32BE(33);
      const clientHash = crypto.createHash('sha256').update(clientDataRaw).digest();
      const signed = Buffer.concat([authData, clientHash]);
      const key = crypto.createPublicKey({ key: wc.jwk, format: 'jwk' });
      if (!crypto.verify('sha256', signed, key, b64urlToBuf(cred.response.signature)))
        return { ok: false, error: 'Verification failed' };
      if (wc.counter && signCount && signCount <= wc.counter) return { ok: false, error: 'Verification failed' };
      wc.counter = signCount;
      await run('UPDATE users SET wa_cred=? WHERE id=?', [JSON.stringify(wc), user.id]);
      const pub = { id: Number(user.id), name: user.name, email: user.email, username: user.username || null };
      return { ok: true, token: makeToken(pub), user: pub };
    } catch (e) { return { ok: false, error: 'Fingerprint sign-in failed — please use your password' }; }
  },

  async setUsername({ token, username }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const u = normUsername(username);
    if (!validUsername(u)) return { ok: false, error: 'Use 3-20 characters: letters, numbers, dot or underscore, starting with a letter' };
    if (await usernameTaken(u, data.uid)) return { ok: false, error: 'That username is taken — please try another' };
    await run('UPDATE users SET username=? WHERE id=?', [u, data.uid]);
    return { ok: true, username: u };
  },

  async searchUsers({ token, q }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const s = normUsername(q);
    if (s.length < 2) return { ok: true, users: [] };
    const rows = await allRows(
      'SELECT username, name FROM users WHERE id<>? AND username IS NOT NULL AND (username LIKE ? OR LOWER(name) LIKE ?) ORDER BY username LIMIT 6',
      [data.uid, s + '%', '%' + String(q || '').trim().toLowerCase() + '%']);
    return { ok: true, users: rows.map(r => ({ username: r.username, name: r.name })) };
  },

  async sendLetter({ token, to, body, stampImg, paper }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const uname = normUsername(to);
    const text = String(body || '').trim();
    if (!text) return { ok: false, error: 'Write a message first' };
    if (text.length > 1000) return { ok: false, error: 'Letter is too long (max 1000 characters)' };
    const recip = await one('SELECT id, username FROM users WHERE username=?', [uname]);
    if (!recip) return { ok: false, error: 'No Snapmark user with @' + uname + ' — check the username and try again' };
    if (Number(recip.id) === Number(data.uid)) return { ok: false, error: 'You cannot send a letter to yourself' };
    const img = typeof stampImg === 'string' && stampImg.startsWith('http') ? stampImg : null;
    const pap = ['plain','ruled','vintage','dots'].includes(paper) ? paper : 'plain';
    await run('INSERT INTO letters (from_id, to_id, body, stamp_img, paper, created_at) VALUES (?,?,?,?,?,?)',
      [data.uid, recip.id, text, img, pap, now()]);
    return { ok: true, to: recip.username };
  },

  async listLetters({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const recv = await allRows(
      `SELECT l.id, l.body, l.stamp_img, l.paper, l.created_at, l.read_at, u.username AS fu, u.name AS fn
       FROM letters l JOIN users u ON u.id=l.from_id WHERE l.to_id=? ORDER BY l.created_at DESC LIMIT 50`, [data.uid]);
    const sent = await allRows(
      `SELECT l.id, l.body, l.stamp_img, l.paper, l.created_at, u.username AS tu, u.name AS tn
       FROM letters l JOIN users u ON u.id=l.to_id WHERE l.from_id=? ORDER BY l.created_at DESC LIMIT 50`, [data.uid]);
    return { ok: true,
      received: recv.map(r => ({ id: Number(r.id), body: r.body, stampImg: r.stamp_img, paper: r.paper || 'plain', ts: Number(r.created_at), read: !!r.read_at, fromUsername: r.fu, fromName: r.fn })),
      sent: sent.map(r => ({ id: Number(r.id), body: r.body, stampImg: r.stamp_img, paper: r.paper || 'plain', ts: Number(r.created_at), toUsername: r.tu, toName: r.tn })) };
  },

  async unreadLetters({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    const rows = await allRows(
      `SELECT l.id, l.body, u.username AS fu FROM letters l JOIN users u ON u.id=l.from_id
       WHERE l.to_id=? AND l.read_at IS NULL ORDER BY l.created_at DESC`, [data.uid]);
    return { ok: true, count: rows.length,
      latest: rows.length ? { id: Number(rows[0].id), fromUsername: rows[0].fu, body: rows[0].body } : null };
  },

  async markLettersRead({ token }) {
    const data = readToken(token);
    if (!data) return { ok: false, error: 'Login required' };
    await run('UPDATE letters SET read_at=? WHERE to_id=? AND read_at IS NULL', [now(), data.uid]);
    return { ok: true };
  }
};

/* ---------- HTTP handler (local server + Vercel function) ---------- */
async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const pathOnly = (req.url || '').split('?')[0];
  if (req.method === 'GET' && (pathOnly === '/health' || pathOnly === '/api/health')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, app: 'snapmark-server' }));
  }
  if (req.method === 'GET' && (pathOnly === '/' || pathOnly === '/index.html')) {
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
