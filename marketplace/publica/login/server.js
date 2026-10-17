const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const db = new Database(path.join(__dirname, '../../data.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reset_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 60 }));
app.use(express.static(path.join(__dirname, 'public')));

const hash = t => crypto.createHash('sha256').update(t).digest('hex');
const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const str = v => String(v || '').trim();
const fail = (res, code, error) => res.status(code).json({ error });

function signIn(req, res, id, remember) {
  req.session.regenerate(() => {
    req.session.userId = id;
    req.session.cookie.maxAge = remember ? 7 * 24 * 3600 * 1000 : null;
    res.json({ ok: true });
  });
}

app.post('/api/register', (req, res) => {
  const name = str(req.body.name);
  const email = str(req.body.email).toLowerCase();
  const pw = String(req.body.password || '');
  if (!name || name.length > 60) return fail(res, 400, 'กรุณากรอกชื่อ (ไม่เกิน 60 ตัวอักษร)');
  if (!emailOk(email)) return fail(res, 400, 'รูปแบบอีเมลไม่ถูกต้อง');
  if (pw.length < 8) return fail(res, 400, 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email))
    return fail(res, 409, 'อีเมลนี้ถูกใช้งานแล้ว');
  const info = db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)')
    .run(name, email, bcrypt.hashSync(pw, 10));
  signIn(req, res, info.lastInsertRowid, false);
});

app.post('/api/login', (req, res) => {
  const email = str(req.body.email).toLowerCase();
  const pw = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(pw, u.password_hash))
    return fail(res, 401, 'อีเมลหรือรหัสผ่านไม่ถูกต้อง');
  signIn(req, res, u.id, !!req.body.remember);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return fail(res, 401, 'ยังไม่ได้เข้าสู่ระบบ');
  const u = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.userId);
  if (!u) return fail(res, 401, 'ยังไม่ได้เข้าสู่ระบบ');
  res.json(u);
});

app.post('/api/forgot', (req, res) => {
  const email = str(req.body.email).toLowerCase();
  const u = db.prepare('SELECT id FROM users WHERE email=?').get(email);
  if (u) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO reset_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)')
      .run(u.id, hash(token), Date.now() + 60 * 60 * 1000);
    const link = `${req.protocol}://${req.get('host')}/reset.html?token=${token}`;
    // โหมดพัฒนา: แสดงลิงก์ในเทอร์มินัล (ของจริงให้ส่งทางอีเมลด้วย nodemailer)
    console.log(`\n[ลิงก์รีเซ็ตรหัสผ่านของ ${email}]\n${link}\n`);
  }
  res.json({ ok: true });
});

app.post('/api/reset', (req, res) => {
  const token = str(req.body.token);
  const pw = String(req.body.password || '');
  if (pw.length < 8) return fail(res, 400, 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
  const row = db.prepare('SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 AND expires_at>?')
    .get(hash(token), Date.now());
  if (!row) return fail(res, 400, 'ลิงก์หมดอายุหรือถูกใช้ไปแล้ว');
  db.transaction(() => {
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(pw, 10), row.user_id);
    db.prepare('UPDATE reset_tokens SET used=1 WHERE id=?').run(row.id);
  })();
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('เซิร์ฟเวอร์ทำงานที่พอร์ต ' + PORT));
