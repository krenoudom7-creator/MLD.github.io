'use strict';
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { buildDynamicKhqr, md5Of } = require('./khqr');
const { checkTransactionByMd5, tokenInfo } = require('./bakong');
let DatabaseSync;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (e) {
  console.error('\n❌ Node.js version របស់អ្នកចាស់ពេក (ត្រូវការ v22.13 ឡើងទៅ)។ សូមដំឡើង Node.js LTS ថ្មីពី https://nodejs.org\n   Your Node.js (' + process.version + ') has no built-in SQLite. Install Node 22.13+ or newer.\n');
  process.exit(1);
}

// ---------------------------------------------------------------
// Config
// ---------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// JWT secret: from env, else generated once and persisted (so logins survive restarts)
function getJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const f = path.join(DATA_DIR, 'jwt.secret');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(f, 'utf8').trim();
}
const JWT_SECRET = getJwtSecret();
const TOKEN_TTL = process.env.TOKEN_TTL || '8h';

// Cambodia is UTC+7. Reports group orders by local date using this offset.
const TZ_HOURS = Number.isFinite(Number(process.env.TZ_OFFSET)) ? Number(process.env.TZ_OFFSET) : 7;
const TZ_MOD = `${TZ_HOURS >= 0 ? '+' : '-'}${Math.abs(TZ_HOURS)} hours`;
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
fs.mkdirSync(BACKUP_DIR, { recursive: true });

// ---- KHQR checkout / Bakong verification (all secrets come from environment variables only) ----
const BAKONG_ENV = String(process.env.BAKONG_ENV || 'sandbox').toLowerCase() === 'production' ? 'production' : 'sandbox';
const BAKONG = {
  env: BAKONG_ENV,
  token: process.env.BAKONG_TOKEN || '',
  baseUrl: process.env.BAKONG_BASE_URL || (BAKONG_ENV === 'production' ? 'https://api-bakong.nbc.gov.kh' : 'https://sit-api-bakong.nbc.gov.kh'),
  accountType: String(process.env.BAKONG_ACCOUNT_TYPE || 'individual').toLowerCase() === 'merchant' ? 'merchant' : 'individual',
  accountId: process.env.BAKONG_ACCOUNT_ID || '',                       // e.g. name@bank (decoded from your static KHQR)
  accountInfo: { USD: process.env.BAKONG_ACCOUNT_INFO_USD || '', KHR: process.env.BAKONG_ACCOUNT_INFO_KHR || '' },
  acquiringBank: process.env.BAKONG_ACQUIRING_BANK || '',
  merchantId: process.env.BAKONG_MERCHANT_ID || '',
  merchantName: process.env.BAKONG_MERCHANT_NAME || '',                 // exactly as shown on your static QR
  merchantCity: process.env.BAKONG_MERCHANT_CITY || 'Phnom Penh',
  mcc: process.env.BAKONG_MCC || '5999',
  storeLabel: process.env.BAKONG_STORE_LABEL || '',
  expectToAccount: process.env.BAKONG_EXPECT_TO_ACCOUNT || '',          // optional strict check of toAccountId
  expireMinutes: Math.max(1, Number(process.env.KHQR_EXPIRE_MINUTES) || 10),
  graceMinutes: Math.max(1, Number(process.env.KHQR_GRACE_MINUTES) || 5),
  holdMinutes: Math.max(1, Number(process.env.KHQR_ORDER_HOLD_MINUTES) || 15),
};

// Two menu sections: drinks (have sugar level) and food (note only)
const CATEGORIES = ['coffee', 'tea', 'drink', 'bakery', 'meal', 'snack'];
const KIND_OF = { coffee: 'drink', tea: 'drink', drink: 'drink', bakery: 'food', meal: 'food', snack: 'food' };
const ORDER_STATUSES = ['pending', 'preparing', 'completed', 'cancelled'];

// ---------------------------------------------------------------
// Database
// ---------------------------------------------------------------
const db = new DatabaseSync(path.join(DATA_DIR, 'mlob-doung.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

// Minimal transaction helper (node:sqlite has no .transaction()). Rolls back if fn throws.
function tx(fn) {
  return (...args) => {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn(...args);
      db.exec('COMMIT');
      return result;
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
      throw err;
    }
  };
}

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price REAL NOT NULL CHECK (price >= 0),
  stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
  status TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS orders (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  table_no TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_seq INTEGER NOT NULL REFERENCES orders(seq) ON DELETE CASCADE,
  product_id TEXT,
  name TEXT NOT NULL,
  price REAL NOT NULL,
  quantity INTEGER NOT NULL,
  sugar TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_seq);
`);

// Migration: per-item customer note (older databases lack this column)
if (!db.prepare('PRAGMA table_info(order_items)').all().some((c) => c.name === 'note')) {
  db.exec("ALTER TABLE order_items ADD COLUMN note TEXT NOT NULL DEFAULT ''");
}

// Migration: per-product discount percent (0-100)
if (!db.prepare('PRAGMA table_info(products)').all().some((c) => c.name === 'discount')) {
  db.exec('ALTER TABLE products ADD COLUMN discount INTEGER NOT NULL DEFAULT 0');
}

// Migrations: roles, payments, order tracking, settings
const hasCol = (t, c) => db.prepare(`PRAGMA table_info(${t})`).all().some((x) => x.name === c);
if (!hasCol('admins', 'role')) db.exec("ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'");
for (const [col, ddl] of [
  ['pay_status', "TEXT NOT NULL DEFAULT 'unpaid'"],   // unpaid | paid | refunded
  ['pay_method', "TEXT NOT NULL DEFAULT ''"],         // cash | khqr | other
  ['received', 'REAL NOT NULL DEFAULT 0'],
  ['received_cur', "TEXT NOT NULL DEFAULT 'USD'"],
  ['change_usd', 'REAL NOT NULL DEFAULT 0'],
  ['rate', 'REAL NOT NULL DEFAULT 0'],
  ['paid_at', 'TEXT'],
  ['track_code', 'TEXT'],
]) {
  if (!hasCol('orders', col)) db.exec(`ALTER TABLE orders ADD COLUMN ${col} ${ddl}`);
}
db.exec('CREATE INDEX IF NOT EXISTS idx_orders_track ON orders(track_code)');
db.exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');

// Every KHQR payment attempt. An order can have several attempts (expired/failed QR -> new QR).
db.exec(`
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_seq INTEGER NOT NULL REFERENCES orders(seq) ON DELETE CASCADE,
  reference TEXT NOT NULL UNIQUE,            -- bill number embedded in the QR
  currency TEXT NOT NULL,                    -- USD | KHR
  amount_minor INTEGER NOT NULL,             -- expected amount: cents (USD) or riel (KHR)
  rate REAL NOT NULL,                        -- USD->KHR rate used when the QR was made
  khqr TEXT NOT NULL,
  md5 TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',    -- pending | paid | failed | expired | review
  env TEXT NOT NULL,                         -- sandbox | production
  account_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_check_at INTEGER NOT NULL DEFAULT 0,  -- epoch ms
  last_checked_at TEXT,
  last_error TEXT,
  verified_at TEXT,
  verified_amount_minor INTEGER,
  verified_currency TEXT,
  tx_hash TEXT,
  from_account TEXT,
  to_account TEXT,
  raw_response TEXT,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, next_check_at);
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_seq);
-- A real bank transaction can settle at most ONE payment (blocks replays / double use).
CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_tx_hash ON payments(tx_hash) WHERE tx_hash IS NOT NULL;
`);

const getSetting = (k, d = '') => { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r ? r.value : d; };
const setSetting = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, String(v));
const getRate = () => { const r = Number(getSetting('exchange_rate', '4100')); return r > 0 ? r : 4100; };
const khrOf = (usd, rate) => Math.round((usd * rate) / 100) * 100; // riel, rounded to 100

// Promo banners (managed by admin, shown on the POS home screen)
db.exec(`
CREATE TABLE IF NOT EXISTS banners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL DEFAULT '',
  subtitle TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);
if (db.prepare('SELECT COUNT(*) AS n FROM banners').get().n === 0) {
  const insB = db.prepare('INSERT INTO banners (title, subtitle, image, sort_order) VALUES (?, ?, ?, ?)');
  const defaults = [
    ['កាហ្វេត្រជាក់ ស្រស់ស្រាយ', 'ជ្រើសរើសកាហ្វេដែលអ្នកស្រលាញ់ ថ្ងៃនេះ', 'https://images.unsplash.com/photo-1517701604599-bb29b565090c?auto=format&fit=crop&w=1200&q=75'],
    ['តែបៃតង & ម៉ាត់ឆាឡាតេ', 'ក្លិនឈ្ងុយ ផ្អែមល្មម ត្រជាក់ស្រួល', 'https://images.unsplash.com/photo-1515823662972-da6a2e4d3002?auto=format&fit=crop&w=1200&q=75'],
    ['នំប័ុងក្តៅៗ ស្រួយឆ្ងាញ់', 'ញ៉ាំជាមួយកាហ្វេ ពិសេសបំផុត', 'https://images.unsplash.com/photo-1555507036-ab1f4038808a?auto=format&fit=crop&w=1200&q=75'],
    ['ភេសជ្ជៈស្រស់ ត្រជាក់បេះដូង', 'ផាសិនសូដា និងភេសជ្ជៈជាច្រើនទៀត', 'https://images.unsplash.com/photo-1513558161293-cdaf765ed2fd?auto=format&fit=crop&w=1200&q=75'],
  ];
  tx(() => defaults.forEach((d, i) => insB.run(d[0], d[1], d[2], i)))();
}

// Seed admin (first run only)
if (db.prepare('SELECT COUNT(*) AS n FROM admins').get().n === 0) {
  const u = process.env.ADMIN_USERNAME || 'admin';
  const p = process.env.ADMIN_PASSWORD || '123456';
  db.prepare("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, 'owner')").run(u, bcrypt.hashSync(p, 10));
  if (!process.env.ADMIN_PASSWORD) {
    console.warn('\n⚠️  Default admin created: admin / 123456 — please change the password right after first login!\n');
  }
}

// Seed products (first run only)
if (db.prepare('SELECT COUNT(*) AS n FROM products').get().n === 0) {
  const ins = db.prepare(`INSERT INTO products (id, name, category, price, stock, status, description, image)
                          VALUES (@id, @name, @category, @price, @stock, 'active', @description, @image)`);
  const u = (id) => `https://images.unsplash.com/${id}?auto=format&fit=crop&w=400&q=80`;
  const seed = [
    { id: 'prod-1', name: 'Iced Milk Coffee (កាហ្វេទឹកដោះគោ)', category: 'coffee', price: 2.25, stock: 45, description: 'កាហ្វេទឹកដោះគោត្រជាក់ ឈ្ងុយឆ្ងាញ់', image: u('photo-1517701604599-bb29b565090c') },
    { id: 'prod-2', name: 'Iced Americano (អាមេរិកខាណូ)', category: 'coffee', price: 2.0, stock: 60, description: 'កាហ្វេខ្មៅស្រស់ ក្លិនឈ្ងុយពិសារ', image: u('photo-1514432324607-a09d9b4aefdd') },
    { id: 'prod-3', name: 'Iced Caramel Macchiato', category: 'coffee', price: 2.85, stock: 30, description: 'កាហ្វេការ៉ាមែលផ្អែមល្មម ឈ្ងុយឆ្ងាញ់', image: u('photo-1485808191679-5f86510681a2') },
    { id: 'prod-4', name: 'Iced Matcha Latte (ម៉ាត់ឆាឡាតេ)', category: 'tea', price: 2.75, stock: 20, description: 'តែបៃតងជប៉ុន ម៉ាត់ឆាដើម', image: u('photo-1515823662972-da6a2e4d3002') },
    { id: 'prod-5', name: 'Thai Milk Tea (តែថៃទឹកដោះគោ)', category: 'tea', price: 2.25, stock: 0, description: 'តែថៃឈ្ងុយឆ្ងាញ់ ជាមួយទឹកដោះគោស្រស់', image: u('photo-1558857563-b371033873b8') },
    { id: 'prod-6', name: 'Passion Soda (ផាសិនសូដា)', category: 'drink', price: 2.3, stock: 50, description: 'ផាសិនស្រស់ លាយសូដាត្រជាក់បកបេះដូង', image: u('photo-1513558161293-cdaf765ed2fd') },
    { id: 'prod-7', name: 'Butter Croissant (នំប័ុងក្រូសង់)', category: 'bakery', price: 1.8, stock: 15, description: 'នំប័ុងក្រូសង់ប៊័រស្រស់ ក្តៅៗស្រួយឆ្ងាញ់', image: u('photo-1555507036-ab1f4038808a') },
  ];
  tx(() => seed.forEach((s) => ins.run(s)))();
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// Price after discount, rounded to cents
const finalPrice = (price, discount) => Math.round(price * (100 - (discount || 0))) / 100;

const productOut = (r) => ({
  id: r.id, name: r.name, category: r.category, price: r.price, stock: r.stock,
  discount: r.discount || 0, finalPrice: finalPrice(r.price, r.discount), kind: KIND_OF[r.category] || 'drink',
  status: r.status, description: r.description, image: r.image, created_at: r.created_at,
});

function loadOrders(whereSql = '', params = []) {
  const rows = db.prepare(`SELECT * FROM orders ${whereSql} ORDER BY seq DESC`).all(...params);
  if (!rows.length) return [];
  const itemsStmt = db.prepare('SELECT name, price, quantity, sugar, note FROM order_items WHERE order_seq = ? ORDER BY id');
  return rows.map((o) => ({
    id: 'ORD-' + (1000 + o.seq),
    customerName: o.customer_name,
    tableNo: o.table_no,
    items: itemsStmt.all(o.seq),
    total: o.total,
    status: o.status,
    payStatus: o.pay_status,
    payMethod: o.pay_method,
    received: o.received,
    receivedCur: o.received_cur,
    changeUsd: o.change_usd,
    rate: o.rate,
    paidAt: o.paid_at ? o.paid_at.replace(' ', 'T') + 'Z' : null,
    createdAt: o.created_at.replace(' ', 'T') + 'Z', // SQLite datetime('now') is UTC
  }));
}
const seqFromOrderId = (id) => {
  const m = /^ORD-(\d+)$/.exec(String(id));
  return m ? Number(m[1]) - 1000 : NaN;
};

const bannerOut = (r) => ({
  id: r.id, title: r.title, subtitle: r.subtitle, image: r.image, status: r.status, sortOrder: r.sort_order,
});

// Same rule as products: only our own uploads or http(s) URLs
function parseImage(v, required) {
  const img = String(v ?? '').trim();
  if (required && !img) throw new HttpError(400, 'សូមជ្រើសរើសរូបភាព');
  if (img && !/^(\/uploads\/[\w.-]+|https?:\/\/[^\s]+)$/i.test(img)) throw new HttpError(400, 'រូបភាពមិនត្រឹមត្រូវ');
  return img;
}
function parseBanner(body) {
  const title = String(body.title ?? '').trim();
  const subtitle = String(body.subtitle ?? '').trim();
  if (title.length > 80) throw new HttpError(400, 'ចំណងជើងវែងពេក (អតិបរមា 80)');
  if (subtitle.length > 120) throw new HttpError(400, 'អត្ថបទរងវែងពេក (អតិបរមា 120)');
  if (!['active', 'inactive'].includes(body.status ?? 'active')) throw new HttpError(400, 'ស្ថានភាពមិនត្រឹមត្រូវ');
  return { title, subtitle, image: parseImage(body.image, true), status: body.status ?? 'active' };
}
// Delete an uploaded file only when nothing else still uses it
function removeUploadIfUnused(img) {
  if (!img || !img.startsWith('/uploads/')) return;
  const still = db.prepare('SELECT 1 FROM products WHERE image = ? UNION SELECT 1 FROM banners WHERE image = ? UNION SELECT 1 FROM settings WHERE value = ?').get(img, img, img);
  if (!still) fs.unlink(path.join(UPLOAD_DIR, path.basename(img)), () => {});
}

// Validation for product payloads
function parseProduct(body, { partial = false } = {}) {
  const out = {};
  const has = (k) => body[k] !== undefined;

  if (!partial || has('name')) {
    const name = String(body.name ?? '').trim();
    if (!name || name.length > 120) throw new HttpError(400, 'ឈ្មោះទំនិញមិនត្រឹមត្រូវ');
    out.name = name;
  }
  if (!partial || has('category')) {
    if (!CATEGORIES.includes(body.category)) throw new HttpError(400, 'ប្រភេទទំនិញមិនត្រឹមត្រូវ');
    out.category = body.category;
  }
  if (!partial || has('price')) {
    const price = Number(body.price);
    if (!Number.isFinite(price) || price < 0 || price > 100000) throw new HttpError(400, 'តម្លៃមិនត្រឹមត្រូវ');
    out.price = Math.round(price * 100) / 100;
  }
  if (!partial || has('discount')) {
    const discount = Number(body.discount ?? 0);
    if (!Number.isInteger(discount) || discount < 0 || discount > 100) throw new HttpError(400, 'ការបញ្ចុះតម្លៃត្រូវតែនៅចន្លោះ 0-100%');
    out.discount = discount;
  }
  if (!partial || has('stock')) {
    const stock = Number(body.stock);
    if (!Number.isInteger(stock) || stock < 0 || stock > 1000000) throw new HttpError(400, 'ចំនួនស្តុកមិនត្រឹមត្រូវ');
    out.stock = stock;
  }
  if (!partial || has('status')) {
    if (!['active', 'inactive'].includes(body.status)) throw new HttpError(400, 'ស្ថានភាពមិនត្រឹមត្រូវ');
    out.status = body.status;
  }
  if (!partial || has('description')) {
    const d = String(body.description ?? '').trim();
    if (d.length > 500) throw new HttpError(400, 'ការពិពណ៌នាវែងពេក');
    out.description = d;
  }
  if (!partial || has('image')) {
    const img = String(body.image ?? '').trim();
    // Only allow our own uploads or http(s) URLs (blocks javascript:/data: payloads)
    if (img && !/^(\/uploads\/[\w.-]+|https?:\/\/[^\s]+)$/i.test(img)) throw new HttpError(400, 'រូបភាពមិនត្រឹមត្រូវ');
    out.image = img;
  }
  return out;
}

// ---------------------------------------------------------------
// App
// ---------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '100kb' }));

// Auth middleware
function requireAdmin(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return next(new HttpError(401, 'តម្រូវឱ្យចូលប្រើជា Admin'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Always read role from DB so a removed user / changed role takes effect immediately
    const a = db.prepare('SELECT id, username, role FROM admins WHERE id = ?').get(payload.sub);
    if (!a) throw new Error('admin removed');
    req.admin = a;
    next();
  } catch {
    next(new HttpError(401, 'Session ផុតកំណត់ សូមចូលប្រើម្តងទៀត'));
  }
}

// Image upload
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' }[file.mimetype];
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(file.mimetype)) cb(null, true);
    else cb(new HttpError(400, 'អនុញ្ញាតតែរូបភាព JPG, PNG, WEBP, GIF'));
  },
});

// ---------------- Health ----------------
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---------------- Auth ----------------
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'ព្យាយាមចូលច្រើនពេក សូមរង់ចាំ ១៥ នាទី' } });

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const username = String(req.body.username ?? '').trim();
  const password = String(req.body.password ?? '');
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  // Always run a compare to keep timing similar whether or not the user exists
  const hash = admin ? admin.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali';
  const ok = bcrypt.compareSync(password, hash);
  if (!admin || !ok) return res.status(401).json({ error: 'ឈ្មោះអ្នកប្រើ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ!' });
  const token = jwt.sign({ sub: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  res.json({ token, admin: { id: admin.id, username: admin.username, role: admin.role } });
});

app.get('/api/auth/me', requireAdmin, (req, res) => res.json({ admin: req.admin }));

app.post('/api/auth/change-password', requireAdmin, (req, res) => {
  const current = String(req.body.currentPassword ?? '');
  const next = String(req.body.newPassword ?? '');
  if (next.length < 6) throw new HttpError(400, 'ពាក្យសម្ងាត់ថ្មីត្រូវមានយ៉ាងតិច ៦ តួអក្សរ');
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.admin.id);
  if (!bcrypt.compareSync(current, admin.password_hash)) throw new HttpError(400, 'ពាក្យសម្ងាត់បច្ចុប្បន្នមិនត្រឹមត្រូវ');
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(next, 10), admin.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------
// KHQR checkout: dynamic KHQR + SERVER-SIDE verification through the Bakong Open API.
// Nothing here trusts the browser. An order becomes "paid" ONLY inside settlePayment(),
// which runs only after Bakong confirmed a transaction whose amount/currency match.
// ---------------------------------------------------------------
const BAKONG_READY = Boolean(BAKONG.token && BAKONG.accountId && BAKONG.merchantName &&
  (BAKONG.accountType !== 'merchant' || (BAKONG.merchantId && BAKONG.acquiringBank)));
const GRACE_MS = BAKONG.graceMinutes * 60000;
const workerState = { lastRunAt: null, lastSuccessAt: null, lastError: '', lastErrorState: '', consecutiveErrors: 0, backoffUntil: 0 };
let workerBusy = false;

const sqlTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
const parseSqlTime = (t) => Date.parse(String(t).replace(' ', 'T') + 'Z');
const isoOf = (t) => (t ? new Date(parseSqlTime(t)).toISOString() : null);
const toMinor = (cur, amount) => {
  const n = Number(amount);
  if (!Number.isFinite(n) || n < 0) return null;
  return cur === 'USD' ? Math.round(n * 100) : cur === 'KHR' ? Math.round(n) : null;
};
const fromMinor = (cur, minor) => (cur === 'USD' ? minor / 100 : minor);
const nextDelayMs = (attempts) => (attempts < 15 ? 4000 : attempts < 45 ? 8000 : 15000);

function publicPayment(p) {
  return {
    reference: p.reference, status: p.status, currency: p.currency,
    amount: fromMinor(p.currency, p.amount_minor), amountMinor: p.amount_minor,
    khqr: p.status === 'pending' ? p.khqr : null,           // only a live QR is ever handed out
    createdAt: isoOf(p.created_at), expiresAt: isoOf(p.expires_at), verifiedAt: isoOf(p.verified_at),
    delayed: p.status === 'pending' && Boolean(p.last_error), // verification temporarily unavailable
    env: p.env,
  };
}

/** Creates the dynamic KHQR for an order (call inside the order transaction). The amount ALWAYS comes from the DB total. */
function createPayment(seq, totalUsd, currency) {
  if (!BAKONG_READY) throw new HttpError(503, 'ការបង់ប្រាក់តាម KHQR មិនទាន់បើកទេ');
  const rate = getRate();
  const amountMinor = currency === 'KHR' ? khrOf(totalUsd, rate) : Math.round(totalUsd * 100);
  if (!Number.isInteger(amountMinor) || amountMinor <= 0) throw new HttpError(400, 'ចំនួនទឹកប្រាក់មិនត្រឹមត្រូវ');
  const createdMs = Date.now();
  const expiresMs = createdMs + BAKONG.expireMinutes * 60000;
  const reference = `ORD${1000 + seq}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  let khqr;
  try {
    khqr = buildDynamicKhqr({
      accountType: BAKONG.accountType, accountId: BAKONG.accountId, accountInfo: BAKONG.accountInfo[currency],
      acquiringBank: BAKONG.acquiringBank, merchantId: BAKONG.merchantId, merchantName: BAKONG.merchantName,
      merchantCity: BAKONG.merchantCity, mcc: BAKONG.mcc, currency, amountMinor, billNumber: reference,
      storeLabel: BAKONG.storeLabel, createdMs, expiresMs,
    });
  } catch (e) {
    console.error('KHQR build failed:', e.message);
    throw new HttpError(500, 'មិនអាចបង្កើត KHQR បានទេ');
  }
  db.prepare(`INSERT INTO payments (order_seq, reference, currency, amount_minor, rate, khqr, md5, env, account_id, expires_at, next_check_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(seq, reference, currency, amountMinor, rate, khqr, md5Of(khqr), BAKONG.env, BAKONG.accountId, sqlTime(expiresMs), Date.now() + 3000);
}

/** '' when the Bakong transaction matches what we expect, otherwise a human readable reason. */
function validateTransaction(p, data) {
  if (!data || typeof data.hash !== 'string' || data.hash.length < 8) return 'transaction has no hash';
  const cur = String(data.currency || '').toUpperCase();
  if (cur !== p.currency) return `currency mismatch (paid ${cur || '?'}, expected ${p.currency})`;
  const minor = toMinor(cur, data.amount);
  if (minor === null || minor !== p.amount_minor) return `amount mismatch (paid ${data.amount}, expected ${fromMinor(p.currency, p.amount_minor)} ${p.currency})`;
  if (BAKONG.expectToAccount && data.toAccountId !== BAKONG.expectToAccount) return 'receiver account mismatch';
  const t = Number(data.createdDateMs);
  if (Number.isFinite(t) && t > 1e12) {
    if (t < parseSqlTime(p.created_at) - 120000 || t > parseSqlTime(p.expires_at) + GRACE_MS + 120000) return 'transaction time is outside the payment window';
  }
  return '';
}

function markReview(p, note, data) {
  const args = [note, data ? toMinor(String(data.currency || '').toUpperCase(), data.amount) : null, data ? String(data.currency || '') : null,
    data ? data.fromAccountId || null : null, data ? data.toAccountId || null : null, data ? JSON.stringify(data).slice(0, 2000) : null];
  try {
    db.prepare("UPDATE payments SET status='review', note=?, verified_amount_minor=?, verified_currency=?, from_account=?, to_account=?, raw_response=?, tx_hash=COALESCE(tx_hash, ?) WHERE id=? AND status IN ('pending','expired','failed')")
      .run(...args, data && typeof data.hash === 'string' ? data.hash : null, p.id);
  } catch (e) { // tx hash already used by another payment -> keep it out of the unique column
    db.prepare("UPDATE payments SET status='review', note=?, verified_amount_minor=?, verified_currency=?, from_account=?, to_account=?, raw_response=? WHERE id=? AND status IN ('pending','expired','failed')")
      .run(...args, p.id);
  }
}

/** Atomically marks payment + order as paid. Idempotent: a payment can be settled exactly once. */
function settlePayment(p, data) {
  const minor = toMinor(data.currency.toUpperCase(), data.amount);
  return tx(() => {
    const cur = db.prepare('SELECT * FROM payments WHERE id = ?').get(p.id);
    if (!cur || cur.status !== 'pending') return cur ? cur.status : 'missing';
    const dup = db.prepare('SELECT id FROM payments WHERE tx_hash = ? AND id != ?').get(data.hash, p.id);
    const o = db.prepare('SELECT * FROM orders WHERE seq = ?').get(cur.order_seq);
    let note = '';
    if (dup) note = `transaction hash already used by payment #${dup.id}`;
    else if (!o || o.status === 'cancelled' || o.pay_status !== 'awaiting') note = 'verified, but the order is no longer awaiting payment (cancelled/expired). Refund or handle manually';
    if (note) {
      db.prepare("UPDATE payments SET status='review', note=?, verified_amount_minor=?, verified_currency=?, from_account=?, to_account=?, raw_response=? WHERE id=? AND status='pending'")
        .run(note, minor, data.currency, data.fromAccountId || null, data.toAccountId || null, JSON.stringify(data).slice(0, 2000), p.id);
      return 'review';
    }
    const r1 = db.prepare("UPDATE payments SET status='paid', verified_at=datetime('now'), verified_amount_minor=?, verified_currency=?, tx_hash=?, from_account=?, to_account=?, raw_response=?, last_error=NULL, note=NULL WHERE id=? AND status='pending'")
      .run(minor, data.currency.toUpperCase(), data.hash, data.fromAccountId || null, data.toAccountId || null, JSON.stringify(data).slice(0, 2000), p.id);
    if (r1.changes !== 1) return 'noop';
    const r2 = db.prepare("UPDATE orders SET pay_status='paid', pay_method='khqr', received=?, received_cur=?, change_usd=0, rate=?, paid_at=datetime('now') WHERE seq=? AND pay_status='awaiting'")
      .run(fromMinor(cur.currency, minor), cur.currency, cur.rate, cur.order_seq);
    if (r2.changes !== 1) throw new Error('order update failed'); // rolls the payment update back too
    return 'paid';
  })();
}

const touchPayment = (p, err) =>
  db.prepare("UPDATE payments SET attempts = attempts + 1, last_checked_at = datetime('now'), next_check_at = ?, last_error = ? WHERE id = ?")
    .run(Date.now() + nextDelayMs(p.attempts + 1), err || null, p.id);
const workerOk = () => { workerState.lastSuccessAt = new Date().toISOString(); workerState.consecutiveErrors = 0; workerState.lastError = ''; workerState.lastErrorState = ''; };
const workerFail = (r) => { workerState.consecutiveErrors += 1; workerState.lastError = r.message || r.state; workerState.lastErrorState = r.state; };

/** Asks Bakong about one payment and updates the DB. Any doubt keeps the payment pending (never "paid"). */
async function verifyPayment(id, { manual = false } = {}) {
  const p = db.prepare('SELECT * FROM payments WHERE id = ?').get(id);
  if (!p || p.status === 'paid') return p;
  const recheckable = manual && (p.status === 'expired' || p.status === 'failed');
  if (p.status !== 'pending' && !recheckable) return p;
  if (md5Of(p.khqr) !== p.md5) {
    db.prepare("UPDATE payments SET status='review', note='stored QR does not match its hash (possible tampering)' WHERE id=? AND status IN ('pending','expired','failed')").run(id);
    return db.prepare('SELECT * FROM payments WHERE id = ?').get(id);
  }
  workerState.lastRunAt = new Date().toISOString();
  const r = await checkTransactionByMd5({ baseUrl: BAKONG.baseUrl, token: BAKONG.token, md5: p.md5 });
  const expiresMs = parseSqlTime(p.expires_at);

  if (r.state === 'found') {
    workerOk(); touchPayment(p, null);
    const reason = validateTransaction(p, r.data);
    if (reason) markReview(p, reason, r.data);
    else if (p.status !== 'pending') markReview(p, 'verified transaction found after the payment window closed. Refund or handle manually', r.data);
    else {
      try { settlePayment(p, r.data); }
      catch (e) { console.error('settle failed:', e.message); markReview(p, 'settlement error: ' + e.message, r.data); }
    }
  } else if (r.state === 'not_found') {
    workerOk(); touchPayment(p, null);
    if (p.status === 'pending' && Date.now() > expiresMs + GRACE_MS) db.prepare("UPDATE payments SET status='expired' WHERE id=? AND status='pending'").run(id);
  } else if (r.state === 'failed') {
    workerOk(); touchPayment(p, null);
    db.prepare("UPDATE payments SET status='failed', note=? WHERE id=? AND status='pending'").run(r.message || 'transaction failed', id);
  } else { // unauthorized | forbidden | ratelimited | error -> unknown, stay pending and retry later
    workerFail(r);
    touchPayment(p, `${r.state}: ${r.message || ''}`.slice(0, 200));
    if (r.state === 'ratelimited') workerState.backoffUntil = Date.now() + 30000;
    if (r.state === 'unauthorized' || r.state === 'forbidden') workerState.backoffUntil = Date.now() + 20000;
    if (p.status === 'pending' && Date.now() > expiresMs + 24 * 3600e3) {
      db.prepare("UPDATE payments SET status='review', note='verification was unavailable for 24h after expiry. Check the bank app manually' WHERE id=? AND status='pending'").run(id);
    }
  }
  return db.prepare('SELECT * FROM payments WHERE id = ?').get(id);
}

/** Cancels orders whose KHQR window is over without any payment, and gives the stock back. */
function cancelAwaitingOrders() {
  const rows = db.prepare(`SELECT seq FROM orders WHERE pay_status = 'awaiting' AND status != 'cancelled'
      AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.order_seq = orders.seq AND p.status IN ('pending','review','paid'))
      AND datetime(COALESCE((SELECT MAX(expires_at) FROM payments WHERE order_seq = orders.seq), created_at), ?) < datetime('now')`)
    .all(`+${BAKONG.holdMinutes} minutes`);
  for (const { seq } of rows) {
    tx(() => {
      const o = db.prepare('SELECT status, pay_status FROM orders WHERE seq = ?').get(seq);
      if (!o || o.status === 'cancelled' || o.pay_status !== 'awaiting') return;
      for (const it of db.prepare('SELECT product_id, quantity FROM order_items WHERE order_seq = ?').all(seq)) {
        db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?').run(it.quantity, it.product_id);
      }
      db.prepare("UPDATE orders SET status = 'cancelled', pay_status = 'expired' WHERE seq = ?").run(seq);
    })();
  }
}

async function paymentWorkerTick() {
  if (workerBusy) return;
  workerBusy = true;
  try {
    if (BAKONG_READY && Date.now() >= workerState.backoffUntil) {
      const due = db.prepare("SELECT id FROM payments WHERE status = 'pending' AND next_check_at <= ? ORDER BY next_check_at LIMIT 10").all(Date.now());
      for (const d of due) {
        await verifyPayment(d.id);
        if (Date.now() < workerState.backoffUntil) break;
      }
    }
    cancelAwaitingOrders();
  } catch (e) { console.error('payment worker:', e.message); }
  finally { workerBusy = false; }
}

// ---------------- Public POS API ----------------
// Menu for the POS screen (active products only)
app.get('/api/products', (req, res) => {
  const rows = db.prepare(`SELECT * FROM products WHERE status = 'active' ORDER BY created_at DESC, rowid DESC`).all();
  res.json(rows.map(productOut));
});

// Public settings (exchange rate + KHQR image for paying)
app.get('/api/settings', (req, res) => {
  res.json({ exchangeRate: getRate(), khqrImage: getSetting('khqr_image', ''), khqrCheckout: BAKONG_READY, khqrEnv: BAKONG.env });
});

// Customer order tracking: only reachable with the unguessable code returned when ordering
const trackLimiter = rateLimit({ windowMs: 60 * 1000, max: 90, standardHeaders: true, legacyHeaders: false,
  message: { error: 'សូមរង់ចាំបន្តិច' } });
app.get('/api/orders/track/:code', trackLimiter, (req, res) => {
  const code = String(req.params.code);
  if (!/^[\w-]{8,40}$/.test(code)) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const o = loadOrders('WHERE track_code = ?', [code])[0];
  if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const ahead = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status IN ('pending','preparing') AND pay_status != 'awaiting' AND seq < ?").get(seqFromOrderId(o.id)).n;
  res.json({
    id: o.id, status: o.status, payStatus: o.payStatus, total: o.total, createdAt: o.createdAt,
    queueAhead: (o.status === 'pending' || o.status === 'preparing') ? ahead : 0,
    items: o.items.map((i) => ({ name: i.name, quantity: i.quantity })),
  });
});

// Payment page data (by the unguessable order code). Read-only: nothing here can mark anything as paid.
const payLimiter = rateLimit({ windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false, message: { error: 'សូមរង់ចាំបន្តិច' } });
function payContext(code) {
  const c = String(code);
  if (!/^[\w-]{8,40}$/.test(c)) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const o = db.prepare('SELECT * FROM orders WHERE track_code = ?').get(c);
  if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const p = db.prepare('SELECT * FROM payments WHERE order_seq = ? ORDER BY id DESC LIMIT 1').get(o.seq);
  if (!p) throw new HttpError(404, 'ការកម្ម៉ង់នេះមិនមានការបង់ប្រាក់ KHQR ទេ');
  return { o, p };
}
app.get('/api/pay/:code', payLimiter, (req, res) => {
  const { o, p } = payContext(req.params.code);
  res.json({
    orderId: 'ORD-' + (1000 + o.seq), orderStatus: o.status, payStatus: o.pay_status, total: o.total,
    items: db.prepare('SELECT name, quantity FROM order_items WHERE order_seq = ? ORDER BY id').all(o.seq),
    payment: publicPayment(p),
    canRetry: BAKONG_READY && o.pay_status === 'awaiting' && o.status !== 'cancelled' && (p.status === 'failed' || p.status === 'expired'),
    exchangeRate: getRate(), serverNow: new Date().toISOString(),
  });
});
const retryLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'សូមរង់ចាំបន្តិច' } });
app.post('/api/pay/:code/retry', retryLimiter, (req, res) => {
  const { o, p } = payContext(req.params.code);
  if (!BAKONG_READY) throw new HttpError(503, 'ការបង់ប្រាក់តាម KHQR មិនទាន់បើកទេ');
  if (o.pay_status !== 'awaiting' || o.status === 'cancelled') throw new HttpError(409, 'ការកម្ម៉ង់នេះមិនអាចបង់ប្រាក់ទៀតបានទេ');
  if (p.status !== 'failed' && p.status !== 'expired') throw new HttpError(409, 'មាន QR កំពុងដំណើរការរួចហើយ');
  const currency = req.body.currency === 'KHR' ? 'KHR' : 'USD';
  tx(() => createPayment(o.seq, o.total, currency))();
  res.status(201).json({ ok: true });
});

// Active promo banners for the POS home screen
app.get('/api/banners', (req, res) => {
  const rows = db.prepare(`SELECT * FROM banners WHERE status = 'active' ORDER BY sort_order, id`).all();
  res.json(rows.map(bannerOut));
});

// Limit order spam from the public customer screen
const orderLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: 'កម្ម៉ង់ញឹកពេក សូមរង់ចាំបន្តិច' } });

// Create an order from the cart. Prices/totals are computed on the server,
// stock is checked and deducted atomically.
// NOTE: this is the ONLY public order endpoint. Listing / updating orders is admin-only.
app.post('/api/orders', orderLimiter, (req, res) => {
  const customerName = String(req.body.customerName ?? '').trim().slice(0, 80) || 'អតិថិជនទូទៅ';
  const tableNo = String(req.body.tableNo ?? '').trim().slice(0, 40) || 'តុទូទៅ';
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (!items.length || items.length > 50) throw new HttpError(400, 'កន្ត្រកទទេ ឬធំពេក');
  const payWith = req.body.payWith === 'khqr' ? 'khqr' : 'counter';
  const payCurrency = req.body.currency === 'KHR' ? 'KHR' : 'USD';
  if (payWith === 'khqr' && !BAKONG_READY) throw new HttpError(503, 'ការបង់ប្រាក់តាម KHQR មិនទាន់បើកទេ');

  const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
  const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?');
  const trackCode = crypto.randomBytes(9).toString('base64url');
  const insOrder = db.prepare('INSERT INTO orders (customer_name, table_no, total, track_code, pay_status) VALUES (?, ?, 0, ?, ?)');
  const insItem = db.prepare('INSERT INTO order_items (order_seq, product_id, name, price, quantity, sugar, note) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const setTotal = db.prepare('UPDATE orders SET total = ? WHERE seq = ?');

  const create = tx(() => {
    const { lastInsertRowid: seq } = insOrder.run(customerName, tableNo, trackCode, payWith === 'khqr' ? 'awaiting' : 'unpaid');
    let total = 0;
    for (const it of items) {
      const qty = Number(it.quantity);
      if (!Number.isInteger(qty) || qty < 1 || qty > 99) throw new HttpError(400, 'ចំនួនមិនត្រឹមត្រូវ');
      const p = getProduct.get(String(it.id));
      if (!p || p.status !== 'active') throw new HttpError(409, `ទំនិញ "${it.name ?? it.id}" មិនមានលក់ទៀតទេ`);
      if (decStock.run(qty, p.id, qty).changes === 0) throw new HttpError(409, `ទំនិញ "${p.name}" អស់ស្តុក ឬមិនគ្រប់ចំនួន (នៅសល់ ${p.stock})`);
      const sugar = KIND_OF[p.category] === 'food' ? '' : String(it.sugar ?? '').slice(0, 20); // food has no sugar level
      const note = String(it.note ?? '').replace(/\s+/g, ' ').trim().slice(0, 100);
      const unit = finalPrice(p.price, p.discount); // discounted unit price, computed on the server
      insItem.run(seq, p.id, p.name, unit, qty, sugar, note);
      total += unit * qty;
    }
    total = Math.round(total * 100) / 100;
    setTotal.run(total, seq);
    if (payWith === 'khqr') createPayment(seq, total, payCurrency); // price comes from the DB, never from the browser
    return seq;
  });

  const seq = create();
  const pay = payWith === 'khqr' ? db.prepare('SELECT * FROM payments WHERE order_seq = ? ORDER BY id DESC LIMIT 1').get(seq) : null;
  res.status(201).json({ ...loadOrders('WHERE seq = ?', [seq])[0], trackCode, payment: pay ? publicPayment(pay) : null });
});

// ---------------- Admin API (JWT required) ----------------
const admin = express.Router();
admin.use(requireAdmin);
// Roles: 'owner' can do everything; 'cashier' can only work with orders (view, status, payment)
admin.use((req, res, next) => {
  if (req.admin.role === 'owner' || req.path.startsWith('/orders')) return next();
  next(new HttpError(403, 'មុខងារនេះសម្រាប់ម្ចាស់ហាងប៉ុណ្ណោះ'));
});

admin.get('/products', (req, res) => {
  const rows = db.prepare('SELECT * FROM products ORDER BY created_at DESC, rowid DESC').all();
  res.json(rows.map(productOut));
});

admin.post('/products', (req, res) => {
  const data = parseProduct(req.body);
  const id = 'prod-' + Date.now() + '-' + crypto.randomBytes(2).toString('hex');
  db.prepare(`INSERT INTO products (id, name, category, price, discount, stock, status, description, image)
              VALUES (@id, @name, @category, @price, @discount, @stock, @status, @description, @image)`).run({ id, ...data });
  res.status(201).json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(id)));
});

admin.put('/products/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!existing) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  const data = parseProduct(req.body);
  db.prepare(`UPDATE products SET name=@name, category=@category, price=@price, discount=@discount, stock=@stock,
              status=@status, description=@description, image=@image WHERE id=@id`).run({ id: req.params.id, ...data });
  res.json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

// Partial update (status toggle, stock changes, etc.)
admin.patch('/products/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!existing) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  const data = parseProduct(req.body, { partial: true });
  const keys = Object.keys(data);
  if (!keys.length) throw new HttpError(400, 'គ្មានទិន្នន័យត្រូវកែ');
  db.prepare(`UPDATE products SET ${keys.map((k) => `${k} = @${k}`).join(', ')} WHERE id = @id`).run({ id: req.params.id, ...data });
  res.json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

// Atomic stock adjustment (+/-), avoids lost updates when two staff click at once
admin.post('/products/:id/stock', (req, res) => {
  const delta = Number(req.body.delta);
  if (!Number.isInteger(delta) || Math.abs(delta) > 100000) throw new HttpError(400, 'delta មិនត្រឹមត្រូវ');
  const r = db.prepare('UPDATE products SET stock = MAX(0, stock + ?) WHERE id = ?').run(delta, req.params.id);
  if (!r.changes) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  res.json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

admin.delete('/products/:id', (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  // Remove the uploaded file if it was ours and nothing else uses it
  if (p.image.startsWith('/uploads/')) {
    const still = db.prepare('SELECT 1 FROM products WHERE image = ? UNION SELECT 1 FROM banners WHERE image = ? UNION SELECT 1 FROM settings WHERE value = ?').get(p.image, p.image, p.image);
    if (!still) fs.unlink(path.join(UPLOAD_DIR, path.basename(p.image)), () => {});
  }
  res.json({ ok: true });
});

admin.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) throw new HttpError(400, 'សូមជ្រើសរើសរូបភាព');
  res.status(201).json({ url: '/uploads/' + req.file.filename });
});

admin.get('/stats', (req, res) => {
  const p = db.prepare(`SELECT COUNT(*) AS total,
      SUM(status='active') AS active,
      SUM(stock = 0) AS outOfStock,
      SUM(stock > 0 AND stock <= 10) AS lowStock
    FROM products`).get();
  const o = db.prepare(`SELECT COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue
    FROM orders WHERE status != 'cancelled' AND date(created_at) = date('now')`).get();
  res.json({
    products: { total: p.total, active: p.active || 0, outOfStock: p.outOfStock || 0, lowStock: p.lowStock || 0 },
    today: { orders: o.orders, revenue: Math.round(o.revenue * 100) / 100 },
  });
});

// ---------------- Admin: Banners (JWT required) ----------------
admin.get('/banners', (req, res) => {
  res.json(db.prepare('SELECT * FROM banners ORDER BY sort_order, id').all().map(bannerOut));
});

admin.post('/banners', (req, res) => {
  if (db.prepare('SELECT COUNT(*) AS n FROM banners').get().n >= 20) throw new HttpError(400, 'Banner ច្រើនពេក (អតិបរមា 20)');
  const d = parseBanner(req.body);
  const next = db.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS n FROM banners').get().n;
  const { lastInsertRowid: id } = db.prepare('INSERT INTO banners (title, subtitle, image, status, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(d.title, d.subtitle, d.image, d.status, next);
  res.status(201).json(bannerOut(db.prepare('SELECT * FROM banners WHERE id = ?').get(id)));
});

admin.put('/banners/:id', (req, res) => {
  const id = Number(req.params.id);
  const old = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  if (!old) throw new HttpError(404, 'រកមិនឃើញ Banner');
  const d = parseBanner(req.body);
  db.prepare('UPDATE banners SET title = ?, subtitle = ?, image = ?, status = ? WHERE id = ?').run(d.title, d.subtitle, d.image, d.status, id);
  if (old.image !== d.image) removeUploadIfUnused(old.image);
  res.json(bannerOut(db.prepare('SELECT * FROM banners WHERE id = ?').get(id)));
});

admin.patch('/banners/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!['active', 'inactive'].includes(req.body.status)) throw new HttpError(400, 'ស្ថានភាពមិនត្រឹមត្រូវ');
  const r = db.prepare('UPDATE banners SET status = ? WHERE id = ?').run(req.body.status, id);
  if (!r.changes) throw new HttpError(404, 'រកមិនឃើញ Banner');
  res.json(bannerOut(db.prepare('SELECT * FROM banners WHERE id = ?').get(id)));
});

admin.post('/banners/:id/move', (req, res) => {
  const id = Number(req.params.id);
  const dir = Number(req.body.dir) < 0 ? -1 : 1;
  tx(() => {
    const list = db.prepare('SELECT id FROM banners ORDER BY sort_order, id').all();
    const i = list.findIndex((b) => b.id === id);
    if (i < 0) throw new HttpError(404, 'រកមិនឃើញ Banner');
    const j = i + dir;
    if (j >= 0 && j < list.length) {
      [list[i], list[j]] = [list[j], list[i]];
      const upd = db.prepare('UPDATE banners SET sort_order = ? WHERE id = ?');
      list.forEach((b, k) => upd.run(k, b.id));
    }
  })();
  res.json({ ok: true });
});

admin.delete('/banners/:id', (req, res) => {
  const id = Number(req.params.id);
  const b = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  if (!b) throw new HttpError(404, 'រកមិនឃើញ Banner');
  db.prepare('DELETE FROM banners WHERE id = ?').run(id);
  removeUploadIfUnused(b.image);
  res.json({ ok: true });
});

// ---------------- Admin: Orders (JWT required) ----------------
admin.get('/orders', (req, res) => {
  const { status } = req.query;
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  if (status && status !== 'all') {
    if (!ORDER_STATUSES.includes(status)) throw new HttpError(400, 'status មិនត្រឹមត្រូវ');
    return res.json(loadOrders("WHERE status = ? AND pay_status != 'awaiting'", [status]).slice(0, limit));
  }
  res.json(loadOrders("WHERE date(created_at) >= date('now', '-7 day') AND pay_status != 'awaiting'").slice(0, limit));
});

admin.patch('/orders/:id/status', (req, res) => {
  const seq = seqFromOrderId(req.params.id);
  const status = req.body.status;
  if (!ORDER_STATUSES.includes(status)) throw new HttpError(400, 'status មិនត្រឹមត្រូវ');
  // Cancelling restores stock (once)
  const updateStatus = tx(() => {
    const o = db.prepare('SELECT * FROM orders WHERE seq = ?').get(seq);
    if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
    if (o.pay_status === 'awaiting') throw new HttpError(409, 'ការកម្ម៉ង់នេះកំពុងរង់ចាំការបង់ប្រាក់ KHQR');
    if (o.status === status) return;
    if (status === 'cancelled') {
      for (const it of db.prepare('SELECT product_id, quantity FROM order_items WHERE order_seq = ?').all(seq)) {
        db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?').run(it.quantity, it.product_id);
      }
    } else if (o.status === 'cancelled') {
      throw new HttpError(409, 'ការកម្ម៉ង់ដែលបានបោះបង់ មិនអាចបើកឡើងវិញបានទេ');
    }
    db.prepare('UPDATE orders SET status = ? WHERE seq = ?').run(status, seq);
    if (status === 'cancelled') db.prepare("UPDATE orders SET pay_status = 'refunded' WHERE seq = ? AND pay_status = 'paid'").run(seq);
  });
  updateStatus();
  res.json(loadOrders('WHERE seq = ?', [seq])[0]);
});

// ---------------- Admin: payment ----------------
admin.post('/orders/:id/pay', (req, res) => {
  const seq = seqFromOrderId(req.params.id);
  const method = String(req.body.method ?? '');
  if (!['cash', 'khqr', 'other'].includes(method)) throw new HttpError(400, 'របៀបបង់ប្រាក់មិនត្រឹមត្រូវ');
  let cur = req.body.currency === 'KHR' ? 'KHR' : 'USD';
  let received = Number(req.body.received);
  tx(() => {
    const o = db.prepare('SELECT * FROM orders WHERE seq = ?').get(seq);
    if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
    if (o.status === 'cancelled') throw new HttpError(409, 'ការកម្ម៉ង់នេះត្រូវបានលុបចោល');
    if (o.pay_status === 'paid') throw new HttpError(409, 'បានបង់ប្រាក់រួចហើយ');
    if (o.pay_status === 'awaiting') throw new HttpError(409, 'ការកម្ម៉ង់នេះកំពុងរង់ចាំការបង់ប្រាក់ KHQR (ត្រូវផ្ទៀងផ្ទាត់ដោយប្រព័ន្ធ)');
    const rate = getRate();
    let changeUsd = 0;
    if (method === 'cash') {
      if (!Number.isFinite(received) || received <= 0 || received > 1e9) throw new HttpError(400, 'ចំនួនប្រាក់មិនត្រឹមត្រូវ');
      if (cur === 'USD') {
        if (received + 0.005 < o.total) throw new HttpError(400, 'ប្រាក់ទទួលមិនគ្រប់');
        changeUsd = Math.max(0, Math.round((received - o.total) * 100) / 100);
      } else {
        const need = khrOf(o.total, rate);          // riel total shown to the customer
        if (received < need) throw new HttpError(400, 'ប្រាក់ទទួលមិនគ្រប់');
        changeUsd = (received - need) / rate;       // change is given back in riel
      }
    } else { cur = 'USD'; received = o.total; }
    db.prepare("UPDATE orders SET pay_status = 'paid', pay_method = ?, received = ?, received_cur = ?, change_usd = ?, rate = ?, paid_at = datetime('now') WHERE seq = ?")
      .run(method, received, cur, changeUsd, rate, seq);
  })();
  res.json(loadOrders('WHERE seq = ?', [seq])[0]);
});

// ---------------- Admin: KHQR payments dashboard (owner only) ----------------
const adminPaymentOut = (p) => ({
  id: p.id, orderId: 'ORD-' + (1000 + p.order_seq), customer: p.customer_name, table: p.table_no, reference: p.reference,
  currency: p.currency, expected: fromMinor(p.currency, p.amount_minor),
  verified: p.verified_amount_minor == null ? null : fromMinor(p.verified_currency || p.currency, p.verified_amount_minor),
  verifiedCurrency: p.verified_currency, txHash: p.tx_hash, fromAccount: p.from_account, toAccount: p.to_account,
  status: p.status, env: p.env, createdAt: isoOf(p.created_at), expiresAt: isoOf(p.expires_at), verifiedAt: isoOf(p.verified_at),
  attempts: p.attempts, lastCheckedAt: isoOf(p.last_checked_at), lastError: p.last_error, note: p.note,
});

admin.get('/payments/health', (req, res) => {
  const counts = Object.fromEntries(['pending', 'paid', 'failed', 'expired', 'review'].map((k) => [k, 0]));
  for (const r of db.prepare('SELECT status, COUNT(*) AS n FROM payments GROUP BY status').all()) counts[r.status] = r.n;
  const oldest = db.prepare("SELECT MIN(created_at) AS t FROM payments WHERE status = 'pending'").get().t;
  const tk = BAKONG.token ? tokenInfo(BAKONG.token) : { expMs: null, daysLeft: null };
  let host = '';
  try { host = new URL(BAKONG.baseUrl).host; } catch (_) {}
  const warnings = [];
  if (!BAKONG_READY) warnings.push('KHQR checkout is OFF. Set BAKONG_TOKEN, BAKONG_ACCOUNT_ID and BAKONG_MERCHANT_NAME (see PAYMENT_SETUP.md).');
  if (BAKONG.env === 'sandbox') warnings.push('SANDBOX mode: QR codes are for testing only. Set BAKONG_ENV=production when you are ready.');
  if (BAKONG.env === 'production' && /sit-api/.test(BAKONG.baseUrl)) warnings.push('BAKONG_ENV=production but BAKONG_BASE_URL points to the sandbox.');
  if (tk.daysLeft !== null && tk.daysLeft <= 14) warnings.push(tk.daysLeft < 0 ? 'The Bakong token has EXPIRED. Renew it, then update BAKONG_TOKEN.' : `The Bakong token expires in ${tk.daysLeft} day(s). Renew it soon.`);
  if (workerState.consecutiveErrors >= 3) {
    warnings.push(`Verification is failing (${workerState.lastErrorState}): ${workerState.lastError}.` +
      (workerState.lastErrorState === 'forbidden' ? ' HTTP 403 often means the API refuses servers outside Cambodia. See PAYMENT_SETUP.md.' : ''));
  }
  if (oldest && Date.now() - parseSqlTime(oldest) > 20 * 60000) warnings.push('Some payments have been pending for over 20 minutes. Check the list below.');
  res.json({
    enabled: BAKONG_READY, env: BAKONG.env, apiHost: host, accountId: BAKONG.accountId || null, accountType: BAKONG.accountType,
    tokenDaysLeft: tk.daysLeft, worker: { lastRunAt: workerState.lastRunAt, lastSuccessAt: workerState.lastSuccessAt, lastError: workerState.lastError, consecutiveErrors: workerState.consecutiveErrors },
    counts, warnings,
  });
});

admin.get('/payments', (req, res) => {
  const where = [];
  const params = [];
  if (req.query.status && ['pending', 'paid', 'failed', 'expired', 'review'].includes(req.query.status)) { where.push('p.status = ?'); params.push(req.query.status); }
  const q = String(req.query.q ?? '').trim().slice(0, 80);
  if (q) {
    const m = /^ORD-?(\d+)$/i.exec(q);
    if (m) { where.push('p.order_seq = ?'); params.push(Number(m[1]) - 1000); }
    else { where.push('(p.reference LIKE ? OR p.tx_hash LIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  }
  const limit = Math.min(Number(req.query.limit) || 200, 500);
  const rows = db.prepare(`SELECT p.*, o.customer_name, o.table_no FROM payments p JOIN orders o ON o.seq = p.order_seq
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY p.id DESC LIMIT ?`).all(...params, limit);
  res.json(rows.map(adminPaymentOut));
});

// Ask Bakong again right now (for pending / expired / failed payments). Never trusts the browser: it just runs the same verification.
admin.post('/payments/:id/recheck', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const p = db.prepare('SELECT * FROM payments WHERE id = ?').get(id);
    if (!p) throw new HttpError(404, 'រកមិនឃើញការបង់ប្រាក់');
    if (!BAKONG_READY) throw new HttpError(503, 'KHQR មិនទាន់បើកទេ');
    if (p.last_checked_at && Date.now() - parseSqlTime(p.last_checked_at) < 3000) throw new HttpError(429, 'សូមរង់ចាំបន្តិច');
    await verifyPayment(id, { manual: true });
    const row = db.prepare('SELECT p.*, o.customer_name, o.table_no FROM payments p JOIN orders o ON o.seq = p.order_seq WHERE p.id = ?').get(id);
    res.json(adminPaymentOut(row));
  } catch (e) { next(e); }
});

// ---------------- Admin: settings ----------------
admin.get('/settings', (req, res) => {
  res.json({ exchangeRate: getRate(), khqrImage: getSetting('khqr_image', '') });
});
admin.put('/settings', (req, res) => {
  const rate = Number(req.body.exchangeRate);
  if (!Number.isFinite(rate) || rate < 100 || rate > 100000) throw new HttpError(400, 'អត្រាប្តូរប្រាក់មិនត្រឹមត្រូវ');
  const oldQr = getSetting('khqr_image', '');
  const qr = parseImage(req.body.khqrImage, false);
  setSetting('exchange_rate', rate);
  setSetting('khqr_image', qr);
  if (oldQr && oldQr !== qr) removeUploadIfUnused(oldQr);
  res.json({ exchangeRate: getRate(), khqrImage: getSetting('khqr_image', '') });
});

// ---------------- Admin: reports ----------------
function reportRange(q) {
  const ok = (d) => /^\d{4}-\d{2}-\d{2}$/.test(String(d)) && !Number.isNaN(Date.parse(d));
  const today = db.prepare('SELECT date(\'now\', ?) AS d').get(TZ_MOD).d;
  const from = ok(q.from) ? q.from : today;
  const to = ok(q.to) ? q.to : today;
  if (from > to) throw new HttpError(400, 'កាលបរិច្ឆេទមិនត្រឹមត្រូវ');
  if ((Date.parse(to) - Date.parse(from)) / 864e5 > 366) throw new HttpError(400, 'ជ្រើសរើសរយៈពេលមិនលើស ១ ឆ្នាំ');
  return { from, to };
}

admin.get('/reports', (req, res) => {
  const { from, to } = reportRange(req.query);
  const W = "status != 'cancelled' AND pay_status != 'awaiting' AND date(created_at, ?) BETWEEN ? AND ?";
  const p = [TZ_MOD, from, to];
  const sum = db.prepare(`SELECT COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue,
      COALESCE(SUM(CASE WHEN pay_status='paid' THEN total END),0) AS paid FROM orders WHERE ${W}`).get(...p);
  const cancelled = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status = 'cancelled' AND pay_status != 'expired' AND date(created_at, ?) BETWEEN ? AND ?").get(...p).n;
  const daily = db.prepare(`SELECT date(created_at, ?) AS d, COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue
      FROM orders WHERE status != 'cancelled' AND pay_status != 'awaiting' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY d ORDER BY d`).all(TZ_MOD, ...p);
  const hourly = db.prepare(`SELECT CAST(strftime('%H', created_at, ?) AS INTEGER) AS h, COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue
      FROM orders WHERE status != 'cancelled' AND pay_status != 'awaiting' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY h ORDER BY h`).all(TZ_MOD, ...p);
  const top = db.prepare(`SELECT oi.name AS name, SUM(oi.quantity) AS qty, SUM(oi.quantity * oi.price) AS revenue
      FROM order_items oi JOIN orders o ON o.seq = oi.order_seq
      WHERE o.status != 'cancelled' AND o.pay_status != 'awaiting' AND date(o.created_at, ?) BETWEEN ? AND ?
      GROUP BY oi.name ORDER BY qty DESC, revenue DESC LIMIT 10`).all(...p);
  const methods = db.prepare(`SELECT pay_method AS method, COUNT(*) AS orders, COALESCE(SUM(total),0) AS total
      FROM orders WHERE status != 'cancelled' AND pay_status != 'awaiting' AND pay_status = 'paid' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY pay_method`).all(...p);
  const r2 = (n) => Math.round(n * 100) / 100;
  res.json({
    from, to, rate: getRate(),
    summary: {
      orders: sum.orders, revenue: r2(sum.revenue), paid: r2(sum.paid), unpaid: r2(sum.revenue - sum.paid),
      avgOrder: sum.orders ? r2(sum.revenue / sum.orders) : 0, cancelled,
    },
    daily: daily.map((d) => ({ ...d, revenue: r2(d.revenue) })),
    hourly: hourly.map((h) => ({ ...h, revenue: r2(h.revenue) })),
    top: top.map((t) => ({ ...t, revenue: r2(t.revenue) })),
    methods: methods.map((m) => ({ ...m, total: r2(m.total) })),
  });
});

admin.get('/reports/export', (req, res) => {
  const { from, to } = reportRange(req.query);
  const rows = loadOrders("WHERE date(created_at, ?) BETWEEN ? AND ? AND pay_status != 'awaiting'", [TZ_MOD, from, to]).reverse();
  const q = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const local = (iso) => new Date(Date.parse(iso) + TZ_HOURS * 3600e3).toISOString().replace('T', ' ').slice(0, 16);
  const head = ['Order', 'Date', 'Customer', 'Table', 'Items', 'Total USD', 'Status', 'Payment status', 'Method', 'Received', 'Currency', 'Change USD'];
  const lines = [head.map(q).join(',')];
  for (const o of rows) {
    lines.push([
      o.id, local(o.createdAt), o.customerName, o.tableNo,
      o.items.map((i) => `${i.name} x${i.quantity}${i.sugar ? ' (' + i.sugar + ')' : ''}`).join('; '),
      o.total.toFixed(2), o.status, o.payStatus, o.payMethod,
      o.payStatus === 'paid' ? o.received : '', o.payStatus === 'paid' ? o.receivedCur : '',
      o.payStatus === 'paid' ? o.changeUsd.toFixed(2) : '',
    ].map(q).join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sales-${from}_${to}.csv"`);
  res.send('\ufeff' + lines.join('\r\n')); // BOM so Excel reads Khmer correctly
});

// ---------------- Admin: backups ----------------
function makeBackup(kind) {
  const stamp = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const name = `mlob-${kind}-${stamp}.db`;
  db.prepare('VACUUM INTO ?').run(path.join(BACKUP_DIR, name)); // consistent snapshot, safe while the DB is in use
  return name;
}
function listBackups() {
  return fs.readdirSync(BACKUP_DIR).filter((n) => /^mlob-auto-\d{14}\.db$/.test(n)).sort().reverse().map((name) => {
    const st = fs.statSync(path.join(BACKUP_DIR, name));
    return { name, size: st.size, createdAt: st.mtime.toISOString() };
  });
}
function autoBackup() {
  try {
    const last = listBackups()[0];
    if (!last || Date.now() - Date.parse(last.createdAt) > 20 * 3600e3) makeBackup('auto');
    for (const b of listBackups().slice(7)) fs.unlink(path.join(BACKUP_DIR, b.name), () => {}); // keep the newest 7
  } catch (e) { console.error('Auto-backup failed:', e.message); }
}

admin.get('/backup', (req, res, next) => {
  const name = makeBackup('manual');
  const file = path.join(BACKUP_DIR, name);
  res.download(file, name, (err) => { fs.unlink(file, () => {}); if (err && !res.headersSent) next(err); });
});
admin.get('/backups', (req, res) => res.json(listBackups()));
admin.get('/backups/:name', (req, res) => {
  const name = String(req.params.name);
  if (!/^mlob-auto-\d{14}\.db$/.test(name) || !fs.existsSync(path.join(BACKUP_DIR, name))) throw new HttpError(404, 'រកមិនឃើញ Backup');
  res.download(path.join(BACKUP_DIR, name), name);
});

// ---------------- Admin: users & roles (owner only via the gate above) ----------------
const ROLES = ['owner', 'cashier'];
const ownersCount = () => db.prepare("SELECT COUNT(*) AS n FROM admins WHERE role = 'owner'").get().n;

admin.get('/users', (req, res) => {
  res.json(db.prepare('SELECT id, username, role, created_at FROM admins ORDER BY id').all());
});
admin.post('/users', (req, res) => {
  const username = String(req.body.username ?? '').trim();
  const password = String(req.body.password ?? '');
  const role = String(req.body.role ?? 'cashier');
  if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username)) throw new HttpError(400, 'ឈ្មោះគណនីត្រូវមាន 3-30 តួ (អក្សរ លេខ _ . -)');
  if (password.length < 6) throw new HttpError(400, 'ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ');
  if (!ROLES.includes(role)) throw new HttpError(400, 'តួនាទីមិនត្រឹមត្រូវ');
  if (db.prepare('SELECT 1 FROM admins WHERE username = ?').get(username)) throw new HttpError(409, 'ឈ្មោះគណនីនេះមានរួចហើយ');
  const { lastInsertRowid: id } = db.prepare('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)').run(username, bcrypt.hashSync(password, 10), role);
  res.status(201).json(db.prepare('SELECT id, username, role, created_at FROM admins WHERE id = ?').get(id));
});
admin.patch('/users/:id', (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM admins WHERE id = ?').get(id);
  if (!u) throw new HttpError(404, 'រកមិនឃើញអ្នកប្រើ');
  if (req.body.role !== undefined) {
    if (!ROLES.includes(req.body.role)) throw new HttpError(400, 'តួនាទីមិនត្រឹមត្រូវ');
    if (u.role === 'owner' && req.body.role !== 'owner' && ownersCount() <= 1) throw new HttpError(400, 'ត្រូវមានម្ចាស់ហាងយ៉ាងតិចម្នាក់');
    db.prepare('UPDATE admins SET role = ? WHERE id = ?').run(req.body.role, id);
  }
  if (req.body.password !== undefined) {
    const pw = String(req.body.password);
    if (pw.length < 6) throw new HttpError(400, 'ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ');
    db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(pw, 10), id);
  }
  res.json(db.prepare('SELECT id, username, role, created_at FROM admins WHERE id = ?').get(id));
});
admin.delete('/users/:id', (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM admins WHERE id = ?').get(id);
  if (!u) throw new HttpError(404, 'រកមិនឃើញអ្នកប្រើ');
  if (id === req.admin.id) throw new HttpError(400, 'មិនអាចលុបគណនីរបស់ខ្លួនឯងបានទេ');
  if (u.role === 'owner' && ownersCount() <= 1) throw new HttpError(400, 'ត្រូវមានម្ចាស់ហាងយ៉ាងតិចម្នាក់');
  db.prepare('DELETE FROM admins WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.use('/api/admin', admin);

// ---------------- Static ----------------
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', setHeaders: (res) => res.setHeader('X-Content-Type-Options', 'nosniff') }));
app.use(express.static(PUBLIC_DIR));

app.use('/api', (req, res) => res.status(404).json({ error: 'រកមិនឃើញ API នេះទេ' }));

// ---------------- Errors ----------------
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'ទំហំរូបភាពធំពេក (អតិបរមា 5MB)' : err.message });
  }
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON មិនត្រឹមត្រូវ' });
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'កំហុសម៉ាស៊ីនបម្រើ' : err.message });
});

if (require.main === module) {
  console.log(BAKONG_READY
    ? `💳 KHQR checkout ON (${BAKONG.env}, API ${BAKONG.baseUrl})`
    : '💳 KHQR checkout OFF (set BAKONG_TOKEN, BAKONG_ACCOUNT_ID, BAKONG_MERCHANT_NAME to enable)');
  setInterval(() => paymentWorkerTick().catch((e) => console.error(e.message)), 2000).unref();
  autoBackup();                                   // on start (skipped if one exists from the last 20h)
  setInterval(autoBackup, 6 * 3600e3).unref();    // then check every 6h
  app.listen(PORT, () => console.log(`☕ Mlob Doung Coffee running on http://localhost:${PORT}`));
}
// Test hook (only when NODE_ENV=test) so the payment state machine can be exercised without HTTP
if (process.env.NODE_ENV === 'test') app.__test = { verifyPayment, paymentWorkerTick, cancelAwaitingOrders, db };
module.exports = app;
