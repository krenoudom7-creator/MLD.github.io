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

const CATEGORIES = ['coffee', 'tea', 'drink', 'bakery'];
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
  discount: r.discount || 0, finalPrice: finalPrice(r.price, r.discount),
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

// ---------------- Public POS API ----------------
// Menu for the POS screen (active products only)
app.get('/api/products', (req, res) => {
  const rows = db.prepare(`SELECT * FROM products WHERE status = 'active' ORDER BY created_at DESC, rowid DESC`).all();
  res.json(rows.map(productOut));
});

// Public settings (exchange rate + KHQR image for paying)
app.get('/api/settings', (req, res) => {
  res.json({ exchangeRate: getRate(), khqrImage: getSetting('khqr_image', '') });
});

// Customer order tracking: only reachable with the unguessable code returned when ordering
const trackLimiter = rateLimit({ windowMs: 60 * 1000, max: 90, standardHeaders: true, legacyHeaders: false,
  message: { error: 'សូមរង់ចាំបន្តិច' } });
app.get('/api/orders/track/:code', trackLimiter, (req, res) => {
  const code = String(req.params.code);
  if (!/^[\w-]{8,40}$/.test(code)) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const o = loadOrders('WHERE track_code = ?', [code])[0];
  if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
  const ahead = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status IN ('pending','preparing') AND seq < ?").get(seqFromOrderId(o.id)).n;
  res.json({
    id: o.id, status: o.status, payStatus: o.payStatus, total: o.total, createdAt: o.createdAt,
    queueAhead: (o.status === 'pending' || o.status === 'preparing') ? ahead : 0,
    items: o.items.map((i) => ({ name: i.name, quantity: i.quantity })),
  });
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

  const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
  const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?');
  const trackCode = crypto.randomBytes(9).toString('base64url');
  const insOrder = db.prepare('INSERT INTO orders (customer_name, table_no, total, track_code) VALUES (?, ?, 0, ?)');
  const insItem = db.prepare('INSERT INTO order_items (order_seq, product_id, name, price, quantity, sugar, note) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const setTotal = db.prepare('UPDATE orders SET total = ? WHERE seq = ?');

  const create = tx(() => {
    const { lastInsertRowid: seq } = insOrder.run(customerName, tableNo, trackCode);
    let total = 0;
    for (const it of items) {
      const qty = Number(it.quantity);
      if (!Number.isInteger(qty) || qty < 1 || qty > 99) throw new HttpError(400, 'ចំនួនមិនត្រឹមត្រូវ');
      const p = getProduct.get(String(it.id));
      if (!p || p.status !== 'active') throw new HttpError(409, `ទំនិញ "${it.name ?? it.id}" មិនមានលក់ទៀតទេ`);
      if (decStock.run(qty, p.id, qty).changes === 0) throw new HttpError(409, `ទំនិញ "${p.name}" អស់ស្តុក ឬមិនគ្រប់ចំនួន (នៅសល់ ${p.stock})`);
      const sugar = String(it.sugar ?? '').slice(0, 20);
      const note = String(it.note ?? '').replace(/\s+/g, ' ').trim().slice(0, 100);
      const unit = finalPrice(p.price, p.discount); // discounted unit price, computed on the server
      insItem.run(seq, p.id, p.name, unit, qty, sugar, note);
      total += unit * qty;
    }
    total = Math.round(total * 100) / 100;
    setTotal.run(total, seq);
    return seq;
  });

  const seq = create();
  res.status(201).json({ ...loadOrders('WHERE seq = ?', [seq])[0], trackCode });
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
    return res.json(loadOrders('WHERE status = ?', [status]).slice(0, limit));
  }
  res.json(loadOrders("WHERE date(created_at) >= date('now', '-7 day')").slice(0, limit));
});

admin.patch('/orders/:id/status', (req, res) => {
  const seq = seqFromOrderId(req.params.id);
  const status = req.body.status;
  if (!ORDER_STATUSES.includes(status)) throw new HttpError(400, 'status មិនត្រឹមត្រូវ');
  // Cancelling restores stock (once)
  const updateStatus = tx(() => {
    const o = db.prepare('SELECT * FROM orders WHERE seq = ?').get(seq);
    if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
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
  const W = "status != 'cancelled' AND date(created_at, ?) BETWEEN ? AND ?";
  const p = [TZ_MOD, from, to];
  const sum = db.prepare(`SELECT COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue,
      COALESCE(SUM(CASE WHEN pay_status='paid' THEN total END),0) AS paid FROM orders WHERE ${W}`).get(...p);
  const cancelled = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status = 'cancelled' AND date(created_at, ?) BETWEEN ? AND ?").get(...p).n;
  const daily = db.prepare(`SELECT date(created_at, ?) AS d, COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue
      FROM orders WHERE status != 'cancelled' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY d ORDER BY d`).all(TZ_MOD, ...p);
  const hourly = db.prepare(`SELECT CAST(strftime('%H', created_at, ?) AS INTEGER) AS h, COUNT(*) AS orders, COALESCE(SUM(total),0) AS revenue
      FROM orders WHERE status != 'cancelled' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY h ORDER BY h`).all(TZ_MOD, ...p);
  const top = db.prepare(`SELECT oi.name AS name, SUM(oi.quantity) AS qty, SUM(oi.quantity * oi.price) AS revenue
      FROM order_items oi JOIN orders o ON o.seq = oi.order_seq
      WHERE o.status != 'cancelled' AND date(o.created_at, ?) BETWEEN ? AND ?
      GROUP BY oi.name ORDER BY qty DESC, revenue DESC LIMIT 10`).all(...p);
  const methods = db.prepare(`SELECT pay_method AS method, COUNT(*) AS orders, COALESCE(SUM(total),0) AS total
      FROM orders WHERE status != 'cancelled' AND pay_status = 'paid' AND date(created_at, ?) BETWEEN ? AND ? GROUP BY pay_method`).all(...p);
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
  const rows = loadOrders('WHERE date(created_at, ?) BETWEEN ? AND ?', [TZ_MOD, from, to]).reverse();
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
  autoBackup();                                   // on start (skipped if one exists from the last 20h)
  setInterval(autoBackup, 6 * 3600e3).unref();    // then check every 6h
  app.listen(PORT, () => console.log(`☕ Mlob Doung Coffee running on http://localhost:${PORT}`));
}
module.exports = app;
