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
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');   // e.g. /var/data/db on a Render disk
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'); // e.g. /var/data/uploads
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

const CATEGORIES = ['coffee', 'tea', 'drink', 'bakery', 'food'];
const FOOD_CATS = ['bakery', 'food']; // food items have no sugar level, only a note
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
if (!hasCol('admins', 'must_change')) {
  db.exec('ALTER TABLE admins ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0');
  // Existing accounts still using the well-known default password must change it at next login
  for (const a of db.prepare('SELECT id, password_hash FROM admins').all()) {
    if (bcrypt.compareSync('123456', a.password_hash)) db.prepare('UPDATE admins SET must_change = 1 WHERE id = ?').run(a.id);
  }
}
for (const [col, ddl] of [
  ['pay_status', "TEXT NOT NULL DEFAULT 'unpaid'"],   // unpaid | paid | refunded
  ['pay_method', "TEXT NOT NULL DEFAULT ''"],         // cash | khqr | other
  ['received', 'REAL NOT NULL DEFAULT 0'],
  ['received_cur', "TEXT NOT NULL DEFAULT 'USD'"],
  ['change_usd', 'REAL NOT NULL DEFAULT 0'],
  ['rate', 'REAL NOT NULL DEFAULT 0'],
  ['paid_at', 'TEXT'],
  ['track_code', 'TEXT'],
  ['ip', "TEXT NOT NULL DEFAULT ''"],
]) {
  if (!hasCol('orders', col)) db.exec(`ALTER TABLE orders ADD COLUMN ${col} ${ddl}`);
}
db.exec('CREATE INDEX IF NOT EXISTS idx_orders_track ON orders(track_code)');
if (!hasCol('products', 'options')) db.exec("ALTER TABLE products ADD COLUMN options TEXT NOT NULL DEFAULT '[]'");
if (!hasCol('order_items', 'options')) db.exec("ALTER TABLE order_items ADD COLUMN options TEXT NOT NULL DEFAULT ''");
if (!hasCol('orders', 'status_at')) db.exec('ALTER TABLE orders ADD COLUMN status_at TEXT'); // when the status last changed (queue board)
if (!hasCol('order_items', 'kind')) { // 'drink' | 'food' snapshot, so old orders keep their meaning if a product changes category
  db.exec("ALTER TABLE order_items ADD COLUMN kind TEXT NOT NULL DEFAULT 'drink'");
  db.exec("UPDATE order_items SET kind = 'food' WHERE product_id IN (SELECT id FROM products WHERE category IN ('bakery','food'))");
}
db.exec(`CREATE TABLE IF NOT EXISTS shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  opened_at TEXT NOT NULL DEFAULT (datetime('now')), opened_by TEXT NOT NULL,
  open_usd REAL NOT NULL DEFAULT 0, open_khr REAL NOT NULL DEFAULT 0,
  closed_at TEXT, closed_by TEXT, count_usd REAL, count_khr REAL, exp_usd REAL, exp_khr REAL,
  note TEXT NOT NULL DEFAULT ''
)`);
db.exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
db.exec(`CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL DEFAULT (datetime('now')),
  admin_id INTEGER, username TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT ''
)`);
// Who did what. `req` may be null (system actions) or any object with .admin
const audit = (req, action, target = '', detail = '') => {
  try {
    db.prepare('INSERT INTO audit_log (admin_id, username, action, target, detail) VALUES (?, ?, ?, ?, ?)')
      .run(req && req.admin ? req.admin.id : null, req && req.admin ? req.admin.username : 'system', action, String(target).slice(0, 80), String(detail).slice(0, 300));
  } catch (e) { console.error('audit failed:', e.message); }
};

// ---- Telegram (optional: set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID) ----
const TG_API = process.env.TELEGRAM_API || 'https://api.telegram.org';
const tgOn = () => !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID);
async function tgSend(text) {
  if (!tgOn()) return false;
  try {
    const r = await fetch(`${TG_API}/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: process.env.TELEGRAM_CHAT_ID, text: String(text).slice(0, 3900) }), signal: AbortSignal.timeout(10000),
    });
    return r.ok;
  } catch (e) { console.error('Telegram:', e.message); return false; }
}
async function tgSendFile(file, caption) {
  if (!tgOn()) return false;
  try {
    const fd = new FormData();
    fd.append('chat_id', process.env.TELEGRAM_CHAT_ID);
    fd.append('caption', caption);
    fd.append('document', new Blob([fs.readFileSync(file)]), path.basename(file));
    const r = await fetch(`${TG_API}/bot${process.env.TELEGRAM_BOT_TOKEN}/sendDocument`, { method: 'POST', body: fd, signal: AbortSignal.timeout(60000) });
    return r.ok;
  } catch (e) { console.error('Telegram file:', e.message); return false; }
}
function tgAfterOrder(order, items) {
  if (!tgOn()) return;
  const lines = order.items.map((i) => `• ${i.name} ×${i.quantity}${i.options && i.options.length ? ' [' + i.options.map((o) => o.label).join('/') + ']' : ''}${i.sugar ? ' (ស្ករ ' + i.sugar + ')' : ''}${i.note ? ' 📝 ' + i.note : ''}`).join('\n');
  tgSend(`🔔 ការកម្ម៉ង់ថ្មី ${order.id}\n👤 ${order.customerName} · ${order.tableNo}\n${lines}\n💰 $${order.total.toFixed(2)}`);
  const low = Number(process.env.LOW_STOCK ?? 5), qty = {};
  for (const it of items) qty[it.id] = (qty[it.id] || 0) + Number(it.quantity);
  for (const [pid, q] of Object.entries(qty)) {
    const p = db.prepare('SELECT name, stock FROM products WHERE id = ?').get(pid);
    if (p && p.stock <= low && p.stock + q > low) tgSend(`⚠️ ស្តុកជិតអស់: ${p.name} នៅសល់ ${p.stock}`);
  }
}

// ---- Housekeeping: auto-cancel stale unaccepted orders + daily Telegram summary ----
function expireStale() {
  const ttl = Number(process.env.PENDING_TTL_MIN ?? 20); // 0 disables
  if (!(ttl > 0)) return;
  const rows = db.prepare("SELECT seq FROM orders WHERE status = 'pending' AND pay_status = 'unpaid' AND created_at < datetime('now', ?)").all(`-${ttl} minutes`);
  for (const r of rows) {
    tx(() => {
      const o = db.prepare('SELECT status FROM orders WHERE seq = ?').get(r.seq);
      if (!o || o.status !== 'pending') return;
      for (const it of db.prepare('SELECT product_id, quantity FROM order_items WHERE order_seq = ?').all(r.seq)) {
        db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?').run(it.quantity, it.product_id);
      }
      db.prepare("UPDATE orders SET status = 'cancelled' WHERE seq = ?").run(r.seq);
      audit(null, 'order_auto_cancel', 'ORD-' + (1000 + r.seq), `មិនទាន់ទទួលយកក្នុង ${ttl} នាទី`);
    })();
  }
}
function dailySummaryIfDue() {
  const hour = Number(process.env.SUMMARY_HOUR ?? 21);
  if (!tgOn() || !(hour >= 0 && hour <= 23)) return;
  const local = new Date(Date.now() + TZ_HOURS * 3600e3), today = local.toISOString().slice(0, 10);
  if (local.getUTCHours() < hour || getSetting('last_summary', '') === today) return;
  setSetting('last_summary', today);
  const p = [TZ_MOD, today, today];
  const s = db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(total),0) AS rev, COALESCE(SUM(CASE WHEN pay_status='paid' THEN total END),0) AS paid FROM orders WHERE status != 'cancelled' AND date(created_at, ?) BETWEEN ? AND ?").get(...p);
  const c = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status = 'cancelled' AND date(created_at, ?) BETWEEN ? AND ?").get(...p).n;
  const top = db.prepare("SELECT oi.name AS name, SUM(oi.quantity) AS q FROM order_items oi JOIN orders o ON o.seq = oi.order_seq WHERE o.status != 'cancelled' AND date(o.created_at, ?) BETWEEN ? AND ? GROUP BY oi.name ORDER BY q DESC LIMIT 3").all(...p);
  tgSend(`📊 សរុបលក់ថ្ងៃនេះ (${today})\nការកម្ម៉ង់: ${s.n} (លុប ${c})\nចំណូល: $${s.rev.toFixed(2)}\nបានទទួលប្រាក់: $${s.paid.toFixed(2)}\nមិនទាន់បង់: $${(s.rev - s.paid).toFixed(2)}` +
    (top.length ? '\n🏆 ' + top.map((t) => `${t.name} ×${t.q}`).join(', ') : ''));
}
function maintenance() {
  try { expireStale(); dailySummaryIfDue(); } catch (e) { console.error('maintenance:', e.message); }
}

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
  db.prepare("INSERT INTO admins (username, password_hash, role, must_change) VALUES (?, ?, 'owner', ?)").run(u, bcrypt.hashSync(p, 10), process.env.ADMIN_PASSWORD ? 0 : 1);
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
const safeParse = (t) => { try { const v = JSON.parse(t || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } };

const productOut = (r) => ({
  id: r.id, name: r.name, category: r.category, price: r.price, stock: r.stock,
  discount: r.discount || 0, finalPrice: finalPrice(r.price, r.discount),
  status: r.status, description: r.description, image: r.image, options: safeParse(r.options), created_at: r.created_at,
});

function loadOrders(whereSql = '', params = []) {
  const rows = db.prepare(`SELECT * FROM orders ${whereSql} ORDER BY seq DESC`).all(...params);
  if (!rows.length) return [];
  const itemsStmt = db.prepare('SELECT name, price, quantity, sugar, note, options, kind FROM order_items WHERE order_seq = ? ORDER BY id');
  return rows.map((o) => ({
    id: 'ORD-' + (1000 + o.seq),
    customerName: o.customer_name,
    tableNo: o.table_no,
    items: itemsStmt.all(o.seq).map((i) => ({ ...i, options: safeParse(i.options) })),
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

// Option groups (size, ice, toppings...): [{ name, choices: [{ label, price }] }], one choice per group, first is the default
function parseOptions(v) {
  if (v === undefined || v === null || v === '') return [];
  const arr = typeof v === 'string' ? safeParse(v) : v;
  if (!Array.isArray(arr) || arr.length > 5) throw new HttpError(400, 'ជម្រើសបន្ថែមមិនត្រឹមត្រូវ (អតិបរមា ៥ ក្រុម)');
  return arr.map((g) => {
    const name = String((g && g.name) ?? '').trim().slice(0, 30);
    const ch = g && Array.isArray(g.choices) ? g.choices : [];
    if (!name || ch.length < 1 || ch.length > 8) throw new HttpError(400, `ក្រុមជម្រើស "${name}" ត្រូវមាន 1-8 ជម្រើស`);
    return { name, choices: ch.map((c) => {
      const label = String((c && c.label) ?? '').trim().slice(0, 30), price = Math.round(Number((c && c.price) ?? 0) * 100) / 100;
      if (!label || !Number.isFinite(price) || price < 0 || price > 50) throw new HttpError(400, `ជម្រើស "${label}" មិនត្រឹមត្រូវ`);
      return { label, price };
    }) };
  });
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
  if (!partial || has('options')) out.options = JSON.stringify(parseOptions(body.options));
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
// Same-origin only by default. Set CORS_ORIGIN=https://your-front-end (comma separated) to allow another site.
if (process.env.CORS_ORIGIN) app.use(cors({ origin: process.env.CORS_ORIGIN.split(',') }));
app.use(express.json({ limit: '100kb' }));

// Auth middleware
function requireAdmin(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return next(new HttpError(401, 'តម្រូវឱ្យចូលប្រើជា Admin'));
  let a;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Always read role from DB so a removed user / changed role takes effect immediately
    a = db.prepare('SELECT id, username, role, must_change FROM admins WHERE id = ?').get(payload.sub);
    if (!a) throw new Error('admin removed');
  } catch {
    return next(new HttpError(401, 'Session ផុតកំណត់ សូមចូលប្រើម្តងទៀត'));
  }
  req.admin = { id: a.id, username: a.username, role: a.role, mustChange: !!a.must_change };
  // Default password in use: nothing works except changing it
  if (req.admin.mustChange && !req.originalUrl.startsWith('/api/auth/')) return next(new HttpError(403, 'សូមប្តូរពាក្យសម្ងាត់លំនាំដើមជាមុនសិន'));
  next();
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
  if (!admin || !ok) { audit(null, 'login_failed', username.slice(0, 40), 'IP ' + req.ip); return res.status(401).json({ error: 'ឈ្មោះអ្នកប្រើ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ!' }); }
  const token = jwt.sign({ sub: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  audit({ admin }, 'login', '', 'IP ' + req.ip);
  res.json({ token, admin: { id: admin.id, username: admin.username, role: admin.role, mustChange: !!admin.must_change } });
});

app.get('/api/auth/me', requireAdmin, (req, res) => res.json({ admin: req.admin }));

app.post('/api/auth/change-password', requireAdmin, (req, res) => {
  const current = String(req.body.currentPassword ?? '');
  const next = String(req.body.newPassword ?? '');
  if (next.length < 6) throw new HttpError(400, 'ពាក្យសម្ងាត់ថ្មីត្រូវមានយ៉ាងតិច ៦ តួអក្សរ');
  if (next === '123456' || next === current) throw new HttpError(400, 'សូមជ្រើសពាក្យសម្ងាត់ថ្មីដែលខុសពីមុន និងមិនងាយទាយ');
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.admin.id);
  if (!bcrypt.compareSync(current, admin.password_hash)) throw new HttpError(400, 'ពាក្យសម្ងាត់បច្ចុប្បន្នមិនត្រឹមត្រូវ');
  db.prepare('UPDATE admins SET password_hash = ?, must_change = 0 WHERE id = ?').run(bcrypt.hashSync(next, 10), admin.id);
  audit(req, 'password_change');
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
  res.json({ exchangeRate: getRate(), khqrImage: getSetting('khqr_image', ''), orderingPaused: getSetting('ordering_paused', '0') === '1' });
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

// ---- Queue board (TV in the shop): order NUMBERS only, never names ----
const boardLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, message: { error: 'សូមរង់ចាំបន្តិច' } });
app.get('/api/board', boardLimiter, (req, res) => {
  const rows = db.prepare(`SELECT seq, status FROM orders
    WHERE (status IN ('pending','preparing') AND created_at >= datetime('now','-6 hours'))
       OR (status = 'completed' AND COALESCE(status_at, created_at) >= datetime('now','-15 minutes')) ORDER BY seq`).all();
  res.json({
    preparing: rows.filter((r) => r.status !== 'completed').map((r) => 1000 + r.seq),
    ready: rows.filter((r) => r.status === 'completed').map((r) => 1000 + r.seq),
  });
});

// ---- Smart upsell: what customers actually bought together (no personal data used) ----
app.get('/api/upsell', boardLimiter, (req, res) => {
  const ids = String(req.query.ids || '').split(',').filter((x) => /^[\w-]{1,60}$/.test(x)).slice(0, 10);
  if (!ids.length) return res.json([]);
  const ph = ids.map(() => '?').join(',');
  const seedTotal = db.prepare(`SELECT COUNT(DISTINCT oi.order_seq) AS n FROM order_items oi JOIN orders o ON o.seq = oi.order_seq
    WHERE oi.product_id IN (${ph}) AND o.status != 'cancelled' AND o.created_at >= datetime('now','-90 days')`).get(...ids).n;
  let rows, mode;
  if (seedTotal >= 5) { // enough history: "bought together"
    mode = 'together';
    rows = db.prepare(`SELECT oi.product_id AS id, COUNT(DISTINCT oi.order_seq) AS n FROM order_items oi
      WHERE oi.order_seq IN (SELECT oi2.order_seq FROM order_items oi2 JOIN orders o ON o.seq = oi2.order_seq
        WHERE oi2.product_id IN (${ph}) AND o.status != 'cancelled' AND o.created_at >= datetime('now','-90 days'))
      AND oi.product_id NOT IN (${ph}) GROUP BY oi.product_id HAVING n >= 2 ORDER BY n DESC LIMIT 8`).all(...ids, ...ids);
  } else { // little history: honest fallback to best sellers, no percentages
    mode = 'popular';
    rows = db.prepare(`SELECT oi.product_id AS id, SUM(oi.quantity) AS n FROM order_items oi JOIN orders o ON o.seq = oi.order_seq
      WHERE o.status != 'cancelled' AND o.created_at >= datetime('now','-30 days') AND oi.product_id NOT IN (${ph})
      GROUP BY oi.product_id HAVING n >= 3 ORDER BY n DESC LIMIT 8`).all(...ids);
  }
  const get = db.prepare("SELECT * FROM products WHERE id = ? AND status = 'active' AND stock > 0");
  const out = [];
  for (const r of rows) {
    const p = get.get(r.id);
    if (p) out.push({ id: p.id, name: p.name, price: finalPrice(p.price, p.discount), image: p.image, mode, pct: mode === 'together' ? Math.round((r.n / seedTotal) * 100) : null });
    if (out.length === 3) break;
  }
  res.json(out);
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
  if (getSetting('ordering_paused', '0') === '1') throw new HttpError(409, 'ហាងកំពុងផ្អាកទទួលការកម្ម៉ង់ជាបណ្តោះអាសន្ន សូមព្យាយាមម្តងទៀតបន្តិចក្រោយ');
  const customerName = String(req.body.customerName ?? '').trim().slice(0, 80) || 'អតិថិជនទូទៅ';
  const tableNo = String(req.body.tableNo ?? '').trim().slice(0, 40) || 'តុទូទៅ';
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (!items.length || items.length > 50) throw new HttpError(400, 'កន្ត្រកទទេ ឬធំពេក');
  const perIp = Number(process.env.PENDING_PER_IP ?? 10);
  if (perIp > 0 && db.prepare("SELECT COUNT(*) AS n FROM orders WHERE ip = ? AND status = 'pending'").get(req.ip || '').n >= perIp)
    throw new HttpError(429, 'មានការកម្ម៉ង់កំពុងរង់ចាំច្រើនពេក សូមរង់ចាំបុគ្គលិកទទួលយកជាមុន');

  const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
  const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?');
  const trackCode = crypto.randomBytes(9).toString('base64url');
  const insOrder = db.prepare('INSERT INTO orders (customer_name, table_no, total, track_code, ip) VALUES (?, ?, 0, ?, ?)');
  const insItem = db.prepare('INSERT INTO order_items (order_seq, product_id, name, price, quantity, sugar, note, options, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const setTotal = db.prepare('UPDATE orders SET total = ? WHERE seq = ?');

  const create = tx(() => {
    const { lastInsertRowid: seq } = insOrder.run(customerName, tableNo, trackCode, req.ip || '');
    let total = 0;
    for (const it of items) {
      const qty = Number(it.quantity);
      if (!Number.isInteger(qty) || qty < 1 || qty > 99) throw new HttpError(400, 'ចំនួនមិនត្រឹមត្រូវ');
      const p = getProduct.get(String(it.id));
      if (!p || p.status !== 'active') throw new HttpError(409, `ទំនិញ "${it.name ?? it.id}" មិនមានលក់ទៀតទេ`);
      if (decStock.run(qty, p.id, qty).changes === 0) throw new HttpError(409, `ទំនិញ "${p.name}" អស់ស្តុក ឬមិនគ្រប់ចំនួន (នៅសល់ ${p.stock})`);
      const food = FOOD_CATS.includes(p.category);
      const sugar = food ? '' : String(it.sugar ?? '').slice(0, 20); // food never carries a sugar level
      const note = String(it.note ?? '').replace(/\s+/g, ' ').trim().slice(0, 100);
      // chosen options are re-validated against the product's own option groups; price delta comes from the server
      const picked = Array.isArray(it.options) ? it.options : [], chosen = [];
      for (const g of safeParse(p.options)) {
        const want = picked.find((x) => x && x.group === g.name);
        const c = want ? g.choices.find((x) => x.label === want.label) : g.choices[0];
        if (!c) throw new HttpError(400, `ជម្រើស "${g.name}" មិនត្រឹមត្រូវ`);
        chosen.push({ group: g.name, label: c.label, price: c.price });
      }
      const unit = Math.round((finalPrice(p.price, p.discount) + chosen.reduce((n, c) => n + c.price, 0)) * 100) / 100;
      insItem.run(seq, p.id, p.name, unit, qty, sugar, note, JSON.stringify(chosen), food ? 'food' : 'drink');
      total += unit * qty;
    }
    total = Math.round(total * 100) / 100;
    setTotal.run(total, seq);
    return seq;
  });

  const seq = create();
  const created = loadOrders('WHERE seq = ?', [seq])[0];
  tgAfterOrder(created, items);
  res.status(201).json({ ...created, trackCode });
});

// ---------------- Admin API (JWT required) ----------------
const admin = express.Router();
admin.use(requireAdmin);
// Roles: 'owner' can do everything; 'cashier' can only work with orders (view, status, payment)
admin.use((req, res, next) => {
  if (req.admin.role === 'owner' || req.path.startsWith('/orders') || req.path === '/ordering' || req.path.startsWith('/shifts')) return next();
  next(new HttpError(403, 'មុខងារនេះសម្រាប់ម្ចាស់ហាងប៉ុណ្ណោះ'));
});

admin.get('/products', (req, res) => {
  const rows = db.prepare('SELECT * FROM products ORDER BY created_at DESC, rowid DESC').all();
  res.json(rows.map(productOut));
});

admin.post('/products', (req, res) => {
  const data = parseProduct(req.body);
  const id = 'prod-' + Date.now() + '-' + crypto.randomBytes(2).toString('hex');
  db.prepare(`INSERT INTO products (id, name, category, price, discount, stock, status, description, image, options)
              VALUES (@id, @name, @category, @price, @discount, @stock, @status, @description, @image, @options)`).run({ id, ...data });
  audit(req, 'product_create', id, `${data.name} $${data.price} stock ${data.stock}`);
  res.status(201).json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(id)));
});

admin.put('/products/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!existing) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  const data = parseProduct(req.body);
  db.prepare(`UPDATE products SET name=@name, category=@category, price=@price, discount=@discount, stock=@stock,
              status=@status, description=@description, image=@image, options=@options WHERE id=@id`).run({ id: req.params.id, ...data });
  audit(req, 'product_update', req.params.id, `${existing.name}: $${existing.price}→$${data.price}, ស្តុក ${existing.stock}→${data.stock}, បញ្ចុះ ${existing.discount || 0}→${data.discount}%, ${existing.status}→${data.status}`);
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
  audit(req, 'product_update', req.params.id, `${existing.name}: ${keys.map((k) => `${k} ${existing[k]}→${data[k]}`).join(', ')}`);
  res.json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

// Atomic stock adjustment (+/-), avoids lost updates when two staff click at once
admin.post('/products/:id/stock', (req, res) => {
  const delta = Number(req.body.delta);
  if (!Number.isInteger(delta) || Math.abs(delta) > 100000) throw new HttpError(400, 'delta មិនត្រឹមត្រូវ');
  const r = db.prepare('UPDATE products SET stock = MAX(0, stock + ?) WHERE id = ?').run(delta, req.params.id);
  if (!r.changes) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  audit(req, 'stock_adjust', req.params.id, `${delta > 0 ? '+' : ''}${delta}`);
  res.json(productOut(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

admin.delete('/products/:id', (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) throw new HttpError(404, 'រកមិនឃើញទំនិញ');
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  audit(req, 'product_delete', req.params.id, p.name);
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
  const reason = String(req.body.reason ?? '').trim().slice(0, 200);
  if (!ORDER_STATUSES.includes(status)) throw new HttpError(400, 'status មិនត្រឹមត្រូវ');
  const FLOW = { pending: ['preparing', 'completed', 'cancelled'], preparing: ['completed', 'cancelled'], completed: ['cancelled'], cancelled: [] };
  let prev = null, moneyCancel = null;
  tx(() => {
    const o = db.prepare('SELECT * FROM orders WHERE seq = ?').get(seq);
    if (!o) throw new HttpError(404, 'រកមិនឃើញការកម្ម៉ង់');
    if (o.status === status) return;
    if (!FLOW[o.status].includes(status)) {
      throw new HttpError(409, o.status === 'cancelled' ? 'ការកម្ម៉ង់ដែលបានបោះបង់ មិនអាចបើកឡើងវិញបានទេ' : 'មិនអាចប្តូរស្ថានភាពថយក្រោយបានទេ');
    }
    if (status === 'cancelled') {
      const risky = o.pay_status === 'paid' || o.status === 'completed'; // money taken or drink already served
      if (risky) {
        if (req.admin.role !== 'owner') throw new HttpError(403, 'ការលុបការកម្ម៉ង់ដែលបានបង់ប្រាក់ ឬបម្រើរួច ត្រូវការម្ចាស់ហាង');
        if (reason.length < 3) throw new HttpError(400, 'សូមបញ្ចូលមូលហេតុនៃការលុប/សងប្រាក់');
        moneyCancel = { total: o.total };
      }
      for (const it of db.prepare('SELECT product_id, quantity FROM order_items WHERE order_seq = ?').all(seq)) {
        db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?').run(it.quantity, it.product_id);
      }
      db.prepare("UPDATE orders SET pay_status = 'refunded' WHERE seq = ? AND pay_status = 'paid'").run(seq);
    }
    prev = o.status;
    db.prepare("UPDATE orders SET status = ?, status_at = datetime('now') WHERE seq = ?").run(status, seq);
  })();
  if (prev) {
    audit(req, 'order_status', req.params.id, `${prev} → ${status}${reason ? ': ' + reason : ''}`);
    if (moneyCancel) tgSend(`↩️ លុប/សងប្រាក់ ${req.params.id} ($${moneyCancel.total.toFixed(2)})\nដោយ ${req.admin.username}\nមូលហេតុ: ${reason}`);
  }
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
  audit(req, 'order_pay', req.params.id, `${method} ${method === 'cash' ? received + ' ' + cur : ''}`.trim());
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
  const oldRate = getRate();
  setSetting('exchange_rate', rate);
  setSetting('khqr_image', qr);
  audit(req, 'settings', '', `អត្រា ${oldRate}→${rate}${oldQr !== qr ? ', ប្តូររូប KHQR' : ''}`);
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
  const q = (v) => { // neutralise spreadsheet formulas (=, +, -, @) in text typed by customers
    let t = String(v ?? '');
    if (typeof v === 'string' && /^[=+\-@\t\r]/.test(t)) t = "'" + t;
    return '"' + t.replace(/"/g, '""') + '"';
  };
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
    if (!last || Date.now() - Date.parse(last.createdAt) > 20 * 3600e3) {
      const n = makeBackup('auto');
      tgSendFile(path.join(BACKUP_DIR, n), '💾 Backup ' + n);
    }
    for (const b of listBackups().slice(7)) fs.unlink(path.join(BACKUP_DIR, b.name), () => {}); // keep the newest 7
  } catch (e) { console.error('Auto-backup failed:', e.message); }
}

admin.get('/backup', (req, res, next) => {
  audit(req, 'backup_download');
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
  audit(req, 'user_create', username, role);
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
  audit(req, 'user_update', u.username, `${req.body.role !== undefined ? 'role ' + u.role + '→' + req.body.role : ''}${req.body.password !== undefined ? ' ប្តូរពាក្យសម្ងាត់' : ''}`.trim());
  res.json(db.prepare('SELECT id, username, role, created_at FROM admins WHERE id = ?').get(id));
});
admin.delete('/users/:id', (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM admins WHERE id = ?').get(id);
  if (!u) throw new HttpError(404, 'រកមិនឃើញអ្នកប្រើ');
  if (id === req.admin.id) throw new HttpError(400, 'មិនអាចលុបគណនីរបស់ខ្លួនឯងបានទេ');
  if (u.role === 'owner' && ownersCount() <= 1) throw new HttpError(400, 'ត្រូវមានម្ចាស់ហាងយ៉ាងតិចម្នាក់');
  db.prepare('DELETE FROM admins WHERE id = ?').run(id);
  audit(req, 'user_delete', u.username);
  res.json({ ok: true });
});

// ---------------- Pause / resume customer ordering ----------------
admin.put('/ordering', (req, res) => {
  const paused = !!req.body.paused;
  setSetting('ordering_paused', paused ? '1' : '0');
  audit(req, 'ordering', paused ? 'paused' : 'open');
  tgSend(paused ? '⏸️ ផ្អាកទទួលការកម្ម៉ង់ ដោយ ' + req.admin.username : '▶️ បើកទទួលការកម្ម៉ង់វិញ ដោយ ' + req.admin.username);
  res.json({ orderingPaused: paused });
});

// ---------------- Cash drawer shifts (cashier + owner) ----------------
const isoDt = (d) => d.replace(' ', 'T') + 'Z';
const cash = (v) => { const n = Number(v ?? 0); if (!Number.isFinite(n) || n < 0 || n > 1e9) throw new HttpError(400, 'ចំនួនលុយមិនត្រឹមត្រូវ'); return n; };
function shiftExpected(sh) {
  // Cash sales in the shift. Assumes change is returned in the same currency that was received.
  let usd = 0, khr = 0, n = 0;
  for (const o of db.prepare("SELECT total, rate, received_cur FROM orders WHERE pay_method = 'cash' AND pay_status = 'paid' AND paid_at >= ? AND paid_at <= ?").all(sh.opened_at, sh.closed_at || '9999')) {
    n++;
    if (o.received_cur === 'KHR') khr += khrOf(o.total, o.rate > 0 ? o.rate : getRate()); else usd += o.total;
  }
  const r2 = (x) => Math.round(x * 100) / 100;
  return { salesUsd: r2(usd), salesKhr: khr, orders: n, expUsd: r2(sh.open_usd + usd), expKhr: sh.open_khr + khr };
}
const shiftOut = (sh) => ({
  id: sh.id, openedAt: isoDt(sh.opened_at), openedBy: sh.opened_by, openUsd: sh.open_usd, openKhr: sh.open_khr,
  closedAt: sh.closed_at ? isoDt(sh.closed_at) : null, closedBy: sh.closed_by, countUsd: sh.count_usd, countKhr: sh.count_khr, note: sh.note,
  ...(sh.closed_at ? { expUsd: sh.exp_usd, expKhr: sh.exp_khr } : shiftExpected(sh)),
});
const openShift = () => db.prepare('SELECT * FROM shifts WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1').get();
admin.get('/shifts/current', (req, res) => { const sh = openShift(); res.json(sh ? shiftOut(sh) : null); });
admin.get('/shifts', (req, res) => res.json(db.prepare('SELECT * FROM shifts WHERE closed_at IS NOT NULL ORDER BY id DESC LIMIT 30').all().map(shiftOut)));
admin.post('/shifts/open', (req, res) => {
  if (openShift()) throw new HttpError(409, 'មានវេនកំពុងបើករួចហើយ');
  const u = cash(req.body.openUsd), k = cash(req.body.openKhr);
  const { lastInsertRowid: id } = db.prepare('INSERT INTO shifts (opened_by, open_usd, open_khr) VALUES (?, ?, ?)').run(req.admin.username, u, k);
  audit(req, 'shift_open', '#' + id, `$${u} + ៛${k}`);
  res.status(201).json(shiftOut(db.prepare('SELECT * FROM shifts WHERE id = ?').get(id)));
});
admin.post('/shifts/close', (req, res) => {
  const sh = openShift();
  if (!sh) throw new HttpError(409, 'មិនមានវេនកំពុងបើកទេ');
  const cu = cash(req.body.countUsd), ck = cash(req.body.countKhr), note = String(req.body.note ?? '').trim().slice(0, 200);
  const e = shiftExpected(sh);
  db.prepare("UPDATE shifts SET closed_at = datetime('now'), closed_by = ?, count_usd = ?, count_khr = ?, exp_usd = ?, exp_khr = ?, note = ? WHERE id = ?")
    .run(req.admin.username, cu, ck, e.expUsd, e.expKhr, note, sh.id);
  const dU = Math.round((cu - e.expUsd) * 100) / 100, dK = ck - e.expKhr;
  audit(req, 'shift_close', '#' + sh.id, `USD ${dU >= 0 ? '+' : ''}${dU}, KHR ${dK >= 0 ? '+' : ''}${dK}${note ? ' · ' + note : ''}`);
  tgSend(`💵 បិទវេន #${sh.id} ដោយ ${req.admin.username}\nUSD: រំពឹង $${e.expUsd} រាប់បាន $${cu} (${dU === 0 ? 'ត្រូវ' : dU > 0 ? 'លើស $' + dU : 'ខ្វះ $' + (-dU)})\nKHR: រំពឹង ៛${e.expKhr} រាប់បាន ៛${ck} (${dK === 0 ? 'ត្រូវ' : dK > 0 ? 'លើស ៛' + dK : 'ខ្វះ ៛' + (-dK)})`);
  res.json(shiftOut(db.prepare('SELECT * FROM shifts WHERE id = ?').get(sh.id)));
});

// ---------------- Restore from a backup file (owner only) ----------------
const restoreUpload = multer({ dest: path.join(DATA_DIR, 'tmp'), limits: { fileSize: 200 * 1024 * 1024, files: 1 } });
admin.post('/restore', restoreUpload.single('file'), (req, res) => {
  if (!req.file) throw new HttpError(400, 'សូមជ្រើសរើសឯកសារ Backup (.db)');
  const tmp = req.file.path;
  try {
    const head = Buffer.alloc(16), fd = fs.openSync(tmp, 'r');
    fs.readSync(fd, head, 0, 16, 0); fs.closeSync(fd);
    if (head.toString('latin1') !== 'SQLite format 3\0') throw new HttpError(400, 'ឯកសារនេះមិនមែនជា Backup ត្រឹមត្រូវទេ');
    const restored = {};
    db.exec(`ATTACH DATABASE '${tmp.replace(/'/g, "''")}' AS rs`);
    try {
      const have = new Set(db.prepare("SELECT name FROM rs.sqlite_master WHERE type = 'table'").all().map((r) => r.name));
      for (const t of ['products', 'orders', 'order_items', 'admins']) if (!have.has(t)) throw new HttpError(400, `Backup មិនមានតារាង ${t}`);
      if (db.prepare('PRAGMA rs.integrity_check').get().integrity_check !== 'ok') throw new HttpError(400, 'ឯកសារ Backup ខូច');
      if (db.prepare('SELECT COUNT(*) AS n FROM rs.admins').get().n < 1) throw new HttpError(400, 'Backup មិនមានគណនី Admin');
      makeBackup('prerestore'); // safety copy of what is being replaced
      const tables = ['order_items', 'orders', 'products', 'banners', 'settings', 'admins'].filter((t) => have.has(t)); // children first
      tx(() => {
        for (const t of tables) db.exec(`DELETE FROM main.${t}`);
        for (const t of [...tables].reverse()) {
          const mc = db.prepare(`PRAGMA main.table_info(${t})`).all().map((c) => c.name);
          const rc = new Set(db.prepare(`PRAGMA rs.table_info(${t})`).all().map((c) => c.name));
          const cols = mc.filter((c) => rc.has(c)).map((c) => `"${c}"`).join(',');
          db.exec(`INSERT INTO main.${t} (${cols}) SELECT ${cols} FROM rs.${t}`);
          restored[t] = db.prepare(`SELECT COUNT(*) AS n FROM main.${t}`).get().n;
        }
      })();
    } finally { try { db.exec('DETACH DATABASE rs'); } catch (_) { /* not attached */ } }
    audit(req, 'restore', String(req.file.originalname).slice(0, 60), JSON.stringify(restored));
    tgSend('♻️ ស្តារទិន្នន័យពី Backup ដោយ ' + req.admin.username + '\n' + JSON.stringify(restored));
    res.json({ ok: true, restored });
  } finally { fs.unlink(tmp, () => {}); }
});

admin.get('/audit', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  res.json(db.prepare('SELECT id, at, username, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?').all(limit)
    .map((r) => ({ ...r, at: r.at.replace(' ', 'T') + 'Z' })));
});
admin.post('/telegram/test', asyncH(async (req, res) => {
  if (!tgOn()) return res.json({ ok: false, message: 'មិនទាន់កំណត់ TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID ក្នុង .env' });
  const ok = await tgSend('✅ សារសាកល្បងពី កាហ្វេ ម្លប់ដូង (' + req.admin.username + ')');
  res.json({ ok, message: ok ? 'បានផ្ញើសារសាកល្បងរួចរាល់ សូមពិនិត្យ Telegram' : 'ផ្ញើមិនបាន សូមពិនិត្យ token និង chat id' });
}));

app.use('/api/admin', admin);

// ---------------- Static ----------------
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', setHeaders: (res) => res.setHeader('X-Content-Type-Options', 'nosniff') }));
app.get('/board', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'board.html')));
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
  maintenance();
  setInterval(maintenance, Number(process.env.MAINT_MS) || 60e3).unref(); // auto-cancel stale orders, daily Telegram summary
  app.listen(PORT, () => console.log(`☕ Mlob Doung Coffee running on http://localhost:${PORT}`));
}
module.exports = app;
