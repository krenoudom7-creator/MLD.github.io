'use strict';
/**
 * Minimal KHQR (EMVCo-based) encoder / decoder for DYNAMIC payment QR codes.
 *
 * - No network, no secrets. Pure functions.
 * - Field layout follows the public KHQR / EMV merchant-presented QR structure
 *   (tags 00,01,29|30,52,53,54,58,59,60,62,99,63).
 * - The official NBC SDK (npm "bakong-khqr") produces the same kind of string. If you prefer the
 *   official SDK, replace buildDynamicKhqr() only; nothing else in the app depends on this file.
 */
const crypto = require('crypto');

const CURRENCY_CODE = { USD: '840', KHR: '116' };

/** CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) as required by EMV QR. Returns 4 upper-case hex chars. */
function crc16(str) {
  let crc = 0xffff;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let b = 0; b < 8; b++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

function tlv(tag, value) {
  const v = String(value);
  if (v.length > 99) throw new Error(`KHQR tag ${tag} is longer than 99 characters`);
  return tag + String(v.length).padStart(2, '0') + v;
}

function asciiField(value, max, label, required = true) {
  const v = String(value ?? '').replace(/[^\x20-\x7E]/g, '').trim();
  if (!v && required) throw new Error(`KHQR ${label} is required (ASCII only)`);
  if (v.length > max) throw new Error(`KHQR ${label} must be at most ${max} characters`);
  return v;
}

/** USD -> "2.25" (2 decimals), KHR -> "9200" (whole riel). amountMinor = cents (USD) or riel (KHR). */
function formatAmount(currency, amountMinor) {
  if (!Number.isInteger(amountMinor) || amountMinor <= 0) throw new Error('KHQR amount must be a positive integer (minor units)');
  return currency === 'USD' ? (amountMinor / 100).toFixed(2) : String(amountMinor);
}

/**
 * Build a dynamic KHQR string (amount + currency + bill number + creation/expiry timestamps).
 * @param {object} o
 *  accountType   'individual' (tag 29) | 'merchant' (tag 30)
 *  accountId     Bakong account id, e.g. "name@bank"
 *  accountInfo   individual: optional account number inside tag 29 (sub-tag 01)
 *  acquiringBank optional (individual) / required (merchant) bank name
 *  merchantId    required for merchant
 *  merchantName  <=25 ASCII, merchantCity <=15 ASCII, mcc 4 digits
 *  currency      'USD' | 'KHR'
 *  amountMinor   integer, cents (USD) or riel (KHR)
 *  billNumber    <=25 chars (our unique payment reference)
 *  storeLabel    optional <=25
 *  createdMs / expiresMs   13-digit epoch milliseconds
 */
function buildDynamicKhqr(o) {
  const currency = String(o.currency || '').toUpperCase();
  if (!CURRENCY_CODE[currency]) throw new Error('KHQR currency must be USD or KHR');
  if (!Number.isInteger(o.createdMs) || !Number.isInteger(o.expiresMs) || o.expiresMs <= o.createdMs) throw new Error('KHQR needs createdMs < expiresMs');
  if (String(o.createdMs).length !== 13 || String(o.expiresMs).length !== 13) throw new Error('KHQR timestamps must be 13-digit epoch milliseconds');

  const accountId = asciiField(o.accountId, 32, 'accountId');
  let account;
  if ((o.accountType || 'individual') === 'merchant') {
    account = tlv('30', tlv('00', accountId) + tlv('01', asciiField(o.merchantId, 32, 'merchantId')) + tlv('02', asciiField(o.acquiringBank, 32, 'acquiringBank')));
  } else {
    const info = asciiField(o.accountInfo, 32, 'accountInfo', false);
    const bank = asciiField(o.acquiringBank, 32, 'acquiringBank', false);
    account = tlv('29', tlv('00', accountId) + (info ? tlv('01', info) : '') + (bank ? tlv('02', bank) : ''));
  }
  const mcc = String(o.mcc || '5999');
  if (!/^\d{4}$/.test(mcc)) throw new Error('KHQR merchant category code must be 4 digits');

  const bill = asciiField(o.billNumber, 25, 'billNumber');
  const store = asciiField(o.storeLabel, 25, 'storeLabel', false);

  const body =
    tlv('00', '01') +
    tlv('01', '12') + // 12 = dynamic QR
    account +
    tlv('52', mcc) +
    tlv('53', CURRENCY_CODE[currency]) +
    tlv('54', formatAmount(currency, o.amountMinor)) +
    tlv('58', 'KH') +
    tlv('59', asciiField(o.merchantName, 25, 'merchantName')) +
    tlv('60', asciiField(o.merchantCity || 'Phnom Penh', 15, 'merchantCity')) +
    tlv('62', tlv('01', bill) + (store ? tlv('03', store) : '')) +
    tlv('99', tlv('00', String(o.createdMs)) + tlv('01', String(o.expiresMs)));
  const withCrcTag = body + '6304';
  return withCrcTag + crc16(withCrcTag);
}

function parseTlv(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const lenStr = s.slice(i + 2, i + 4);
    if (i + 4 > s.length || !/^\d\d$/.test(lenStr)) throw new Error('malformed KHQR');
    const len = parseInt(lenStr, 10);
    const val = s.slice(i + 4, i + 4 + len);
    if (val.length !== len) throw new Error('malformed KHQR (length)');
    out.push([s.slice(i, i + 2), val]);
    i += 4 + len;
  }
  return out;
}

/** True when the trailing CRC (tag 63) matches the content. */
function verifyKhqr(str) {
  const s = String(str);
  return s.length > 8 && s.slice(-8, -4) === '6304' && crc16(s.slice(0, -4)) === s.slice(-4);
}

/** Decode into { tag: value } with nested maps for 29/30/62/99. Throws on malformed input. */
function parseKhqr(str) {
  const fields = {};
  for (const [tag, val] of parseTlv(String(str))) {
    fields[tag] = ['29', '30', '62', '99'].includes(tag) ? Object.fromEntries(parseTlv(val)) : val;
  }
  return fields;
}

const md5Of = (s) => crypto.createHash('md5').update(String(s)).digest('hex');

module.exports = { crc16, tlv, buildDynamicKhqr, verifyKhqr, parseKhqr, md5Of, CURRENCY_CODE };
