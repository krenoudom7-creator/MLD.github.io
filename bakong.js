'use strict';
/**
 * Thin client for the Bakong Open API (National Bank of Cambodia).
 * Docs: https://api-bakong.nbc.gov.kh/document  (check_transaction_by_md5 works for DYNAMIC KHQR only)
 *
 * The token is only ever sent from the server (Authorization header). It is never logged or returned.
 */

/**
 * @returns {Promise<{state: 'found'|'not_found'|'failed'|'unauthorized'|'forbidden'|'ratelimited'|'error', data?: object, http?: number, message?: string}>}
 *  found        -> Bakong has a successful transaction for this QR (data.hash/amount/currency/...)
 *  not_found    -> no transaction yet (errorCode 1)
 *  failed       -> Bakong reports the transaction failed (errorCode 3)
 *  unauthorized -> token missing / expired / rejected (HTTP 401 or errorCode 6)
 *  forbidden    -> HTTP 403 (token not allowed, or the API refuses the caller's IP/region)
 *  ratelimited  -> HTTP 429
 *  error        -> network error, timeout, 5xx, or an unexpected response. Always treated as "unknown": retry later.
 */
async function checkTransactionByMd5({ baseUrl, token, md5, timeoutMs = 10000, fetchImpl }) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== 'function') return { state: 'error', message: 'fetch is not available (use Node 18+)' };
  const url = String(baseUrl).replace(/\/+$/, '') + '/v1/check_transaction_by_md5';
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res, text;
  try {
    res = await doFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ md5 }),
      signal: ctrl.signal,
    });
    text = await res.text();
  } catch (e) {
    return { state: 'error', message: e && e.name === 'AbortError' ? 'timeout' : 'network error: ' + (e && e.message) };
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 401) return { state: 'unauthorized', http: 401, message: 'token rejected or expired' };
  if (res.status === 403) return { state: 'forbidden', http: 403, message: 'forbidden (token not authorised, or API blocks this server IP/region)' };
  if (res.status === 429) return { state: 'ratelimited', http: 429, message: 'rate limited' };
  if (res.status >= 500) return { state: 'error', http: res.status, message: 'bakong server error ' + res.status };

  let body;
  try { body = JSON.parse(text); } catch (_) { return { state: 'error', http: res.status, message: 'invalid JSON from bakong' }; }
  if (!body || typeof body !== 'object') return { state: 'error', http: res.status, message: 'unexpected response' };

  if (body.responseCode === 0 && body.data && typeof body.data === 'object') return { state: 'found', data: body.data, http: res.status };
  if (body.responseCode === 1) {
    if (body.errorCode === 1) return { state: 'not_found', http: res.status, message: body.responseMessage };
    if (body.errorCode === 3) return { state: 'failed', http: res.status, message: body.responseMessage };
    if (body.errorCode === 6) return { state: 'unauthorized', http: res.status, message: body.responseMessage };
    return { state: 'error', http: res.status, message: `bakong errorCode ${body.errorCode}: ${body.responseMessage || ''}` };
  }
  return { state: 'error', http: res.status, message: 'unexpected response shape' };
}

/** Reads the expiry from the JWT payload (no signature check; only used for a warning in the dashboard). */
function tokenInfo(token) {
  try {
    const payload = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8'));
    if (!payload.exp) return { expMs: null, daysLeft: null };
    const expMs = payload.exp * 1000;
    return { expMs, daysLeft: Math.floor((expMs - Date.now()) / 86400000) };
  } catch (_) {
    return { expMs: null, daysLeft: null };
  }
}

module.exports = { checkTransactionByMd5, tokenInfo };
