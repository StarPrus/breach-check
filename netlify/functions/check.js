/**
 * netlify/functions/check.js — Netlify Functions adapteris
 * ------------------------------------------------------------------
 * Ta pati logika kaip /api/check.js (Vercel), pritaikyta Netlify
 * event/context sąsajai. Frontend'as visada kviečia /api/check —
 * peradresavimas nustatytas netlify.toml faile.
 * ------------------------------------------------------------------
 */

'use strict';

const {
  validateEmail,
  checkRateLimit,
  hashIdentifier,
  performCheck
} = require('../../lib/breachCheck.js');

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow'
};

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: JSON_HEADERS, body: JSON.stringify({ klaida: 'METHOD_NOT_ALLOWED' }) };
  }

  const origin = event.headers.origin || event.headers.referer || '';
  const host = event.headers.host || '';
  if (origin && host && !origin.includes(host)) {
    return { statusCode: 403, headers: JSON_HEADERS, body: JSON.stringify({ klaida: 'FORBIDDEN' }) };
  }

  const clientIp =
    (event.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    (event.headers['client-ip'] || 'unknown');
  if (!checkRateLimit(hashIdentifier(clientIp))) {
    return { statusCode: 429, headers: JSON_HEADERS, body: JSON.stringify({ klaida: 'RATE_LIMITED' }) };
  }

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch { body = {}; }

  if (body.consent !== true) {
    return { statusCode: 400, headers: JSON_HEADERS, body: JSON.stringify({ klaida: 'CONSENT_REQUIRED' }) };
  }

  const validation = validateEmail(body.email);
  if (!validation.ok) {
    return { statusCode: 400, headers: JSON_HEADERS, body: JSON.stringify({ klaida: validation.error }) };
  }

  try {
    const result = await performCheck(validation.email);
    return { statusCode: 200, headers: JSON_HEADERS, body: JSON.stringify(result) };
  } catch (err) {
    console.error('check klaida:', err.code || 'UNKNOWN');
    const code = err.code === 'UPSTREAM_RATE_LIMIT' ? 'UPSTREAM_RATE_LIMIT' : 'UPSTREAM_UNAVAILABLE';
    return { statusCode: 503, headers: JSON_HEADERS, body: JSON.stringify({ klaida: code }) };
  }
};
