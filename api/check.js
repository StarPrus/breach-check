/**
 * api/check.js — Vercel serverless funkcija
 * ------------------------------------------------------------------
 * POST /api/check   { "email": "vardas@pavyzdys.lt", "consent": true }
 *
 * Saugumo priemonės:
 *  - Tik POST metodas (mažina CSRF riziką kartu su SameSite ir tuo,
 *    kad endpoint'as nekeičia jokios būsenos serveryje).
 *  - „Same-origin" patikra pagal Origin/Referer antraštes.
 *  - Užklausų dažnio ribojimas pagal anonimizuotą IP maišą.
 *  - El. pašto adresas NĖRA rašomas į žurnalus ir NĖRA saugomas.
 *  - Naudotojui negrąžinamos techninės klaidos — tik draugiški kodai.
 * ------------------------------------------------------------------
 */

'use strict';

const {
  validateEmail,
  checkRateLimit,
  hashIdentifier,
  performCheck
} = require('../lib/breachCheck.js');

module.exports = async function handler(req, res) {
  // Rezultatų atsakymai niekada neturi būti talpinami tarpiniuose serveriuose
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ klaida: 'METHOD_NOT_ALLOWED' });
  }

  // --- Paprasta same-origin patikra (apsauga nuo svetimų svetainių
  //     bandymo naudoti šį API masiniam tikrinimui) -----------------
  const origin = req.headers.origin || req.headers.referer || '';
  const host = req.headers.host || '';
  if (origin && host && !origin.includes(host)) {
    return res.status(403).json({ klaida: 'FORBIDDEN' });
  }

  // --- Užklausų dažnio ribojimas ----------------------------------
  const clientIp =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown';
  const ipHash = hashIdentifier(clientIp); // saugome tik maišą, ne IP

  if (!checkRateLimit(ipHash)) {
    return res.status(429).json({ klaida: 'RATE_LIMITED' });
  }

  // --- Įvesties apdorojimas ----------------------------------------
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  body = body || {};

  // Naudotojas privalo patvirtinti, kad tikrina savo adresą arba
  // turi teisę jį tikrinti.
  if (body.consent !== true) {
    return res.status(400).json({ klaida: 'CONSENT_REQUIRED' });
  }

  const validation = validateEmail(body.email);
  if (!validation.ok) {
    return res.status(400).json({ klaida: validation.error });
  }

  // --- Patikra ------------------------------------------------------
  try {
    const result = await performCheck(validation.email);
    return res.status(200).json(result);
  } catch (err) {
    // Į žurnalą rašome TIK klaidos kodą — jokių naudotojo duomenų.
    console.error('check klaida:', err.code || 'UNKNOWN');
    const code = err.code === 'UPSTREAM_RATE_LIMIT' ? 'UPSTREAM_RATE_LIMIT' : 'UPSTREAM_UNAVAILABLE';
    return res.status(503).json({ klaida: code });
  }
};
