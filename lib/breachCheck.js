/**
 * lib/breachCheck.js
 * ------------------------------------------------------------------
 * Bendra (framework'ui neutrali) duomenų nutekėjimų tikrinimo logika.
 * Naudojama tiek Vercel (/api/check.js), tiek Netlify
 * (/netlify/functions/check.js) adapterių.
 *
 * DUOMENŲ ŠALTINIS: XposedOrNot (https://xposedornot.com) — visiškai
 * NEMOKAMAS, atviro kodo (MIT) duomenų nutekėjimų tikrinimo API.
 * El. pašto patikros galiniams taškams API raktas NEREIKALINGAS.
 * Naudojant privaloma atribucija (nurodyta svetainės poraštėje).
 *
 * SVARBU (privatumas):
 *  - El. pašto adresas NIEKUR nesaugomas ir NERAŠOMAS į žurnalus.
 *  - Užklausos į XposedOrNot API siunčiamos tik iš serverio pusės —
 *    naudotojo naršyklė su išoriniu API tiesiogiai nebendrauja.
 *  - Jei DEMO_MODE=true, grąžinami DEMONSTRACINIAI duomenys
 *    (patogu kūrimui / testavimui be tinklo).
 * ------------------------------------------------------------------
 */

'use strict';

// ------------------------------------------------------------------
// 1. Įvesties validacija
// ------------------------------------------------------------------

const EMAIL_MAX_LENGTH = 254;

// Praktiškas (ne perteklinis) el. pašto formato patikrinimas.
// Galutinę „tiesą" vis tiek nustato patikros šaltinis.
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/**
 * Patikrina el. pašto formatą.
 * @param {unknown} email
 * @returns {{ ok: boolean, email?: string, error?: string }}
 */
function validateEmail(email) {
  if (typeof email !== 'string') {
    return { ok: false, error: 'INVALID_EMAIL' };
  }
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length === 0) {
    return { ok: false, error: 'EMPTY_EMAIL' };
  }
  if (trimmed.length > EMAIL_MAX_LENGTH || !EMAIL_REGEX.test(trimmed)) {
    return { ok: false, error: 'INVALID_EMAIL' };
  }
  return { ok: true, email: trimmed };
}

// ------------------------------------------------------------------
// 2. Užklausų dažnio ribojimas (rate limiting)
// ------------------------------------------------------------------
// Paprastas atminties (in-memory) ribotuvas vienam serverless
// egzemplioriui. Tinka demonstracijai ir mažam srautui.
//
// PRODUKCIJAI rekomenduojama naudoti išorinę saugyklą
// (pvz., Upstash Redis, Vercel KV), nes serverless egzemplioriai
// nesidalija atmintimi. Žr. README.md.
// ------------------------------------------------------------------

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minutė
const RATE_LIMIT_MAX = 6;            // 6 užklausos per minutę vienam IP

const rateBuckets = new Map();

/**
 * @param {string} ipHash - anonimizuotas kliento identifikatorius
 * @returns {boolean} true, jei užklausa leidžiama
 */
function checkRateLimit(ipHash) {
  const now = Date.now();
  // Išvalome pasenusius įrašus, kad atmintis neaugtų be ribų.
  if (rateBuckets.size > 5000) {
    for (const [key, bucket] of rateBuckets) {
      if (now - bucket.start > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(key);
    }
  }
  const bucket = rateBuckets.get(ipHash);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    rateBuckets.set(ipHash, { start: now, count: 1 });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= RATE_LIMIT_MAX;
}

/**
 * IP adresą paverčiame negrįžtama maiša — žurnaluose ir atmintyje
 * nesaugome tikro IP (duomenų minimizavimas pagal BDAR).
 */
function hashIdentifier(value) {
  const crypto = require('crypto');
  return crypto
    .createHash('sha256')
    .update(String(value) + (process.env.RATE_LIMIT_SALT || 'ar-nutekejo'))
    .digest('hex')
    .slice(0, 32);
}

// ------------------------------------------------------------------
// 3. Duomenų kategorijų vertimas į lietuvių kalbą (XON naudoja HIBP
//    suderinamus kategorijų pavadinimus)
// ------------------------------------------------------------------

const DATA_CLASS_LT = {
  'Email addresses': 'El. pašto adresai',
  'Passwords': 'Slaptažodžiai',
  'Usernames': 'Naudotojų vardai',
  'Names': 'Vardai ir pavardės',
  'Phone numbers': 'Telefono numeriai',
  'IP addresses': 'IP adresai',
  'Dates of birth': 'Gimimo datos',
  'Physical addresses': 'Gyvenamosios vietos adresai',
  'Geographic locations': 'Geografinės vietovės',
  'Security questions and answers': 'Saugumo klausimai ir atsakymai',
  'Password hints': 'Slaptažodžių užuominos',
  'Social media profiles': 'Socialinių tinklų profiliai',
  'Genders': 'Lytis',
  'Job titles': 'Pareigos',
  'Employers': 'Darbdaviai',
  'Website activity': 'Veikla svetainėje',
  'Browsing histories': 'Naršymo istorija',
  'Credit card CVV': 'Mokėjimo kortelių CVV kodai',
  'Partial credit card data': 'Daliniai mokėjimo kortelių duomenys',
  'Bank account numbers': 'Banko sąskaitų numeriai',
  'Government issued IDs': 'Valstybės išduoti dokumentai',
  'Purchases': 'Pirkimai',
  'Device information': 'Įrenginių informacija',
  'Auth tokens': 'Autentifikavimo žetonai (tokens)',
  'Historical passwords': 'Ankstesni slaptažodžiai',
  'Chat logs': 'Susirašinėjimų įrašai',
  'Private messages': 'Privačios žinutės',
  'Spoken languages': 'Kalbos',
  'Nationalities': 'Pilietybės',
  'Salutations': 'Kreipiniai',
  'Instant messenger identities': 'Žinučių programų paskyros',
  'Avatars': 'Profilio nuotraukos',
  'Biometric data': 'Biometriniai duomenys',
  'Health insurance information': 'Sveikatos draudimo informacija',
  'Personal health data': 'Asmens sveikatos duomenys',
  'Social security numbers': 'Socialinio draudimo numeriai',
  'Family members\' names': 'Šeimos narių vardai',
  'Marital statuses': 'Šeiminė padėtis',
  'Income levels': 'Pajamų lygis',
  'Loyalty program details': 'Lojalumo programų duomenys',
  'Support tickets': 'Pagalbos užklausos',
  'Survey results': 'Apklausų rezultatai',
  'Education levels': 'Išsilavinimas',
  'Ethnicities': 'Etninė kilmė',
  'Sexual orientations': 'Seksualinė orientacija',
  'Political views': 'Politinės pažiūros',
  'Religions': 'Religiniai įsitikinimai'
};

function translateDataClass(dc) {
  return DATA_CLASS_LT[dc] || dc;
}

// ------------------------------------------------------------------
// 4. Rizikos lygio vertinimas
// ------------------------------------------------------------------

const RISK_LEVELS = ['zemas', 'vidutinis', 'aukstas', 'kritinis'];

const CRITICAL_CLASSES = new Set([
  'Credit card CVV',
  'Bank account numbers',
  'Government issued IDs',
  'Social security numbers',
  'Auth tokens',
  'Biometric data'
]);

const HIGH_CLASSES = new Set([
  'Passwords', // bazinis lygis; keliamas iki kritinio pagal passwordRisk
  'Security questions and answers',
  'Password hints',
  'Historical passwords',
  'Partial credit card data',
  'Personal health data',
  'Health insurance information',
  'Private messages',
  'Chat logs'
]);

const MEDIUM_CLASSES = new Set([
  'Phone numbers',
  'Dates of birth',
  'Physical addresses',
  'IP addresses',
  'Geographic locations',
  'Device information',
  'Purchases',
  'Income levels'
]);

/**
 * Apskaičiuoja vieno incidento rizikos lygį pagal nutekintų
 * duomenų kategorijas ir incidento požymius.
 * @param {string[]} dataClasses - kategorijos (anglų k., šaltinio formatu)
 * @param {object} opts
 * @param {string}  [opts.passwordRisk] - XposedOrNot laukas „password_risk":
 *                  'plaintextpassword' | 'easytocrack' | 'hardtocrack' | 'unknown'
 * @param {boolean} [opts.isSensitive]
 * @returns {'zemas'|'vidutinis'|'aukstas'|'kritinis'}
 */
function computeBreachRisk(dataClasses, { passwordRisk = '', isSensitive = false } = {}) {
  let level = 0; // zemas
  for (const dc of dataClasses) {
    if (CRITICAL_CLASSES.has(dc)) level = Math.max(level, 3);
    else if (HIGH_CLASSES.has(dc)) level = Math.max(level, 2);
    else if (MEDIUM_CLASSES.has(dc)) level = Math.max(level, 1);
  }
  // Slaptažodžiai atviru tekstu arba silpna maiša — kritinė rizika.
  const pr = String(passwordRisk).toLowerCase();
  if (pr.includes('plaintext') || pr.includes('easytocrack')) {
    level = Math.max(level, 3);
  }
  // „Jautrūs" incidentai (pvz., pažintys, sveikata) — bent aukštas.
  if (isSensitive) level = Math.max(level, 2);
  return RISK_LEVELS[level];
}

/** Bendras rizikos lygis — aukščiausias iš visų incidentų, koreguojamas pagal kiekį. */
function computeOverallRisk(breaches) {
  if (breaches.length === 0) return 'zemas';
  let max = 0;
  for (const b of breaches) {
    max = Math.max(max, RISK_LEVELS.indexOf(b.rizikosLygis));
  }
  // Daug incidentų — didesnė kumuliacinė rizika.
  if (breaches.length >= 8 && max < 3) max += 1;
  return RISK_LEVELS[Math.min(max, 3)];
}

// ------------------------------------------------------------------
// 5. Rekomendacijų generavimas pagal rastus duomenis
// ------------------------------------------------------------------

function buildRecommendations(breaches) {
  const all = new Set();
  for (const b of breaches) for (const dc of b._rawClasses || []) all.add(dc);

  const recs = [];
  const add = (id, tekstas, prioritetas) => recs.push({ id, tekstas, prioritetas });

  if (all.has('Passwords') || all.has('Historical passwords')) {
    add('keisti-slaptazodi', 'Nedelsdami pakeiskite šios paskyros slaptažodį ir visose kitose sistemose, kuriose naudojote tą patį ar panašų slaptažodį.', 'kritinis');
    add('unikalus-slaptazodis', 'Nenaudokite to paties slaptažodžio keliose sistemose — kiekvienai paskyrai kurkite unikalų slaptažodį.', 'aukstas');
  }
  if (all.has('Security questions and answers') || all.has('Password hints')) {
    add('saugumo-klausimai', 'Pakeiskite saugumo klausimus ir atsakymus visose paskyrose, kuriose jie galėjo būti atskleisti.', 'aukstas');
  }
  if (all.has('Credit card CVV') || all.has('Partial credit card data') || all.has('Bank account numbers')) {
    add('bankas', 'Susisiekite su banku, peržiūrėkite mokėjimo operacijas ir apsvarstykite kortelės blokavimą ar keitimą.', 'kritinis');
  }
  if (all.has('Phone numbers')) {
    add('sim', 'Būkite budrūs dėl sukčiavimo skambučiais ir SMS žinutėmis (smishing); nespauskit įtartinų nuorodų.', 'vidutinis');
  }
  if (breaches.length > 0) {
    add('mfa', 'Įjunkite dviejų veiksnių autentifikavimą (MFA) — geriausia programėlės ar aparatinio rakto pagrindu.', 'aukstas');
    add('sesijos', 'Patikrinkite aktyvias prisijungimo sesijas ir atjunkite nepažįstamus įrenginius.', 'vidutinis');
    add('phishing', 'Įvertinkite padidėjusią tikslinio sukčiavimo („phishing") riziką — atidžiai tikrinkite gaunamų laiškų siuntėjus ir nuorodas.', 'vidutinis');
    add('stebejimas', 'Reguliariai stebėkite paskyrų ir el. pašto prisijungimų istoriją, įjunkite pranešimus apie naujus prisijungimus.', 'vidutinis');
    add('tvarkykle', 'Naudokite slaptažodžių tvarkyklę unikaliems ir stipriems slaptažodžiams kurti bei saugoti.', 'vidutinis');
  } else {
    add('prevencija-mfa', 'Nors nutekėjimų nerasta, rekomenduojame įjungti dviejų veiksnių autentifikavimą svarbiausiose paskyrose.', 'zemas');
    add('prevencija-tvarkykle', 'Naudokite slaptažodžių tvarkyklę ir unikalius slaptažodžius kiekvienai paskyrai.', 'zemas');
    add('prevencija-tikrinimas', 'Periodiškai pasitikrinkite el. pašto adresą — nauji nutekėjimai skelbiami nuolat.', 'zemas');
  }
  return recs;
}

// ------------------------------------------------------------------
// 6. Šaltinio aprašymo valymas (HTML pašalinimas — apsauga nuo XSS)
// ------------------------------------------------------------------

function stripHtml(html) {
  return String(html || '')
    .replace(/<[^>]*>/g, '')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

// ------------------------------------------------------------------
// 7. XposedOrNot incidento normalizavimas į vidinį formatą
// ------------------------------------------------------------------
// XON „breach-analytics" atsakymo laukai (breaches_details[]):
//   breach          - incidento pavadinimas
//   domain          - paveiktos paslaugos domenas
//   details         - incidento aprašymas (tekstas)
//   xposed_data     - kategorijos, atskirtos „;" (pvz., "Email addresses;Passwords")
//   xposed_date     - incidento metai (pvz., "2019")
//   xposed_records  - paveiktų įrašų skaičius
//   password_risk   - slaptažodžių būklė: plaintextpassword / easytocrack /
//                     hardtocrack / unknown
//   verified        - ar šaltinis patvirtintas ("Yes"/"No" arba bool)
// ------------------------------------------------------------------

const PASSWORD_RISK_LT = {
  plaintextpassword: 'Slaptažodžiai atviru tekstu',
  easytocrack: 'Silpna slaptažodžių maiša (lengvai iššifruojama)',
  hardtocrack: 'Stipri slaptažodžių maiša',
  unknown: null
};

function normalizeBreach(raw) {
  const dataClasses = String(raw.xposed_data || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);

  const passwordRisk = String(raw.password_risk || '').toLowerCase();
  const verified = raw.verified === true || String(raw.verified).toLowerCase() === 'yes';

  const rizikosLygis = computeBreachRisk(dataClasses, { passwordRisk });

  const records = Number(raw.xposed_records);

  return {
    pavadinimas: raw.breach || 'Nežinomas šaltinis',
    domenas: raw.domain || '',
    nutekejimoData: raw.xposed_date ? String(raw.xposed_date) : null, // incidento metai
    // XON viešai nepateikia įtraukimo į DB datos atskiru lauku
    paviesinimoData: null,
    aprasymas: stripHtml(raw.details),
    duomenuKategorijos: dataClasses.map(translateDataClass),
    _rawClasses: dataClasses,
    slaptazodziuBukle: PASSWORD_RISK_LT[passwordRisk] || null,
    paveiktaPaskyru: Number.isFinite(records) ? records : null,
    patvirtintas: verified,
    rizikosLygis
  };
}

// ------------------------------------------------------------------
// 8. Demonstraciniai duomenys (DEMO_MODE=true — kūrimui be tinklo)
// ------------------------------------------------------------------

const DEMO_BREACHES = [
  {
    breach: 'DemoForum',
    domain: 'demoforum.example',
    xposed_date: '2023',
    xposed_records: 8400000,
    verified: 'Yes',
    password_risk: 'easytocrack',
    details: 'Demonstracinis įrašas. Interneto forumo duomenų bazė buvo paviešinta programišių forume. Nutekėjo naudotojų el. pašto adresai, naudotojų vardai ir silpna maiša apsaugoti slaptažodžiai (MD5).',
    xposed_data: 'Email addresses;Usernames;Passwords'
  },
  {
    breach: 'ShopDemo',
    domain: 'shopdemo.example',
    xposed_date: '2021',
    xposed_records: 1200000,
    verified: 'Yes',
    password_risk: 'unknown',
    details: 'Demonstracinis įrašas. El. parduotuvės klientų duomenys buvo pasiekiami per neapsaugotą duomenų bazę. Atskleisti vardai, telefono numeriai ir gyvenamųjų vietų adresai.',
    xposed_data: 'Email addresses;Names;Phone numbers;Physical addresses'
  },
  {
    breach: 'NewsletterDemo',
    domain: 'newsletterdemo.example',
    xposed_date: '2019',
    xposed_records: 560000,
    verified: 'Yes',
    password_risk: 'unknown',
    details: 'Demonstracinis įrašas. Naujienlaiškių platformos prenumeratorių sąrašas buvo paviešintas. Nutekėjo tik el. pašto adresai.',
    xposed_data: 'Email addresses'
  }
];

// ------------------------------------------------------------------
// 9. Pagrindinė tikrinimo funkcija — XposedOrNot API (nemokamas)
// ------------------------------------------------------------------

const XON_ENDPOINT = 'https://api.xposedornot.com/v1/breach-analytics?email=';
const XON_TIMEOUT_MS = 12_000;

/**
 * Atlieka nutekėjimų patikrą per nemokamą XposedOrNot API
 * (arba grąžina demo duomenis, jei DEMO_MODE=true).
 * @param {string} email - jau validuotas el. pašto adresas
 * @returns {Promise<object>} atsakymo objektas frontend'ui
 */
async function performCheck(email) {
  let rawBreaches;
  let demo = false;

  if (String(process.env.DEMO_MODE).toLowerCase() === 'true') {
    // --- DEMO REŽIMAS (nebūtinas — tik kūrimui/testavimui) --------
    demo = true;
    await new Promise((r) => setTimeout(r, 900)); // imituojame tinklo delsą
    rawBreaches = DEMO_BREACHES;
  } else {
    // --- TIKRAS XposedOrNot API (be rakto, nemokamas) --------------
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), XON_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(XON_ENDPOINT + encodeURIComponent(email), {
        headers: {
          accept: 'application/json',
          'user-agent': process.env.APP_USER_AGENT || 'ArNutekejo-Patikra'
        },
        signal: controller.signal
      });
    } catch (err) {
      clearTimeout(timer);
      const e = new Error('UPSTREAM_UNAVAILABLE');
      e.code = 'UPSTREAM_UNAVAILABLE';
      throw e;
    }
    clearTimeout(timer);

    if (response.status === 404) {
      // XON 404 = adresas žinomuose nutekėjimuose nerastas (gerai!)
      rawBreaches = [];
    } else if (response.status === 200) {
      const payload = await response.json();
      rawBreaches = payload?.ExposedBreaches?.breaches_details || [];
    } else if (response.status === 429) {
      const e = new Error('UPSTREAM_RATE_LIMIT');
      e.code = 'UPSTREAM_RATE_LIMIT';
      throw e;
    } else {
      const e = new Error('UPSTREAM_ERROR');
      e.code = 'UPSTREAM_ERROR';
      throw e;
    }
  }

  const breaches = rawBreaches
    .map(normalizeBreach)
    .sort((a, b) => String(b.nutekejimoData).localeCompare(String(a.nutekejimoData)));

  const rekomendacijos = buildRecommendations(breaches);
  const bendraRizika = computeOverallRisk(breaches);

  // Iš atsakymo pašaliname vidinį lauką _rawClasses
  for (const b of breaches) delete b._rawClasses;

  return {
    demo,
    rasta: breaches.length > 0,
    nutekejimuSkaicius: breaches.length,
    bendraRizika,
    incidentai: breaches,
    rekomendacijos,
    patikrosLaikas: new Date().toISOString()
  };
}

module.exports = {
  validateEmail,
  checkRateLimit,
  hashIdentifier,
  performCheck
};
