/**
 * app.js — kliento pusės logika
 * ------------------------------------------------------------------
 * - Formos validacija ir būsenų valdymas (tuščia / neteisinga /
 *   kraunama / rezultatai / klaida)
 * - Užklausa į /api/check (serverio tarpinį sluoksnį)
 * - Saugus rezultatų atvaizdavimas (tik textContent — jokio innerHTML
 *   su išoriniais duomenimis, apsauga nuo XSS)
 * - Tamsaus/šviesaus režimo perjungimas
 * - Ataskaitos spausdinimas / PDF
 * ------------------------------------------------------------------
 */

'use strict';

// ---------- Elementų nuorodos ----------
const form = document.getElementById('check-form');
const emailInput = document.getElementById('email-input');
const consentInput = document.getElementById('consent-input');
const checkButton = document.getElementById('check-button');
const formError = document.getElementById('form-error');

const loadingSection = document.getElementById('loading-section');
const resultsSection = document.getElementById('results-section');
const errorSection = document.getElementById('error-section');
const errorMessage = document.getElementById('error-message');

const demoBanner = document.getElementById('demo-banner');
const summaryCard = document.getElementById('summary-card');
const summaryTitle = document.getElementById('summary-title');
const summarySub = document.getElementById('summary-sub');
const metricCount = document.getElementById('metric-count');
const metricRisk = document.getElementById('metric-risk');
const breachListWrap = document.getElementById('breach-list-wrap');
const breachList = document.getElementById('breach-list');
const recsList = document.getElementById('recs-list');

const printButton = document.getElementById('print-button');
const newCheckButton = document.getElementById('new-check-button');
const retryButton = document.getElementById('retry-button');
const themeToggle = document.getElementById('theme-toggle');

// ---------- Tekstai ----------
const RISK_LT = {
  zemas: 'Žemas',
  vidutinis: 'Vidutinis',
  aukstas: 'Aukštas',
  kritinis: 'Kritinis'
};

const ERROR_TEXTS = {
  EMPTY_EMAIL: 'Įveskite el. pašto adresą.',
  INVALID_EMAIL: 'Įvestas adresas neatitinka el. pašto formato. Patikrinkite ir bandykite dar kartą.',
  CONSENT_REQUIRED: 'Prieš patikrą pažymėkite, kad tikrinate savo adresą arba turite teisę jį tikrinti.',
  RATE_LIMITED: 'Per trumpą laiką atlikta per daug užklausų. Palaukite minutę ir bandykite dar kartą.',
  UPSTREAM_RATE_LIMIT: 'Patikros šaltinis šiuo metu perkrautas. Palaukite kelias sekundes ir bandykite dar kartą.',
  UPSTREAM_UNAVAILABLE: 'Patikros paslauga laikinai nepasiekiama. Bandykite dar kartą po kelių minučių.',
  NETWORK: 'Nepavyko prisijungti prie serverio. Patikrinkite interneto ryšį ir bandykite dar kartą.',
  UNKNOWN: 'Įvyko nenumatyta klaida. Bandykite dar kartą.'
};

// Kritinės duomenų kategorijos, žymimos raudonai
const DANGER_TAGS = new Set([
  'Slaptažodžiai',
  'Saugumo klausimai ir atsakymai',
  'Mokėjimo kortelių CVV kodai',
  'Banko sąskaitų numeriai',
  'Valstybės išduoti dokumentai',
  'Autentifikavimo žetonai (tokens)'
]);

// ---------- Pagalbinės ----------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }

function setState(state) {
  hide(loadingSection);
  hide(resultsSection);
  hide(errorSection);
  if (state === 'loading') show(loadingSection);
  if (state === 'results') show(resultsSection);
  if (state === 'error') show(errorSection);
}

function showFormError(code) {
  formError.textContent = ERROR_TEXTS[code] || ERROR_TEXTS.UNKNOWN;
  show(formError);
  emailInput.classList.add('input-invalid');
}

function clearFormError() {
  hide(formError);
  formError.textContent = '';
  emailInput.classList.remove('input-invalid');
}

function formatNumber(n) {
  return typeof n === 'number' ? n.toLocaleString('lt-LT') : '—';
}

// ---------- Rezultatų atvaizdavimas ----------
// SAUGUMAS: visi išoriniai duomenys įterpiami TIK per textContent,
// todėl HTML/skriptų injekcija (XSS) neįmanoma.

function renderResults(data) {
  // Demo juosta
  data.demo ? show(demoBanner) : hide(demoBanner);

  // Santrauka
  const riskKey = data.bendraRizika || 'zemas';
  summaryCard.style.setProperty('--summary-accent', `var(--risk-${riskKey})`);
  metricCount.textContent = String(data.nutekejimuSkaicius);
  metricRisk.textContent = RISK_LT[riskKey] || riskKey;
  metricRisk.className = `metric-value risk-badge risk-${riskKey}`;

  if (data.rasta) {
    summaryTitle.textContent = 'Adresas aptiktas duomenų nutekėjimuose';
    summarySub.textContent =
      `Šis el. pašto adresas rastas ${data.nutekejimuSkaicius} žinomame(-uose) saugumo incidente(-uose). ` +
      'Peržiūrėkite incidentų informaciją ir atlikite rekomenduojamus veiksmus.';
    show(breachListWrap);
  } else {
    summaryTitle.textContent = 'Adresas žinomuose nutekėjimuose nerastas';
    summarySub.textContent =
      'Viešai žinomose duomenų bazėse šio adreso pėdsakų neaptikta. ' +
      'Vis dėlto rekomenduojame laikytis žemiau pateiktų prevencinių patarimų.';
    hide(breachListWrap);
  }

  // Incidentų kortelės
  breachList.textContent = '';
  for (const incident of data.incidentai || []) {
    breachList.appendChild(buildBreachCard(incident));
  }

  // Rekomendacijos
  recsList.textContent = '';
  for (const rec of data.rekomendacijos || []) {
    const li = document.createElement('li');
    if (rec.prioritetas === 'kritinis') li.classList.add('rec-kritinis');
    if (rec.prioritetas === 'aukstas') li.classList.add('rec-aukstas');
    li.appendChild(document.createTextNode(rec.tekstas));
    recsList.appendChild(li);
  }

  setState('results');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function buildBreachCard(incident) {
  const details = document.createElement('details');
  details.className = 'breach-card';

  // --- Antraštė (summary) ---
  const summary = document.createElement('summary');
  summary.className = 'breach-summary';

  const rail = document.createElement('span');
  rail.className = `breach-rail rail-${incident.rizikosLygis}`;
  summary.appendChild(rail);

  const head = document.createElement('div');
  head.className = 'breach-head';

  const name = document.createElement('div');
  name.className = 'breach-name';
  name.textContent = incident.pavadinimas;
  head.appendChild(name);

  if (incident.domenas) {
    const domain = document.createElement('div');
    domain.className = 'breach-domain';
    domain.textContent = incident.domenas;
    head.appendChild(domain);
  }
  summary.appendChild(head);

  const badge = document.createElement('span');
  badge.className = `risk-badge risk-${incident.rizikosLygis}`;
  badge.textContent = RISK_LT[incident.rizikosLygis] || incident.rizikosLygis;
  summary.appendChild(badge);

  if (incident.nutekejimoData) {
    const date = document.createElement('span');
    date.className = 'breach-date';
    date.textContent = incident.nutekejimoData;
    summary.appendChild(date);
  }

  const chevron = document.createElement('span');
  chevron.className = 'breach-chevron';
  chevron.setAttribute('aria-hidden', 'true');
  summary.appendChild(chevron);

  details.appendChild(summary);

  // --- Turinys ---
  const body = document.createElement('div');
  body.className = 'breach-body';

  if (incident.aprasymas) {
    const desc = document.createElement('p');
    desc.textContent = incident.aprasymas;
    body.appendChild(desc);
  }

  const facts = document.createElement('div');
  facts.className = 'breach-facts';
  facts.append(
    buildFact('Incidento metai', incident.nutekejimoData || '—'),
    buildFact('Paveikta paskyrų', formatNumber(incident.paveiktaPaskyru)),
    buildFact('Šaltinis patvirtintas', incident.patvirtintas ? 'Taip' : 'Nepatvirtintas')
  );
  if (incident.paviesinimoData) {
    facts.appendChild(buildFact('Paviešinta / įtraukta į DB', incident.paviesinimoData));
  }
  if (incident.slaptazodziuBukle) {
    facts.appendChild(buildFact('Slaptažodžių apsauga', incident.slaptazodziuBukle));
  }
  body.appendChild(facts);

  const tagsLabel = document.createElement('span');
  tagsLabel.className = 'fact-label';
  tagsLabel.textContent = 'Galimai nutekintų duomenų kategorijos';
  body.appendChild(tagsLabel);

  const tags = document.createElement('div');
  tags.className = 'data-tags';
  for (const kategorija of incident.duomenuKategorijos || []) {
    const tag = document.createElement('span');
    tag.className = 'data-tag' + (DANGER_TAGS.has(kategorija) ? ' tag-danger' : '');
    tag.textContent = kategorija;
    tags.appendChild(tag);
  }
  body.appendChild(tags);

  details.appendChild(body);
  return details;
}

function buildFact(label, value) {
  const wrap = document.createElement('div');
  const l = document.createElement('span');
  l.className = 'fact-label';
  l.textContent = label;
  const v = document.createElement('span');
  v.className = 'fact-value';
  v.textContent = value;
  wrap.append(l, v);
  return wrap;
}

// ---------- Patikros vykdymas ----------
let lastEmail = null;

async function runCheck(email) {
  setState('loading');
  checkButton.disabled = true;
  checkButton.classList.add('is-loading');

  try {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, consent: true })
    });

    let payload = null;
    try { payload = await response.json(); } catch { /* tuščias kūnas */ }

    if (!response.ok) {
      const code = payload?.klaida || 'UNKNOWN';
      if (code === 'INVALID_EMAIL' || code === 'EMPTY_EMAIL' || code === 'CONSENT_REQUIRED') {
        setState('idle');
        showFormError(code);
      } else {
        errorMessage.textContent = ERROR_TEXTS[code] || ERROR_TEXTS.UNKNOWN;
        setState('error');
      }
      return;
    }

    renderResults(payload);
  } catch (err) {
    // Tinklo klaida — techninių detalių naudotojui nerodome
    errorMessage.textContent = ERROR_TEXTS.NETWORK;
    setState('error');
  } finally {
    checkButton.disabled = false;
    checkButton.classList.remove('is-loading');
  }
}

// ---------- Įvykiai ----------
form.addEventListener('submit', (e) => {
  e.preventDefault();
  clearFormError();

  const email = emailInput.value.trim();

  if (!email) { showFormError('EMPTY_EMAIL'); emailInput.focus(); return; }
  if (email.length > 254 || !EMAIL_REGEX.test(email)) {
    showFormError('INVALID_EMAIL'); emailInput.focus(); return;
  }
  if (!consentInput.checked) { showFormError('CONSENT_REQUIRED'); return; }

  lastEmail = email;
  runCheck(email);
});

emailInput.addEventListener('input', clearFormError);
consentInput.addEventListener('change', clearFormError);

retryButton.addEventListener('click', () => {
  if (lastEmail) runCheck(lastEmail);
  else { setState('idle'); emailInput.focus(); }
});

newCheckButton.addEventListener('click', () => {
  setState('idle');
  emailInput.value = '';
  emailInput.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// Prieš spausdinant atskleidžiame visas incidentų korteles,
// kad PDF ataskaitoje matytųsi visa informacija.
printButton.addEventListener('click', () => {
  document.querySelectorAll('.breach-card').forEach((d) => { d.open = true; });
  window.print();
});
window.addEventListener('beforeprint', () => {
  document.querySelectorAll('.breach-card').forEach((d) => { d.open = true; });
});

// ---------- Temos perjungimas ----------
themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('ar-nutekejo-tema', next); } catch { /* ignoruojame */ }
});
