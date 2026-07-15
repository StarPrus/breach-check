# Ar nutekėjo? 🛡️

Vieno puslapio svetainė lietuvių kalba, leidžianti pasitikrinti, ar el. pašto
adresas buvo aptiktas viešai žinomuose duomenų nutekėjimuose.

**Projektas veikia 100 % be mokamų paslaugų:**

| Komponentas | Sprendimas | Kaina |
|---|---|---|
| Duomenų šaltinis | [XposedOrNot](https://xposedornot.com) API — atviro kodo (MIT), be API rakto | Nemokama |
| Talpinimas | Vercel *Hobby* arba Netlify *Free* planas (HTTPS įskaičiuotas) | Nemokama |
| Šriftai | Google Fonts | Nemokama |

Išorinis API kviečiamas tik per saugų serverio tarpinį sluoksnį (serverless
funkciją) — naudotojo naršyklė su juo tiesiogiai nebendrauja, o serveris
prideda dažnio ribojimą ir privatumo apsaugą.

## Projekto struktūra

```
ar-nutekejo/
├── public/                     # Statinis frontend'as
│   ├── index.html              # Pagrindinis puslapis (forma, rezultatai, DUK)
│   ├── styles.css              # Stiliai (tamsi/šviesi tema, spausdinimo šablonas)
│   ├── app.js                  # Kliento logika (validacija, būsenos, atvaizdavimas)
│   ├── theme-init.js           # Temos inicializacija (suderinama su CSP)
│   ├── privatumas.html         # Privatumo politika
│   └── salygos.html            # Naudojimo sąlygos
├── api/
│   └── check.js                # Vercel serverless funkcija (POST /api/check)
├── netlify/functions/
│   └── check.js                # Ta pati funkcija Netlify platformai
├── lib/
│   └── breachCheck.js          # Bendra logika: validacija, XON API, rizika, demo
├── vercel.json                 # Saugumo antraštės (CSP ir kt.), Vercel nustatymai
├── netlify.toml                # Netlify nustatymai ir peradresavimai
├── .env.example                # Aplinkos kintamųjų pavyzdys (raktų nereikia!)
└── package.json
```

## Kaip veikia

1. Naudotojas įveda el. pašto adresą ir patvirtina, kad turi teisę jį tikrinti.
2. Naršyklė siunčia `POST /api/check` užklausą į **savo** serverio funkciją.
3. Funkcija validuoja adresą, pritaiko užklausų dažnio ribojimą ir kviečia
   nemokamą XposedOrNot galinį tašką
   `GET https://api.xposedornot.com/v1/breach-analytics?email=…` (be rakto).
4. Atsakymas normalizuojamas: kategorijos išverčiamos į lietuvių kalbą,
   pagal jas ir slaptažodžių apsaugos būklę (`password_risk`) apskaičiuojamas
   kiekvieno incidento bei bendras rizikos lygis, sugeneruojamos individualios
   rekomendacijos.
5. Frontend'as saugiai (tik per `textContent`, be `innerHTML`) atvaizduoja ataskaitą.

**Demo režimas (nebūtinas):** nustačius aplinkos kintamąjį `DEMO_MODE=true`,
funkcija grąžina pavyzdinius duomenis su aiškia žyma — patogu kūrimui ar
demonstracijai be interneto ryšio.

## Paleidimas lokaliai

Reikalavimai: Node.js ≥ 18. Jokių API raktų registruoti nereikia.

### Variantas A — Vercel CLI (rekomenduojama)

```bash
npm install -g vercel
cd ar-nutekejo
vercel dev
```

Svetainė pasiekiama adresu `http://localhost:3000`. `vercel dev` automatiškai
aptarnauja `public/` katalogą ir `api/check.js` funkciją.

### Variantas B — Netlify CLI

```bash
npm install -g netlify-cli
cd ar-nutekejo
netlify dev
```

`netlify.toml` faile jau nustatytas peradresavimas `/api/check` →
`/.netlify/functions/check`.

## Publikavimas (nemokami planai)

### Vercel (Hobby planas — nemokamas)

```bash
cd ar-nutekejo
vercel          # pirmas diegimas (peržiūros aplinka)
vercel --prod   # produkcinis diegimas
```

Arba per svetainę: <https://vercel.com/new> → importuokite Git repozitoriją →
*Deploy*. Aplinkos kintamųjų nustatyti **nebūtina** — nebent norite pakeisti
`RATE_LIMIT_SALT` ar `APP_USER_AGENT`.

### Netlify (Free planas — nemokamas)

```bash
netlify init
netlify deploy --prod
```

Arba per svetainę: <https://app.netlify.com> → *Add new site* → importuokite
repozitoriją (nustatymai nuskaitomi iš `netlify.toml`) → *Deploy*.

Abu nemokami planai suteikia HTTPS, pasaulinį CDN ir serverless funkcijas —
šiam projektui to visiškai pakanka.

### Kitos platformos

`lib/breachCheck.js` yra framework'ui neutralus — jį nesunku apgaubti Express,
Cloudflare Workers (Free planas taip pat tinka) ar kitu backend'u. Svarbu
išlaikyti: HTTPS, saugumo antraštes (žr. `vercel.json`) ir tai, kad el. pašto
adresas nebūtų rašomas į žurnalus.

## Įgyvendintos saugumo ir privatumo priemonės

| Priemonė | Kur įgyvendinta |
|---|---|
| Išorinis API kviečiamas tik serverio pusėje | `lib/breachCheck.js` |
| El. paštas nesaugomas, nerašomas į žurnalus | serverio funkcijos (loginamas tik klaidos kodas) |
| Užklausų dažnio ribojimas (6/min per IP) | `lib/breachCheck.js` (`checkRateLimit`) |
| IP anonimizavimas (SHA-256 maiša) | `hashIdentifier()` |
| Apsauga nuo XSS | frontend'e tik `textContent`; aprašymų HTML valymas serveryje; CSP |
| CSRF mažinimas | tik POST + JSON, same-origin patikra, `form-action 'self'` |
| Apsauga nuo masinio tikrinimo | rate limit + same-origin patikra + sutikimo žyma |
| Saugumo antraštės (CSP, HSTS, nosniff, frame-ancestors) | `vercel.json` / `netlify.toml` |
| Rezultatų neindeksavimas | `X-Robots-Tag: noindex` API atsakymuose; `Referrer-Policy: no-referrer` |
| Draugiški klaidų pranešimai be techninių detalių | `app.js` (`ERROR_TEXTS`) |
| Sutikimo patvirtinimas prieš patikrą | forma + serverio `consent` patikra |
| Šaltinio 429 (perkrovos) korektiškas apdorojimas | `performCheck()` → draugiškas pranešimas |

### Rekomendacijos produkcijai

- **Rate limit saugykla:** numatytas atminties ribotuvas veikia viename serverless
  egzemplioriuje. Didesniam srautui naudokite Upstash Redis (turi nemokamą planą)
  ar pan.
- **CAPTCHA:** pastebėjus piktnaudžiavimą, prieš patikrą įterpkite privatumui
  draugišką **Cloudflare Turnstile** (nemokama) ir tikrinkite jos žetoną
  serverio funkcijoje.
- **XON dažnio limitai:** nemokamas API riboja užklausų dažnį (viršijus grąžina
  429 su `Retry-After`) — funkcija tai apdoroja ir parodo naudotojui draugišką
  pranešimą.

## Atribucija ir šaltiniai

Duomenų šaltinis: [XposedOrNot](https://xposedornot.com) (MIT licencija,
atviras kodas: <https://github.com/XposedOrNot/XposedOrNot-API>). Pagal XON
naudojimo sąlygas rodant jų duomenis privaloma aiški atribucija — ji pateikta
svetainės poraštėje. Laikykitės API dažnio limitų; komercinis duomenų
perpardavimas draudžiamas.
