/**
 * theme-init.js
 * Nustato tamsų/šviesų režimą PRIEŠ puslapio atvaizdavimą, kad
 * nebūtų mirgėjimo. Atskiras failas — suderinama su CSP
 * (script-src 'self', be 'unsafe-inline').
 *
 * Privatumo pastaba: localStorage saugoma TIK temos parinktis —
 * jokių naudotojo įvestų duomenų.
 */
(function () {
  try {
    var saved = localStorage.getItem('ar-nutekejo-tema');
    var theme = saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {
    /* localStorage gali būti nepasiekiamas — paliekame numatytą temą */
  }
})();
