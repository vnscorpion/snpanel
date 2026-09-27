// Applied before first paint, so a dark-mode user does not see the page flash
// light while the app loads.
//
// This was an inline <script> in index.html, and the panel's own
// Content-Security-Policy - `script-src 'self'`, correctly strict - refused to
// run it on every page load: the flash it existed to prevent happened anyway,
// with a console error to say so. A file served from the panel itself is
// 'self', so it runs; the policy did not have to be loosened.
//
// Loaded as a classic, synchronous script from <head>, before the stylesheet
// and the app, which is what makes it early enough.
(function () {
  var root = document.documentElement;
  try {
    var stored = localStorage.getItem('snpanel-theme');
    var theme = stored === 'dark' || stored === 'light'
      ? stored
      : (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
  } catch (e) {}
  try {
    // The language, for the same reason: set from the first byte rather than
    // after the app has mounted. Must agree with initialLocale() in
    // src/i18n/index.jsx.
    var locale = localStorage.getItem('snpanel-locale');
    if (locale !== 'en' && locale !== 'vi') {
      locale = (navigator.language || '').toLowerCase().indexOf('vi') === 0 ? 'vi' : 'en';
    }
    root.lang = locale;
  } catch (e) {}
})();
