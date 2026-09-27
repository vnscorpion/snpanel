// English is the panel's language; Vietnamese is a translation of it.
//
// gettext-style: the English text is the key. `t('Save settings')` is
// "Save settings" in English with no catalogue at all, and whatever vi.js
// maps it to in Vietnamese. A string nobody has translated yet shows in
// English rather than as a key, so adding a string never breaks a screen.
//
// Parameters go in braces: t('Saved schedule: {list}', { list }). A
// parameter may be a React element, for sentences with a link or a <code> in
// the middle - the whole sentence is translated once, instead of being cut
// into fragments that each language would have to put back in the same
// order. Such a call returns a fragment instead of a string.
//
// The server answers in English too. serverText() shows its messages in the
// viewer's language through vi-server.js, which only a viewer reading
// Vietnamese downloads - see server.js.
import { createContext, Fragment, createElement, isValidElement, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import vi from './vi.js';
import { compile, translateMessage } from './server.js';

export const LOCALES = [
  { code: 'en', label: 'English', short: 'EN' },
  { code: 'vi', label: 'Tiếng Việt', short: 'VI' },
];

const CATALOGUES = { vi };
const SERVER_CATALOGUES = { vi: () => import('./vi-server.js') };
const STORAGE_KEY = 'snpanel-locale';

function initialLocale() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (LOCALES.some((l) => l.code === stored)) return stored;
  } catch {}
  const browser = (typeof navigator !== 'undefined' && navigator.language) || '';
  return browser.toLowerCase().startsWith('vi') ? 'vi' : 'en';
}

const PLACEHOLDER = /\{(\w+)\}/g;

export function translate(locale, text, params) {
  const catalogue = CATALOGUES[locale];
  const template = (catalogue && catalogue[text]) || text;
  if (!params) return template;

  const hasElement = Object.values(params).some(isValidElement);
  if (!hasElement) {
    return template.replace(PLACEHOLDER, (m, key) => (key in params ? String(params[key] ?? '') : m));
  }

  // Interleave the text with the elements, in the translation's own order.
  const parts = [];
  let last = 0;
  for (const m of template.matchAll(PLACEHOLDER)) {
    if (m.index > last) parts.push(template.slice(last, m.index));
    const key = m[1];
    parts.push(key in params ? params[key] : m[0]);
    last = m.index + m[0].length;
  }
  if (last < template.length) parts.push(template.slice(last));
  return createElement(Fragment, null, ...parts);
}

/// Marks a string for translation without translating it. For constants,
/// which cannot call t(): the code that shows one does - t(LABELS[key]) - and
/// scripts/i18n-check.mjs finds the string through this.
export const msg = (text) => text;

// The language on screen, for code outside React - formatApiError() - and
// the server catalogues loaded so far, compiled.
let activeLocale = 'en';
const serverCatalogues = {};
const serverLoads = {};

function loadServerCatalogue(locale) {
  if (!SERVER_CATALOGUES[locale]) return Promise.resolve(null);
  if (!serverLoads[locale]) {
    serverLoads[locale] = SERVER_CATALOGUES[locale]()
      .then((m) => { serverCatalogues[locale] = compile(m.default); return serverCatalogues[locale]; })
      .catch(() => { delete serverLoads[locale]; return null; });
  }
  return serverLoads[locale];
}

/// A message from the server in the viewer's language. The English as it
/// came when nothing matches, or while the catalogue is still loading - the
/// screen shows it again in Vietnamese once it has arrived.
export function serverText(text) {
  if (typeof text !== 'string' || !text || activeLocale === 'en') return text;
  const own = CATALOGUES[activeLocale]?.[text];
  if (own !== undefined) return own;
  const compiled = serverCatalogues[activeLocale];
  if (!compiled) { loadServerCatalogue(activeLocale); return text; }
  return translateMessage(compiled, text);
}

const LocaleContext = createContext({
  locale: 'en',
  setLocale: () => {},
  t: (text, params) => translate('en', text, params),
});

export function LocaleProvider({ children }) {
  const [locale, setLocaleState] = useState(initialLocale);
  const [serverReady, setServerReady] = useState(() => !SERVER_CATALOGUES[locale] || !!serverCatalogues[locale]);
  // Set while rendering, so the children rendering after it read the same.
  activeLocale = locale;

  const setLocale = useCallback((next) => {
    setLocaleState(next);
    try { localStorage.setItem(STORAGE_KEY, next); } catch {}
  }, []);

  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => {
    if (!SERVER_CATALOGUES[locale] || serverCatalogues[locale]) return;
    let live = true;
    setServerReady(false);
    loadServerCatalogue(locale).then(() => { if (live) setServerReady(true); });
    return () => { live = false; };
  }, [locale]);

  const t = useCallback((text, params) => translate(locale, text, params), [locale]);
  // serverReady is in the value so that everything reading the context
  // renders again when the server catalogue arrives; t keeps its identity.
  const value = useMemo(() => ({ locale, setLocale, t, serverReady }), [locale, setLocale, t, serverReady]);
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale() {
  return useContext(LocaleContext);
}

export function useT() {
  return useContext(LocaleContext).t;
}

/// A two-state EN / VI switch, for the header and the login page.
export function LocaleSwitch({ className = '' }) {
  const { locale, setLocale, t } = useLocale();
  const next = LOCALES.find((l) => l.code !== locale) || LOCALES[0];
  const current = LOCALES.find((l) => l.code === locale) || LOCALES[0];
  return (
    <button
      type="button"
      className={`locale-switch ${className}`.trim()}
      onClick={() => setLocale(next.code)}
      aria-label={t('Switch language to {language}', { language: next.label })}
      title={t('Switch language to {language}', { language: next.label })}
    >
      {current.short}
    </button>
  );
}
