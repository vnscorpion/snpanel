// Everything App.jsx declared at module scope: constants, formatters and the
// few small components the pages share. Moved here unchanged so the pages
// can import them without importing App.jsx, which imports the pages.
import { useCallback, useEffect, useRef, useState } from 'react';
import { msg, serverText, useT } from '../i18n/index.jsx';
import { AlertCircle, Check, Moon, Sun, X } from 'lucide-react';

export const API = import.meta.env.VITE_API_URL || '/api';
export const DEFAULT_SERVICE_NAMES = ['snpanel-api', 'nginx', 'php8.3-fpm', 'php8.4-fpm', 'mariadb', 'redis-server'];
export const HTTP_FLOOD_DEFAULTS = {
  access_limit_requests: 100,
  access_limit_window: 10,
  access_limit_burst: 100,
  connection_limit: 60,
};
export const PHP_VERSION_ORDER = ['5.6', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5'];
export const NGINX_REWRITE_MODES = [
  { value: 'none', label: msg('None / static PHP') },
  { value: 'front_controller', label: msg('PHP front controller') },
  { value: 'laravel', label: 'Laravel' },
  { value: 'codeigniter', label: 'CodeIgniter' },
  { value: 'seohburl', label: 'SEO HB URL' },
];
export function composeWebPorts(plan, wanted) {
  // Which ports the service behind the domain listens on. More than one means
  // the customer has to say which, rather than the panel guessing.
  const name = wanted || plan?.web_service;
  const service = plan?.services?.find(item => item.name === name);
  return service?.container_ports || [];
}

// Pages opened from inside another page instead of the sidebar. They have no
// nav entry of their own, so without this the header falls back to the first
// item and titles the page "Dashboard".
export const NAV_PARENT_PAGE = { 'waf-site': 'waf', 'api-tokens': 'settings', 'malware-scan': 'malware' };

// 'waf-site' is reached from the WAF overview rather than the sidebar, but it
// still belongs to Settings so the menu stays open and WAF stays highlighted.
export const SETTINGS_PAGE_KEYS = ['settings', 'api-tokens', 'security', 'mcp', 'php', 'firewall', 'fail2ban', 'waf', 'waf-site', 'malware', 'malware-scan', 'access-logs', 'updates', 'addons', 'services'];
export const PAGE_ROUTES = {
  dashboard: '/',
  websites: '/website',
  applications: '/applications',
  ssl: '/ssl',
  databases: '/database',
  cron: '/cron',
  files: '/filemanager',
  backups: '/backups',
  users: '/users',
  settings: '/settings',
  'api-tokens': '/api-tokens',
  security: '/security',
  php: '/php',
  firewall: '/firewall',
  fail2ban: '/fail2ban',
  mcp: '/ai-assistants',
  waf: '/waf',
  'waf-site': '/waf-site',
  malware: '/malware',
  // One scan's details; the job id follows it, see scanRoute.
  'malware-scan': '/malware/scan',
  'access-logs': '/access-logs',
  updates: '/updates',
  services: '/services',
  addons: '/addons',
};

/* ---------------------------------------------------------------
   Theme (light / dark)
   The initial value is applied by the inline script in index.html,
   so React only has to keep it in sync from here on.
--------------------------------------------------------------- */
export const THEME_STORAGE_KEY = 'snpanel-theme';
export const THEME_EVENT = 'snpanel-theme-change';

export function readStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored === 'dark' || stored === 'light' ? stored : null;
  } catch { return null; }
}

export function systemTheme() {
  try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
  catch { return 'light'; }
}

export function currentTheme() {
  const attr = document.documentElement.getAttribute('data-theme');
  if (attr === 'dark' || attr === 'light') return attr;
  return readStoredTheme() || systemTheme();
}

export function applyTheme(theme) {
  const root = document.documentElement;
  root.setAttribute('data-theme', theme);
  root.style.colorScheme = theme;
  document.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: theme }));
}


/* Owns the theme: persists the user's choice, follows the OS until they pick one. */
export function useTheme() {
  const [theme, setTheme] = useState(currentTheme);

  useEffect(() => { applyTheme(theme); }, [theme]);

  useEffect(() => {
    let media;
    try { media = window.matchMedia('(prefers-color-scheme: dark)'); } catch { return undefined; }
    const onChange = () => { if (!readStoredTheme()) setTheme(systemTheme()); };
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(prev => {
      const next = prev === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch {}
      return next;
    });
  }, []);

  return [theme, toggleTheme];
}

export function ThemeToggle({ theme, onToggle, className = '' }) {
  const t = useT();
  const isDark = theme === 'dark';
  const label = isDark ? t('Switch to light mode') : t('Switch to dark mode');
  return <button
    type="button"
    className={`theme-toggle ${className}`.trim()}
    onClick={onToggle}
    title={label}
    aria-label={label}
    aria-pressed={isDark}
  >{isDark ? <Sun size={16}/> : <Moon size={16}/>}</button>;
}

export function WordPressIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" className="lucide">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" />
      <text x="12" y="16" textAnchor="middle" fontSize="11" fontWeight="700" fontFamily="Georgia, serif" fill="currentColor">W</text>
    </svg>
  );
}
export const WAF_ACCESS_LOG_DEFAULTS = {
  websiteId: '',
  verdict: 'all',
  query: '',
  limit: 50,
  refresh: 5,
};
export const ROUTE_PAGES = new Map([
  ...Object.entries(PAGE_ROUTES).map(([pageName, path]) => [path, pageName]),
  ['/dashboard', 'dashboard'],
  ['/websites', 'websites'],
  ['/databases', 'databases'],
  ['/files', 'files'],
  ['/file-manager', 'files'],
  ['/website', 'websites'],
  ['/api-token', 'api-tokens'],
  ['/api-tokens', 'api-tokens'],
]);

export function pageFromPathname(pathname) {
  const normalized = `/${String(pathname || '').replace(/^\/+|\/+$/g, '')}`.toLowerCase();
  if (/^\/malware\/scan\/[a-z0-9_-]+$/.test(normalized)) return 'malware-scan';
  return ROUTE_PAGES.get(normalized) || 'dashboard';
}

// The address of one scan's details, and the job it names.
export const scanRoute = (jobId) => `/malware/scan/${encodeURIComponent(jobId)}`;
export const scanFromPathname = (pathname) => /^\/malware\/scan\/([A-Za-z0-9_-]+)\/?$/.exec(pathname || '')?.[1] || '';

export function routeForPage(pageName) {
  return PAGE_ROUTES[pageName] || PAGE_ROUTES.dashboard;
}

export function sortPhpVersions(versions = []) {
  return [...versions].sort((a, b) => {
    const ai = PHP_VERSION_ORDER.indexOf(a);
    const bi = PHP_VERSION_ORDER.indexOf(b);
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    return String(a).localeCompare(String(b), undefined, { numeric: true });
  });
}

export function normalizeHttpFloodConfig(config = {}) {
  let value = config;
  if (typeof value === 'string') {
    try { value = value.trim() ? JSON.parse(value) : {}; } catch { value = {}; }
  }
  if (!value || typeof value !== 'object') value = {};
  return Object.fromEntries(Object.entries(HTTP_FLOOD_DEFAULTS).map(([key, fallback]) => {
    const number = value[key] === '' ? NaN : Number(value[key]);
    return [key, Number.isFinite(number) ? number : fallback];
  }));
}

// The one website mode served by proxying to an installed application.
export const PROXIED_APP_TYPES = ['application'];
export const EMPTY_SITE_APP_DRAFT = {
  name: 'app',
  kind: 'node',
  port: '',
  memory_limit_mb: '',
  compose_source: '',
  web_service: '',
  start_kind: 'npm',
  start_arg: 'start',
  node_major: '22',
  image: '',
  container_port: '3000',
  cpu_limit: '1',
  env: '',
};
export const SITE_APP_KIND_LABELS = { node: 'Node.js', docker: msg('Container'), compose: 'Compose' };
export const SITE_APP_KINDS = [
  ['node', 'Node.js', msg('SNPanel installs dependencies and keeps the process running under systemd.')],
  ['docker', msg('Container'), msg('SNPanel pulls the image and runs it, published on loopback only.')],
  ['compose', 'Docker Compose', msg('Paste your project\u2019s docker-compose.yml. SNPanel checks it and runs a file it generates from what it accepted.')],
];
export const WEBSITE_MODES = [
  ['wordpress', 'WordPress'],
  ['php', 'PHP'],
  ['static', msg('Static')],
  ['application', msg('Application')],
];

export function isProxiedAppType(appType) {
  return PROXIED_APP_TYPES.includes(appType);
}

export function websiteConfigForm(site = {}) {
  const appType = site.app_type || 'wordpress';
  return {
    app_type: appType,
    php_version: site.php_version || '8.4',
    app_id: site.app_id ? String(site.app_id) : '',
    nginx_rewrite_mode: appType === 'wordpress'
      ? 'front_controller'
      : appType === 'static' || isProxiedAppType(appType)
        ? 'none'
        : site.nginx_rewrite_mode || 'none',
  };
}

// A time the API wrote, as year-first 24-hour local time. The API writes
// SQLAlchemy's naive UTC - "2026-09-24 22:23:24.748631", no zone - which
// `new Date` reads as local time, wrong by the viewer's offset. A time with
// no zone is taken as the UTC it is.
export function formatWhen(value) {
  if (!value) return '';
  const text = String(value).trim();
  const zoned = /(?:[zZ]|[+-]\d\d:?\d\d)$/.test(text);
  const iso = zoned ? text : `${text.replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1')}Z`;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return text;
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatAccessLogTime(value = '') {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function accessLogBadgeClass(verdict = '') {
  if (verdict === 'allow') return 'access-log-verdict allow';
  if (verdict === 'error') return 'access-log-verdict error';
  return 'access-log-verdict block';
}

export function accessLogVerdictLabel(verdict = '') {
  if (verdict === 'allow') return msg('Allow');
  if (verdict === 'error') return msg('Error');
  return msg('Block');
}

export function accessLogCountryLabel(item = {}) {
  const country = item.country || '';
  const code = item.country_code || '';
  if (country && code && country !== code) return `${country} (${code})`;
  return country || code || '-';
}

export function csvCell(value) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

export function editorParamsFromLocation() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('view') !== 'editor') return null;
  const websiteId = params.get('website_id');
  const appId = params.get('app_id');
  const path = params.get('path') || 'public_html/index.html';
  if (!websiteId && !appId) return null;
  return { websiteId: websiteId ? String(websiteId) : '', appId: appId ? String(appId) : '', path };
}


// --- File permissions (chmod) ------------------------------------------------
// The listing reports POSIX modes as octal strings ("644", and "2755" or the
// like when a folder carries a special bit), so the dialog works on the same
// representation.
// Monday first, matching datetime.weekday() on the server.
// English, and translated where they are shown - a constant cannot call t().
export const WEEKDAY_LABELS = [msg('Monday'), msg('Tuesday'), msg('Wednesday'), msg('Thursday'), msg('Friday'), msg('Saturday'), msg('Sunday')];
export const MALWARE_SCHEDULES_DEFAULT = {
  websites: { enabled: false, weekday: 6, hour: 3, weekday_label: '', next_run_at: '', last_run_at: '', last_status: '' },
  server: { enabled: false, weekday: 6, hour: 4, weekday_label: '', next_run_at: '', last_run_at: '', last_status: '' },
};
export const MALWARE_SCHEDULE_LABELS = {
  websites: msg('All websites'),
  server: msg('Entire server'),
};
// The malware scan schedule is stored and sent to the API as UTC weekday/hour
// (matching datetime.weekday() on the server) - nobody running a Vietnamese
// host should have to do +7 math to pick "giờ ít khách". These convert only
// for display/input; malwareSchedulesForm itself always stays in UTC.
export const VN_UTC_OFFSET_HOURS = 7;
export function utcScheduleToVn(weekday, hour) {
  const vnHour = (hour + VN_UTC_OFFSET_HOURS) % 24;
  const dayShift = hour + VN_UTC_OFFSET_HOURS >= 24 ? 1 : 0;
  return { weekday: (weekday + dayShift) % 7, hour: vnHour };
}
export function vnScheduleToUtc(weekday, hour) {
  const utcHour = (hour - VN_UTC_OFFSET_HOURS + 24) % 24;
  const dayShift = hour - VN_UTC_OFFSET_HOURS < 0 ? -1 : 0;
  return { weekday: (weekday + dayShift + 7) % 7, hour: utcHour };
}

export const PERMISSION_CLASSES = [
  { key: 'owner', label: msg('Owner') },
  { key: 'group', label: msg('Group') },
  { key: 'other', label: msg('Public') },
];
export const PERMISSION_BITS = [
  { key: 'read', label: msg('Read'), value: 4 },
  { key: 'write', label: msg('Write'), value: 2 },
  { key: 'execute', label: msg('Execute'), value: 1 },
];
export const PERMISSION_PRESETS = {
  file: [['644', msg('Default')], ['755', msg('Executable')], ['600', msg('Private')], ['444', msg('Read-only')]],
  dir: [['755', msg('Default')], ['750', msg('Group read')], ['775', msg('Group write')], ['700', msg('Private')]],
};

export function normalizeOctalMode(mode) {
  const value = String(mode ?? '').trim();
  return /^[0-7]{3,4}$/.test(value) ? value : '';
}

export function octalToPermissionBits(mode) {
  const padded = (normalizeOctalMode(mode) || '0644').padStart(4, '0');
  return {
    special: Number(padded[0]),
    owner: Number(padded[1]),
    group: Number(padded[2]),
    other: Number(padded[3]),
  };
}

export function permissionBitsToOctal({ special, owner, group, other }) {
  const body = `${owner}${group}${other}`;
  return special ? `${special}${body}` : body;
}

export function permissionSymbols(mode) {
  const bits = octalToPermissionBits(mode);
  return PERMISSION_CLASSES
    .map(({ key }) => PERMISSION_BITS.map(bit => (bits[key] & bit.value ? bit.key[0] : '-')).join(''))
    .join('');
}

export function formatApiError(detail, fallback = msg('Request failed.')) {
  if (detail === null || detail === undefined || detail === '') return serverText(fallback);
  if (typeof detail === 'string') return serverText(detail.replace(/^Value error,\s*/i, '') || fallback);
  if (typeof detail === 'number' || typeof detail === 'boolean') return String(detail);

  if (Array.isArray(detail)) {
    const messages = detail.map(item => formatApiErrorItem(item)).filter(Boolean);
    return messages.length ? messages.join('\n') : fallback;
  }

  if (typeof detail === 'object') {
    if (detail.detail !== undefined) return formatApiError(detail.detail, fallback);
    if (detail.message !== undefined) return formatApiError(detail.message, fallback);
    if (detail.msg !== undefined) return formatApiError(detail.msg, fallback);
    try { return JSON.stringify(detail); } catch { return fallback; }
  }

  return fallback;
}

export function formatApiErrorItem(item) {
  if (!item || typeof item !== 'object') return formatApiError(item, '');
  const message = formatApiError(item.msg ?? item.message ?? item.detail, msg('Invalid value'));
  const loc = Array.isArray(item.loc)
    ? item.loc.filter(part => part !== 'body' && part !== 'query' && part !== 'path').join('.')
    : '';
  return loc ? `${loc}: ${message}` : message;
}

export function NotificationToast({ type, message, onClose }) {
  const t = useT();
  if (!message) return null;
  const isError = type === 'error';
  const Icon = isError ? AlertCircle : Check;
  return <div className={`app-toast ${isError ? 'app-toast-error' : 'app-toast-success'}`} role={isError ? 'alert' : 'status'} aria-live={isError ? 'assertive' : 'polite'}>
    <Icon className="app-toast-icon" size={18}/>
    <div className="app-toast-content">
      <strong>{isError ? t('Action failed') : t('Completed')}</strong>
      <span>{message}</span>
    </div>
    <button className="app-toast-close" onClick={onClose} aria-label={t('Dismiss notification')} title={t('Dismiss notification')}><X size={16}/></button>
  </div>;
}



// A plain click on an in-panel link stays in the panel; a click that asks for
// a new tab or window is left to the browser, which is what the href is for.
export function followInPanel(event, open) {
  if (event.defaultPrevented || event.button !== 0) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  open();
}
