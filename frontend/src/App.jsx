import React, { useEffect, useState, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import ace from 'ace-builds/src-noconflict/ace';
import 'ace-builds/src-noconflict/ext-language_tools';
import 'ace-builds/src-noconflict/ext-searchbox';
import 'ace-builds/src-noconflict/mode-css';
import 'ace-builds/src-noconflict/mode-html';
import 'ace-builds/src-noconflict/mode-ini';
import 'ace-builds/src-noconflict/mode-javascript';
import 'ace-builds/src-noconflict/mode-json';
import 'ace-builds/src-noconflict/mode-php';
import 'ace-builds/src-noconflict/mode-text';
import 'ace-builds/src-noconflict/mode-yaml';
import 'ace-builds/src-noconflict/theme-textmate';
import 'ace-builds/src-noconflict/theme-tomorrow_night';
import { Archive, ArchiveRestore, ArrowLeft, Ban, Boxes, Check, ChevronDown, Clock, Code2, Copy, Cpu, Database, Dices, ExternalLink, FileText, FolderOpen, Globe, HardDrive, Home, Image, KeyRound, Lock, LogIn, LogOut, MemoryStick, Menu, Moon, MoveRight, Network, Pencil, Save, Search, Server, Settings as SettingsIcon, Shield, Sun, Trash2, TerminalIcon, Users, X, RefreshCw, Plus, Download, Upload, Play, Square, RotateCcw, AlertCircle } from 'lucide-react';
import { Terminal } from './components/Terminal';
import './style.css';
import './brand.css';
import './file-manager.css';
import './theme.css';

const API = import.meta.env.VITE_API_URL || '/api';
const DEFAULT_SERVICE_NAMES = ['snpanel-api', 'nginx', 'php8.3-fpm', 'php8.4-fpm', 'mariadb', 'redis-server'];
const HTTP_FLOOD_DEFAULTS = {
  access_limit_requests: 100,
  access_limit_window: 10,
  access_limit_burst: 100,
  connection_limit: 60,
};
const PHP_VERSION_ORDER = ['5.6', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5'];
const NGINX_REWRITE_MODES = [
  { value: 'none', label: 'None / static PHP' },
  { value: 'front_controller', label: 'PHP front controller' },
  { value: 'laravel', label: 'Laravel' },
  { value: 'codeigniter', label: 'CodeIgniter' },
  { value: 'seohburl', label: 'SEO HB URL' },
];
function composeWebPorts(plan, wanted) {
  // Which ports the service behind the domain listens on. More than one means
  // the customer has to say which, rather than the panel guessing.
  const name = wanted || plan?.web_service;
  const service = plan?.services?.find(item => item.name === name);
  return service?.container_ports || [];
}

// Pages opened from inside another page instead of the sidebar. They have no
// nav entry of their own, so without this the header falls back to the first
// item and titles the page "Dashboard".
const NAV_PARENT_PAGE = { 'waf-site': 'waf' };

// 'waf-site' is reached from the WAF overview rather than the sidebar, but it
// still belongs to Settings so the menu stays open and WAF stays highlighted.
const SETTINGS_PAGE_KEYS = ['settings', 'api-tokens', 'security', 'php', 'firewall', 'waf', 'waf-site', 'malware', 'access-logs', 'updates', 'addons', 'services'];
const PAGE_ROUTES = {
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
  waf: '/waf',
  'waf-site': '/waf-site',
  malware: '/malware',
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
const THEME_STORAGE_KEY = 'snpanel-theme';
const THEME_EVENT = 'snpanel-theme-change';

function readStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored === 'dark' || stored === 'light' ? stored : null;
  } catch { return null; }
}

function systemTheme() {
  try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
  catch { return 'light'; }
}

function currentTheme() {
  const attr = document.documentElement.getAttribute('data-theme');
  if (attr === 'dark' || attr === 'light') return attr;
  return readStoredTheme() || systemTheme();
}

function applyTheme(theme) {
  const root = document.documentElement;
  root.setAttribute('data-theme', theme);
  root.style.colorScheme = theme;
  document.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: theme }));
}

/* Subscribe to the active theme without owning it. */
function useThemeName() {
  const [theme, setTheme] = useState(currentTheme);
  useEffect(() => {
    const handler = event => setTheme(event.detail);
    document.addEventListener(THEME_EVENT, handler);
    return () => document.removeEventListener(THEME_EVENT, handler);
  }, []);
  return theme;
}

/* Owns the theme: persists the user's choice, follows the OS until they pick one. */
function useTheme() {
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

function ThemeToggle({ theme, onToggle, className = '' }) {
  const isDark = theme === 'dark';
  const label = isDark ? 'Switch to light mode' : 'Switch to dark mode';
  return <button
    type="button"
    className={`theme-toggle ${className}`.trim()}
    onClick={onToggle}
    title={label}
    aria-label={label}
    aria-pressed={isDark}
  >{isDark ? <Sun size={16}/> : <Moon size={16}/>}</button>;
}

function WordPressIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" className="lucide">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" />
      <text x="12" y="16" textAnchor="middle" fontSize="11" fontWeight="700" fontFamily="Georgia, serif" fill="currentColor">W</text>
    </svg>
  );
}
const EDITOR_FONT_FAMILY = "Consolas, 'SFMono-Regular', 'Liberation Mono', Menlo, monospace";
const WAF_ACCESS_LOG_DEFAULTS = {
  websiteId: '',
  verdict: 'all',
  query: '',
  limit: 50,
  refresh: 5,
};
const ROUTE_PAGES = new Map([
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

function pageFromPathname(pathname) {
  const normalized = `/${String(pathname || '').replace(/^\/+|\/+$/g, '')}`.toLowerCase();
  return ROUTE_PAGES.get(normalized) || 'dashboard';
}

function routeForPage(pageName) {
  return PAGE_ROUTES[pageName] || PAGE_ROUTES.dashboard;
}

function sortPhpVersions(versions = []) {
  return [...versions].sort((a, b) => {
    const ai = PHP_VERSION_ORDER.indexOf(a);
    const bi = PHP_VERSION_ORDER.indexOf(b);
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    return String(a).localeCompare(String(b), undefined, { numeric: true });
  });
}

function normalizeHttpFloodConfig(config = {}) {
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
const PROXIED_APP_TYPES = ['application'];
const EMPTY_SITE_APP_DRAFT = {
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
const SITE_APP_KIND_LABELS = { node: 'Node.js', docker: 'Container', compose: 'Compose' };
const SITE_APP_KINDS = [
  ['node', 'Node.js', 'SNPanel installs dependencies and keeps the process running under systemd.'],
  ['docker', 'Container', 'SNPanel pulls the image and runs it, published on loopback only.'],
  ['compose', 'Docker Compose', 'Paste your project\u2019s docker-compose.yml. SNPanel checks it and runs a file it generates from what it accepted.'],
];
const WEBSITE_MODES = [
  ['wordpress', 'WordPress'],
  ['php', 'PHP'],
  ['static', 'Static'],
  ['application', 'Application'],
];

function isProxiedAppType(appType) {
  return PROXIED_APP_TYPES.includes(appType);
}

function websiteConfigForm(site = {}) {
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

function formatAccessLogTime(value = '') {
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

function accessLogBadgeClass(verdict = '') {
  if (verdict === 'allow') return 'access-log-verdict allow';
  if (verdict === 'error') return 'access-log-verdict error';
  return 'access-log-verdict block';
}

function accessLogVerdictLabel(verdict = '') {
  if (verdict === 'allow') return 'Allow';
  if (verdict === 'error') return 'Error';
  return 'Block';
}

function accessLogCountryLabel(item = {}) {
  const country = item.country || '';
  const code = item.country_code || '';
  if (country && code && country !== code) return `${country} (${code})`;
  return country || code || '-';
}

function csvCell(value) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

function editorParamsFromLocation() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('view') !== 'editor') return null;
  const websiteId = params.get('website_id');
  const appId = params.get('app_id');
  const path = params.get('path') || 'public_html/index.html';
  if (!websiteId && !appId) return null;
  return { websiteId: websiteId ? String(websiteId) : '', appId: appId ? String(appId) : '', path };
}

function aceModeName(mode) {
  if (mode === 'PHP') return 'php';
  if (mode === 'JavaScript') return 'javascript';
  if (mode === 'CSS') return 'css';
  if (mode === 'HTML') return 'html';
  if (mode === 'JSON') return 'json';
  if (mode === 'YAML') return 'yaml';
  if (mode === 'Config') return 'ini'; // .env, .htaccess, .ini, .conf -> Ace's ini mode
  return 'text';
}

// --- File permissions (chmod) ------------------------------------------------
// The listing reports POSIX modes as octal strings ("644", and "2755" or the
// like when a folder carries a special bit), so the dialog works on the same
// representation.
// Monday first, matching datetime.weekday() on the server.
const WEEKDAY_LABELS = ['Thứ 2', 'Thứ 3', 'Thứ 4', 'Thứ 5', 'Thứ 6', 'Thứ 7', 'Chủ nhật'];
const MALWARE_SCHEDULES_DEFAULT = {
  websites: { enabled: false, weekday: 6, hour: 3, weekday_label: '', next_run_at: '', last_run_at: '', last_status: '' },
  server: { enabled: false, weekday: 6, hour: 4, weekday_label: '', next_run_at: '', last_run_at: '', last_status: '' },
};
const MALWARE_SCHEDULE_LABELS = {
  websites: 'Toàn bộ website',
  server: 'Toàn bộ VPS',
};
// The malware scan schedule is stored and sent to the API as UTC weekday/hour
// (matching datetime.weekday() on the server) - nobody running a Vietnamese
// host should have to do +7 math to pick "giờ ít khách". These convert only
// for display/input; malwareSchedulesForm itself always stays in UTC.
const VN_UTC_OFFSET_HOURS = 7;
function utcScheduleToVn(weekday, hour) {
  const vnHour = (hour + VN_UTC_OFFSET_HOURS) % 24;
  const dayShift = hour + VN_UTC_OFFSET_HOURS >= 24 ? 1 : 0;
  return { weekday: (weekday + dayShift) % 7, hour: vnHour };
}
function vnScheduleToUtc(weekday, hour) {
  const utcHour = (hour - VN_UTC_OFFSET_HOURS + 24) % 24;
  const dayShift = hour - VN_UTC_OFFSET_HOURS < 0 ? -1 : 0;
  return { weekday: (weekday + dayShift + 7) % 7, hour: utcHour };
}

const PERMISSION_CLASSES = [
  { key: 'owner', label: 'Owner' },
  { key: 'group', label: 'Group' },
  { key: 'other', label: 'Public' },
];
const PERMISSION_BITS = [
  { key: 'read', label: 'Read', value: 4 },
  { key: 'write', label: 'Write', value: 2 },
  { key: 'execute', label: 'Execute', value: 1 },
];
const PERMISSION_PRESETS = {
  file: [['644', 'Default'], ['755', 'Executable'], ['600', 'Private'], ['444', 'Read-only']],
  dir: [['755', 'Default'], ['750', 'Group read'], ['775', 'Group write'], ['700', 'Private']],
};

function normalizeOctalMode(mode) {
  const value = String(mode ?? '').trim();
  return /^[0-7]{3,4}$/.test(value) ? value : '';
}

function octalToPermissionBits(mode) {
  const padded = (normalizeOctalMode(mode) || '0644').padStart(4, '0');
  return {
    special: Number(padded[0]),
    owner: Number(padded[1]),
    group: Number(padded[2]),
    other: Number(padded[3]),
  };
}

function permissionBitsToOctal({ special, owner, group, other }) {
  const body = `${owner}${group}${other}`;
  return special ? `${special}${body}` : body;
}

function permissionSymbols(mode) {
  const bits = octalToPermissionBits(mode);
  return PERMISSION_CLASSES
    .map(({ key }) => PERMISSION_BITS.map(bit => (bits[key] & bit.value ? bit.key[0] : '-')).join(''))
    .join('');
}

function formatApiError(detail, fallback = 'Request failed.') {
  if (detail === null || detail === undefined || detail === '') return fallback;
  if (typeof detail === 'string') return detail.replace(/^Value error,\s*/i, '') || fallback;
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

function formatApiErrorItem(item) {
  if (!item || typeof item !== 'object') return formatApiError(item, '');
  const message = formatApiError(item.msg ?? item.message ?? item.detail, 'Invalid value');
  const loc = Array.isArray(item.loc)
    ? item.loc.filter(part => part !== 'body' && part !== 'query' && part !== 'path').join('.')
    : '';
  return loc ? `${loc}: ${message}` : message;
}

function NotificationToast({ type, message, onClose }) {
  if (!message) return null;
  const isError = type === 'error';
  const Icon = isError ? AlertCircle : Check;
  return <div className={`app-toast ${isError ? 'app-toast-error' : 'app-toast-success'}`} role={isError ? 'alert' : 'status'} aria-live={isError ? 'assertive' : 'polite'}>
    <Icon className="app-toast-icon" size={18}/>
    <div className="app-toast-content">
      <strong>{isError ? 'Action failed' : 'Completed'}</strong>
      <span>{message}</span>
    </div>
    <button className="app-toast-close" onClick={onClose} aria-label="Dismiss notification" title="Dismiss notification"><X size={16}/></button>
  </div>;
}

const ACE_THEMES = { light: 'ace/theme/textmate', dark: 'ace/theme/tomorrow_night' };
const aceThemeFor = theme => ACE_THEMES[theme] || ACE_THEMES.light;

function CodeEditor({ value, mode, disabled, onChange, onCursorChange }) {
  const hostRef = useRef(null);
  const editorRef = useRef(null);
  const suppressChangeRef = useRef(false);
  const onChangeRef = useRef(onChange);
  const onCursorChangeRef = useRef(onCursorChange);
  const themeName = useThemeName();
  const themeRef = useRef(themeName);

  useEffect(() => { onChangeRef.current = onChange; }, [onChange]);
  useEffect(() => { onCursorChangeRef.current = onCursorChange; }, [onCursorChange]);
  useEffect(() => {
    themeRef.current = themeName;
    editorRef.current?.setTheme(aceThemeFor(themeName));
  }, [themeName]);

  useEffect(() => {
    if (!hostRef.current) return undefined;
    const editor = ace.edit(hostRef.current, {
      mode: `ace/mode/${aceModeName(mode)}`,
      theme: aceThemeFor(themeRef.current),
      value: value || '',
      readOnly: !!disabled,
      showPrintMargin: false,
      highlightActiveLine: true,
      fontSize: 13,
      tabSize: 2,
      useSoftTabs: true,
      wrap: false,
      selectionStyle: 'text',
    });

    editor.setOptions({
      enableBasicAutocompletion: true,
      enableLiveAutocompletion: true,
      enableMatchBrackets: true,
      enableSnippets: false,
      fontFamily: EDITOR_FONT_FAMILY,
    });
    editor.session.setUseWorker(false);
    editor.session.setNewLineMode('unix');

    let destroyed = false;
    const reportCursor = () => {
      if (destroyed || !editorRef.current || !onCursorChangeRef.current) return;
      const pos = editorRef.current.getCursorPosition();
      onCursorChangeRef.current({ line: pos.row + 1, column: pos.column + 1 });
    };
    const handleChange = () => {
      if (destroyed || !editorRef.current) return;
      if (!suppressChangeRef.current) {
        if (onChangeRef.current) onChangeRef.current(editorRef.current.getValue());
      }
      // Only report cursor on explicit cursor moves, not on every content change
    };

    editor.session.on('change', handleChange);
    editor.selection.on('changeCursor', reportCursor);
    editorRef.current = editor;
    reportCursor();

    return () => {
      destroyed = true;
      editor.session.off('change', handleChange);
      editor.selection.off('changeCursor', reportCursor);
      editor.destroy();
      editorRef.current = null;
      if (hostRef.current) hostRef.current.textContent = '';
    };
  }, []);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    const nextValue = value || '';
    if (nextValue === editor.getValue()) return;
    const cursor = editor.getCursorPosition();
    suppressChangeRef.current = true;
    editor.setValue(nextValue, -1);
    const newRow = Math.max(0, Math.min(cursor.row, editor.session.getLength() - 1));
    editor.moveCursorTo(newRow, cursor.column);
    suppressChangeRef.current = false;
  }, [value]);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.session.setMode(`ace/mode/${aceModeName(mode)}`);
  }, [mode]);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.setReadOnly(!!disabled);
  }, [disabled]);

  return <div className="code-editor-host" ref={hostRef}></div>;
}

function App() {
  // Auth is now cookie-based (HttpOnly snpanel_session). The SPA does not see
  // the JWT at all. We track only whether the user is authenticated in memory.
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const [currentUser, setCurrentUser] = useState(null);
  const [bootstrapping, setBootstrapping] = useState(true);
  const [standaloneEditor] = useState(() => editorParamsFromLocation());
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [needsTwoFactor, setNeedsTwoFactor] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [page, setPage] = useState(() => pageFromPathname(window.location.pathname));
  const [domain, setDomain] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [wpAdminUser, setWpAdminUser] = useState('admin');
  const [wpAdminPassword, setWpAdminPassword] = useState('');
  const [phpVersion, setPhpVersion] = useState('8.4');
  const [siteType, setSiteType] = useState('wordpress');
  const [createSslMode, setCreateSslMode] = useState('none'); // none|letsencrypt|wildcard|shared|manual
  const [createSslToken, setCreateSslToken] = useState(''); // Cloudflare token for the wildcard mode
  const [installWordPress, setInstallWordPress] = useState(true);
  const [nginxCustomEditing, setNginxCustomEditing] = useState(null); // Website settings editor state
  const [websiteSettingsForm, setWebsiteSettingsForm] = useState(websiteConfigForm());
  const [logViewer, setLogViewer] = useState(null); // {id, domain, kind, lines, path, content, exists}
  const [terminalViewer, setTerminalViewer] = useState(null); // {id, domain}
  const [wordpressInstaller, setWordpressInstaller] = useState(null);
  const [websites, setWebsites] = useState([]);
  const [websiteList, setWebsiteList] = useState([]);
  const [websiteSearch, setWebsiteSearch] = useState('');
  const [websiteSearching, setWebsiteSearching] = useState(false);
  const [aliasDrafts, setAliasDrafts] = useState({});
  const [aliasModes, setAliasModes] = useState({});
  const [databases, setDatabases] = useState([]);
  const [dbSearch, setDbSearch] = useState('');
  const [dbSearching, setDbSearching] = useState(false);
  const [newDatabase, setNewDatabase] = useState({ db_name: '', db_user: '', db_password: '' });
  const [createdDbInfo, setCreatedDbInfo] = useState(null);
  const [copiedField, setCopiedField] = useState(null);
  const [users, setUsers] = useState([]);
  const [packages, setPackages] = useState([]);
  const [userTab, setUserTab] = useState('list');
  const [resourceUsage, setResourceUsage] = useState(null);
  const [serviceStates, setServiceStates] = useState({});
  const [serviceNames, setServiceNames] = useState(DEFAULT_SERVICE_NAMES);
  const [backupTab, setBackupTab] = useState('website');
  const [backups, setBackups] = useState([]);
  const [backupJobs, setBackupJobs] = useState([]);
  const [userBackups, setUserBackups] = useState([]);
  const [restoreBackups, setRestoreBackups] = useState([]);
  const [restoreBackupDir, setRestoreBackupDir] = useState('');
  const [selectedBackupUserId, setSelectedBackupUserId] = useState('');
  const [backupSchedules, setBackupSchedules] = useState([]);
  const [newBackupSchedule, setNewBackupSchedule] = useState({ user_ids: [], all_users: false, schedule: '0 2 * * *', target_id: '', retention: 7 });
  const [sftpTargets, setSftpTargets] = useState([]);
  const [selectedSftpTargetId, setSelectedSftpTargetId] = useState('');
  const [newSftpTarget, setNewSftpTarget] = useState({ name: '', host: '', port: 22, username: '', password: '', private_key: '', remote_path: '/backups/snpanel' });
  const [daBackups, setDaBackups] = useState([]);
  const [daReplaceExisting, setDaReplaceExisting] = useState(false);
  const [daScanResult, setDaScanResult] = useState(null);
  const [daImportJob, setDaImportJob] = useState(null);
  const [daBulkImportJob, setDaBulkImportJob] = useState(null);
  const [selectedDaBackups, setSelectedDaBackups] = useState([]);
  const daFileInputRef = React.useRef(null);
  const [selectedWebsiteId, setSelectedWebsiteId] = useState(() => standaloneEditor?.websiteId || '');
  const [sslMode, setSslMode] = useState('letsencrypt');
  const [manualSslForm, setManualSslForm] = useState({ certificate: '', private_key: '', ca_bundle: '' });
  const [manualSslFiles, setManualSslFiles] = useState({ certificate: null, private_key: null, ca_bundle: null });
  const [wildcardToken, setWildcardToken] = useState('');
  const [cfZone, setCfZone] = useState({ zone: null, has_token: false });
  const [sslSources, setSslSources] = useState([]);
  const [sharedSource, setSharedSource] = useState('');
  const [cronSchedule, setCronSchedule] = useState('*/15 * * * *');
  const [cronCommand, setCronCommand] = useState('');
  const [cronItems, setCronItems] = useState([]);
  const [cronUser, setCronUser] = useState('');
  const [cronPhpInfo, setCronPhpInfo] = useState({ php_binary: '', php_version: '' });
  const [siteApps, setSiteApps] = useState({ items: [], limit: 0, used: 0, memory_ceiling_mb: 512, port_range: [21000, 21999] });
  // Optional features. Until this has loaded nothing addon-owned is offered, so
  // a slow first request cannot flash a section that turns out not to be there.
  const [addons, setAddons] = useState({ items: [], can_manage: false, loaded: false });
  const [siteAppDraft, setSiteAppDraft] = useState(EMPTY_SITE_APP_DRAFT);
  const [createSiteAppId, setCreateSiteAppId] = useState('');
  // File manager target: empty means the selected website, otherwise an app.
  const [fileAppId, setFileAppId] = useState(() => standaloneEditor?.appId || '');
  const [siteAppLog, setSiteAppLog] = useState(null);
  const [composePlan, setComposePlan] = useState(null);
  const [siteAppEdit, setSiteAppEdit] = useState(null);
  const [siteAppEditPlan, setSiteAppEditPlan] = useState(null);
  const [siteRuntimes, setSiteRuntimes] = useState({ docker: { installed: false }, node_majors: [], allowed_registries: [] });
  const [chmodTarget, setChmodTarget] = useState(null);
  const [chmodMode, setChmodMode] = useState('644');
  const [filePath, setFilePath] = useState(() => standaloneEditor?.path || 'public_html/index.html');
  const [fileListPath, setFileListPath] = useState('public_html');
  const [fileUploadDir, setFileUploadDir] = useState('public_html');
  const [files, setFiles] = useState([]);
  const [fileJobs, setFileJobs] = useState([]);
  const [fileContent, setFileContent] = useState('');
  const [selectedFilePaths, setSelectedFilePaths] = useState([]);
  const [archiveFormat, setArchiveFormat] = useState('zip');
  const [editorCursor, setEditorCursor] = useState({ line: 1, column: 1 });
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'end_user', package_id: '', website_limit: 5, storage_limit_mb: 1024 });
  const [editingUser, setEditingUser] = useState(null);
  const [editingUserForm, setEditingUserForm] = useState({ email: '', role: 'end_user', package_id: '', website_limit: 5, storage_limit_mb: 1024, new_password: '', confirm_password: '' });
  const [newPackage, setNewPackage] = useState({ name: '', website_limit: 5, storage_limit_mb: 1024 });
  const [editingPackageId, setEditingPackageId] = useState('');
  const [editingPackageForm, setEditingPackageForm] = useState({ name: '', website_limit: 5, storage_limit_mb: 1024 });
  const [phpConfig, setPhpConfig] = useState({ php_version: '8.4', display_errors: 'Off', max_execution_time: 300, max_input_time: 600, max_input_vars: 10000, memory_limit: '1024M', post_max_size: '1024M', upload_max_filesize: '1024M' });
  const [phpVersions, setPhpVersions] = useState({ installed: ['8.4'], supported: ['5.6', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5'] });
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [firewallPort, setFirewallPort] = useState('80');
  const [firewallProtocol, setFirewallProtocol] = useState('tcp');
  const [firewallAllowIp, setFirewallAllowIp] = useState('');
  const [firewallAllowPort, setFirewallAllowPort] = useState('');
  const [firewallAllowProtocol, setFirewallAllowProtocol] = useState('tcp');
  const [firewallBlockIp, setFirewallBlockIp] = useState('');
  const [firewallBlockPort, setFirewallBlockPort] = useState('');
  const [firewallBlockProtocol, setFirewallBlockProtocol] = useState('tcp');
  const [firewallDeleteNumber, setFirewallDeleteNumber] = useState('');
  const [firewallBlocklists, setFirewallBlocklists] = useState(null);
  const [firewallBlocklistUrl, setFirewallBlocklistUrl] = useState('');
  const [wafRules, setWafRules] = useState({ status: null, default_rules: '', custom_rules: '' });
  const [wafCustomRules, setWafCustomRules] = useState('');
  const [selectedWafWebsiteId, setSelectedWafWebsiteId] = useState('');
  const [wafSiteConfig, setWafSiteConfig] = useState(null);
  const [httpFloodForm, setHttpFloodForm] = useState({ http_flood_enabled: false, ...HTTP_FLOOD_DEFAULTS });
  // Bot blocking. The list is free text so a whole blocklist can be pasted in
  // one go; the backend splits and cleans it. Targets are the websites the
  // paste is applied to - it is normally the same list on many sites.
  const [botBlocks, setBotBlocks] = useState(null);
  const [bulkBotOpen, setBulkBotOpen] = useState(false);
  // The global list as an array so each entry can be removed on its own; the
  // paste box is only for adding several at once.
  const [globalBots, setGlobalBots] = useState([]);
  const [crs, setCrs] = useState(null);
  const [newBotName, setNewBotName] = useState('');
  const [globalBotPaste, setGlobalBotPaste] = useState('');
  const [globalBotFilter, setGlobalBotFilter] = useState('');
  // The list for the one site being configured, kept apart from the bulk
  // import above so editing one site cannot disturb a pending bulk paste.
  const [siteBotText, setSiteBotText] = useState('');
  const [wafAccessLogFilters, setWafAccessLogFilters] = useState(WAF_ACCESS_LOG_DEFAULTS);
  const [wafAccessLogs, setWafAccessLogs] = useState({ items: [], total: 0, scanned: 0, missing: [], generated_at: '' });
  const [assignUserId, setAssignUserId] = useState('');
  const [assignWebsiteId, setAssignWebsiteId] = useState('');
  const [twoFactorStatus, setTwoFactorStatus] = useState(null);
  const [twoFactorSetup, setTwoFactorSetup] = useState(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [malwareScanStatus, setMalwareScanStatus] = useState(null);
  const [scanTargetWebsiteId, setScanTargetWebsiteId] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [scanJob, setScanJob] = useState(null);
  const [scanJobs, setScanJobs] = useState([]);
  const [malwareSchedules, setMalwareSchedules] = useState(MALWARE_SCHEDULES_DEFAULT);
  const [malwareSchedulesForm, setMalwareSchedulesForm] = useState(MALWARE_SCHEDULES_DEFAULT);
  const [scanLoading, setScanLoading] = useState(false);
  const [incrementalDays, setIncrementalDays] = useState(2);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState('');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [settingsMenuOpen, setSettingsMenuOpen] = useState(false);
  const [panelSettings, setPanelSettings] = useState({ app_name: 'SNPanel', panel_url: '', panel_hostname: '', panel_port: 2222, logo_url: '', favicon_url: '/favicon.png', ssl_enabled: false });
  const [phpTune, setPhpTune] = useState(null);
  const [phpTuneApplied, setPhpTuneApplied] = useState(false);
  const [panelSettingsForm, setPanelSettingsForm] = useState({ app_name: 'SNPanel', panel_hostname: '', panel_port: 2222, ssl_enabled: false });
  const [apiTokens, setApiTokens] = useState([]);
  const [newApiToken, setNewApiToken] = useState({ name: 'WHMCS', allowed_ips: '' });
  const [createdApiToken, setCreatedApiToken] = useState('');
  const [appVersion, setAppVersion] = useState('');
  const [panelLogoFile, setPanelLogoFile] = useState(null);
  const [panelFaviconFile, setPanelFaviconFile] = useState(null);
  const [adminAccountForm, setAdminAccountForm] = useState({ email: '', current_password: '', password: '', confirm_password: '', code: '' });
  const [updatesStatus, setUpdatesStatus] = useState(null);
  const [showUpdateLog, setShowUpdateLog] = useState(false);
  const [osUpdating, setOsUpdating] = useState(false);
  const [panelUpdating, setPanelUpdating] = useState(false);
  const [panelUpdateLog, setPanelUpdateLog] = useState([]);
  const panelUpdateInterval = useRef(null);
  const [osAutoUpdate, setOsAutoUpdate] = useState({ enabled: true, mode: 'security', auto_reboot: false });
  const noticeTimer = useRef(null);
  const isAdmin = currentUser?.role === 'admin';
  const applicationAddon = addons.items.find(item => item.slug === 'application');
  const applicationAddonInstalled = !!applicationAddon?.installed;
  // Two locks, and both have to be open: the server has to have the addon
  // installed at all, and the customer's package has to include it. Admins skip
  // the second one, never the first.
  const appsFeatureEnabled = applicationAddonInstalled && (isAdmin || siteApps.limit > 0);
  const currentSite = websites.find(site => String(site.id) === String(selectedWebsiteId));
  const accountLabel = currentUser?.package_name
    ? `${currentUser?.username || username} - ${currentUser.package_name}`
    : (currentUser?.username || username);

  const navigateToPage = useCallback((nextPage, options = {}) => {
    const route = routeForPage(nextPage);
    if (!route) return;
    const nextUrl = route;
    if (!options.replace && window.location.pathname !== route) {
      window.history.pushState({}, '', nextUrl);
    } else if (options.replace && window.location.pathname !== route) {
      window.history.replaceState({}, '', nextUrl);
    }
    setPage(nextPage);
  }, []);

  // Auto-dismiss notices after 6 seconds
  useEffect(() => {
    if (notice) {
      if (noticeTimer.current) clearTimeout(noticeTimer.current);
      noticeTimer.current = setTimeout(() => setNotice(''), 6000);
    }
    return () => { if (noticeTimer.current) clearTimeout(noticeTimer.current); };
  }, [notice]);

  function readCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[$()*+./?[\\\]^{|}]/g, '\\$&') + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : '';
  }

  function clearReadableSessionCookies() {
    try {
      document.cookie = 'snpanel_csrf=; Max-Age=0; path=/; SameSite=Lax';
      if (window.location.protocol === 'https:') {
        document.cookie = 'snpanel_csrf=; Max-Age=0; path=/; SameSite=Lax; Secure';
      }
    } catch {}
  }

  function currentPanelHost() {
    return window.location.hostname || '';
  }

  function currentPanelPort() {
    const port = Number(window.location.port || 2222);
    return Number.isFinite(port) && port > 0 ? port : 2222;
  }

  function formFromPanelSettings(data = {}) {
    let hostname = data.panel_hostname || currentPanelHost();
    let port = Number(data.panel_port || currentPanelPort());
    if ((!hostname || !port) && data.panel_url) {
      try {
        const parsed = new URL(data.panel_url);
        hostname = hostname || parsed.hostname;
        port = port || Number(parsed.port || 2222);
      } catch {}
    }
    return {
      app_name: data.app_name || 'SNPanel',
      panel_hostname: hostname,
      panel_port: Number.isFinite(port) && port > 0 ? port : 2222,
      ssl_enabled: !!data.ssl_enabled,
    };
  }

  function clearSession(message = 'Your session expired. Please log in again.') {
    // Old localStorage token from a previous deploy: nuke it for safety.
    try { localStorage.removeItem('token'); } catch {}
    clearReadableSessionCookies();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setNeedsTwoFactor(false);
    setOtpCode('');
    setWebsites([]);
    setDatabases([]);
    setUsers([]);
    setPackages([]);
    setUserTab('list');
    setAdminAccountForm({ email: '', current_password: '', password: '', confirm_password: '', code: '' });
    setResourceUsage(null);
    setServiceStates({});
    setServiceNames(DEFAULT_SERVICE_NAMES);
    setBackupTab('website');
    setBackups([]);
    setBackupJobs([]);
    setCronItems([]);
    setCronUser('');
    setCronPhpInfo({ php_binary: '', php_version: '' });
    setChmodTarget(null);
    setFileAppId('');
    setSiteAppLog(null);
    setUserBackups([]);
    setRestoreBackups([]);
    setRestoreBackupDir('');
    setSelectedBackupUserId('');
    setBackupSchedules([]);
    setSftpTargets([]);
    setSelectedSftpTargetId('');
    setTwoFactorStatus(null);
    setTwoFactorSetup(null);
    setTwoFactorCode('');
    setMalwareScanStatus(null);
    setScanTargetWebsiteId('');
    setScanResults(null);
    setScanJob(null);
    setScanJobs([]);
    setScanLoading(false);
    setWebsiteList([]);
    setWebsiteSearch('');
    setWebsiteSearching(false);
    setUpdatesStatus(null);
    setFirewallBlocklists(null);
    setWafRules({ status: null, default_rules: '', custom_rules: '' });
    setWafCustomRules('');
    setSelectedWafWebsiteId('');
    setWafSiteConfig(null);
    setWafAccessLogFilters(WAF_ACCESS_LOG_DEFAULTS);
    setWafAccessLogs({ items: [], total: 0, scanned: 0, missing: [], generated_at: '' });
    setLogViewer(null);
    setNginxCustomEditing(null);
    setTerminalViewer(null);
    setSelectedWebsiteId('');
    setMobileMenuOpen(false);
    navigateToPage('dashboard', { replace: true });
    setError('');
    setNotice(message);
  }

  function handleAuthExpired(status, detail = '') {
    if (status === 401 || detail === 'Could not validate credentials' || detail === 'Not authenticated') {
      clearSession();
      return true;
    }
    return false;
  }

  async function request(path, options = {}, label = '') {
    try {
      setError('');
      if (label) setLoading(label);
      const { silent, ...fetchOptions } = options;
      const method = (fetchOptions.method || 'GET').toUpperCase();
      const isFormData = typeof FormData !== 'undefined' && fetchOptions.body instanceof FormData;
      const headers = isFormData ? { ...(fetchOptions.headers || {}) } : {
        'Content-Type': 'application/json',
        ...(fetchOptions.headers || {}),
      };
      // CSRF: echo the snpanel_csrf cookie back in a header for mutating
      // requests. The backend rejects mismatches when the request was
      // authenticated via cookie.
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        const csrf = readCookie('snpanel_csrf');
        if (csrf) headers['X-CSRF-Token'] = csrf;
      }
      const res = await fetch(`${API}${path}`, {
        ...fetchOptions,
        credentials: 'include',
        headers,
      });
      const text = await res.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text || `HTTP ${res.status}` }; }
      if (!res.ok && handleAuthExpired(res.status, data.detail)) return null;
      if (!res.ok && !silent) setError(formatApiError(data.detail, `Request failed with status ${res.status}`));
      if (res.ok && data?.message && !silent) setNotice(data.message);
      return res.ok ? data : null;
    } catch (err) {
      setError(`Cannot connect to the ${panelSettings.app_name || 'SNPanel'} API at ${API}. Check snpanel-api and the panel port.`);
      return null;
    } finally {
      if (label) setLoading('');
    }
  }

  async function login() {
    try {
      setError('');
      setLoading('Logging in...');
      const body = new URLSearchParams({ username, password });
      if (needsTwoFactor || otpCode) body.set('otp', otpCode);
      if (rememberMe) body.set('remember', 'true');
      const res = await fetch(`${API}/auth/login`, {
        method: 'POST',
        body,
        credentials: 'include',
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.requires_2fa) {
        setNeedsTwoFactor(true);
        setNotice('Enter your authentication code.');
      } else if (res.ok && data.access_token) {
        // Don't keep the token anywhere: the HttpOnly cookie just got set by
        // the response. JS code MUST NOT touch the JWT.
        setIsAuthenticated(true);
        setNeedsTwoFactor(false);
        setOtpCode('');
        setNotice('Login successful.');
        await loadCurrentUser();
      } else {
        setError(formatApiError(data.detail, `Login failed with status ${res.status}`));
      }
    } catch (err) {
      setError(`Cannot connect to the ${panelSettings.app_name || 'SNPanel'} API at ${API}. Check snpanel-api and the panel port.`);
    } finally {
      setLoading('');
    }
  }

  async function logout() {
    try {
      // Best-effort server logout: clears cookies and bumps token_version.
      await fetch(`${API}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
        headers: (() => {
          const csrf = readCookie('snpanel_csrf');
          return csrf ? { 'X-CSRF-Token': csrf } : {};
        })(),
      });
    } catch {}
    clearSession('Logged out.');
  }

  async function loadCurrentUser({ clearOnUnauthorized = true } = {}) {
    try {
      const res = await fetch(`${API}/auth/session`, { credentials: 'include' });
      if (!res.ok) {
        if (res.status === 401) {
          if (clearOnUnauthorized) clearSession('Session expired.');
          else {
            clearReadableSessionCookies();
            setCurrentUser(null);
            setIsAuthenticated(false);
          }
        }
        return null;
      }
      const data = await res.json();
      if (!data.authenticated || !data.user) {
        if (clearOnUnauthorized) clearSession('Session expired.');
        else {
          clearReadableSessionCookies();
          setCurrentUser(null);
          setIsAuthenticated(false);
        }
        return null;
      }
      setCurrentUser(data.user);
      setAdminAccountForm(prev => ({ ...prev, email: data.user?.email || '' }));
      setIsAuthenticated(true);
      return data.user;
    } catch {
      setCurrentUser(null);
      return null;
    }
  }

  async function loadPanelSettings() {
    // Signed in, the panel tells us more than the login page is allowed to
    // know: the hostnames it answers for and the certificates on this server
    // only come back from the authenticated route.
    const path = currentUser ? '/panel-settings' : '/panel-settings/public';
    try {
      const res = await fetch(`${API}${path}`, { credentials: 'include' });
      if (!res.ok) return null;
      const data = await res.json();
      setPanelSettings(data);
      setPanelSettingsForm(formFromPanelSettings(data));
      return data;
    } catch {
      return null;
    }
  }

  async function loadAppVersion() {
    try {
      const res = await fetch(`${API}/health`, { credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      setAppVersion(data.version || '');
    } catch {}
  }

  async function savePanelSettings() {
    const wantsSsl = !!panelSettingsForm.ssl_enabled;
    const hasSsl = !!panelSettings.ssl_enabled;
    const hostname = String(panelSettingsForm.panel_hostname || '').trim();
    const port = Number(panelSettingsForm.panel_port || 2222);
    const currentHostname = panelSettings.panel_hostname || currentPanelHost();
    const hostnameChanged = hostname && hostname !== currentHostname;

    if (wantsSsl && (!hasSsl || hostnameChanged)) {
      const nameData = await request('/panel-settings', {
        method: 'PATCH',
        body: JSON.stringify({ app_name: panelSettingsForm.app_name }),
      }, 'Saving panel settings...');
      if (!nameData) return;
      const sslData = await request('/panel-settings/ssl', {
        method: 'POST',
        body: JSON.stringify({ panel_hostname: hostname, panel_port: port }),
      }, 'Installing panel SSL...');
      if (sslData) {
        setPanelSettings(sslData);
        setPanelSettingsForm(formFromPanelSettings(sslData));
        setNotice(sslData.message || 'Panel SSL installed. The panel may restart in a moment.');
      }
      return;
    }

    const payload = hasSsl && !wantsSsl
      ? { app_name: panelSettingsForm.app_name, panel_url: `http://${hostname}:${port}` }
      : { app_name: panelSettingsForm.app_name, panel_hostname: hostname };
    const data = await request('/panel-settings', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }, 'Saving panel settings...');
    if (data) {
      setPanelSettings(data);
      setPanelSettingsForm(formFromPanelSettings(data));
      setNotice(hasSsl && !wantsSsl ? 'Panel SSL disabled. The panel remains reachable by IP and port over HTTP.' : 'Panel settings updated.');
    }
  }

  async function saveAdminAccount() {
    const email = String(adminAccountForm.email || '').trim();
    const password = String(adminAccountForm.password || '');
    const confirmPassword = String(adminAccountForm.confirm_password || '');
    const currentPassword = String(adminAccountForm.current_password || '');
    const code = String(adminAccountForm.code || '').trim();

    if (!email) {
      setError('Email is required.');
      return;
    }
    if (password && password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (password && password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    const payload = { email };
    if (password) {
      if (!currentPassword) {
        setError('Current password is required to change password.');
        return;
      }
      payload.password = password;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        if (!code) {
          setError('Authentication code is required.');
          return;
        }
        payload.code = code;
      }
    }

    const data = await request('/panel-settings/admin-account', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }, 'Saving admin account...');
    if (!data) return;
    if (data.password_changed) {
      clearSession('Password changed. Please log in again.');
      return;
    }
    setAdminAccountForm(prev => ({ ...prev, current_password: '', password: '', confirm_password: '', code: '' }));
    await loadCurrentUser({ clearOnUnauthorized: false });
    setNotice(data.message || 'Admin account updated.');
  }

  async function uploadPanelAsset(kind) {
    const file = kind === 'logo' ? panelLogoFile : panelFaviconFile;
    if (!file) return;
    const body = new FormData();
    body.append('file', file);
    const data = await request(`/panel-settings/${kind}`, { method: 'POST', body }, `Uploading ${kind}...`);
    if (data) {
      setPanelSettings(data);
      setPanelSettingsForm(formFromPanelSettings(data));
      if (kind === 'logo') setPanelLogoFile(null);
      if (kind === 'favicon') setPanelFaviconFile(null);
    }
  }

  function brandInitials(value = panelSettings.app_name) {
    const words = String(value || 'SNPanel').trim().split(/\s+/).filter(Boolean);
    const initials = words.length > 1 ? `${words[0][0]}${words[1][0]}` : words[0]?.slice(0, 2);
    return (initials || 'BP').toUpperCase();
  }

  function renderBrandMark(extraClass = '') {
    const classes = ['brand-mark', panelSettings.logo_url ? 'has-logo' : '', extraClass].filter(Boolean).join(' ');
    return <span className={classes}>{panelSettings.logo_url ? <img src={panelSettings.logo_url} alt="" /> : brandInitials()}</span>;
  }

  // Bootstrap: ask for session state without turning an anonymous visit into
  // a console-level 401.
  useEffect(() => {
    (async () => {
      try {
        await loadCurrentUser({ clearOnUnauthorized: false });
      } catch {}
      finally {
        setBootstrapping(false);
        // SSO redirect may carry an error param (e.g. suspended account).
        const urlError = new URLSearchParams(window.location.search).get('error');
        if (urlError) {
          const messages = {
            account_suspended: 'Tài khoản đã bị khóa (suspended). Liên hệ quản trị viên.',
          };
          setError(messages[urlError] || urlError);
          window.history.replaceState({}, '', window.location.pathname);
        }
      }
    })();
  }, []);

  useEffect(() => { loadPanelSettings(); loadAppVersion(); }, []);

  useEffect(() => {
    const appName = panelSettings.app_name || 'SNPanel';
    document.title = appName;
    const configuredFaviconUrl = panelSettings.favicon_url || '/favicon.png';
    const faviconUrl = configuredFaviconUrl.includes('?')
      ? configuredFaviconUrl
      : `${configuredFaviconUrl}?v=${encodeURIComponent(appVersion || 'current')}`;
    const pathname = faviconUrl.split('?', 1)[0].toLowerCase();
    const faviconType = pathname.endsWith('.ico') ? 'image/x-icon'
      : pathname.endsWith('.jpg') || pathname.endsWith('.jpeg') ? 'image/jpeg'
        : pathname.endsWith('.webp') ? 'image/webp'
          : 'image/png';
    document.querySelectorAll('link[rel~="icon"]').forEach(link => link.remove());
    const link = document.createElement('link');
    link.rel = 'icon';
    link.type = faviconType;
    link.href = faviconUrl;
    document.head.appendChild(link);
  }, [panelSettings, appVersion]);

  async function refreshAll() {
    const refreshedUser = await loadCurrentUser();
    const siteData = await request('/websites');
    if (siteData) {
      setWebsites(siteData);
      if (!websiteSearch.trim()) setWebsiteList(siteData);
      if (!selectedWebsiteId && siteData[0]) setSelectedWebsiteId(String(siteData[0].id));
    }
    const dbData = await request(dbSearch.trim() ? `/databases?q=${encodeURIComponent(dbSearch.trim())}` : '/databases');
    if (dbData) setDatabases(dbData);
    if (refreshedUser?.role === 'admin') {
      await loadPhpVersions();
      await loadPackages();
    }
    if (page === 'websites' && websiteSearch.trim()) await loadWebsiteList(websiteSearch, false);
  }

  async function loadWebsiteList(search = websiteSearch, showLoading = false) {
    const query = String(search || '').trim();
    const suffix = query ? `?q=${encodeURIComponent(query)}` : '';
    setWebsiteSearching(true);
    const data = await request(`/websites${suffix}`, {}, showLoading ? 'Loading websites...' : '');
    setWebsiteSearching(false);
    if (data) {
      setWebsiteList(data);
      if (!query) setWebsites(data);
      if (!selectedWebsiteId && data[0]) setSelectedWebsiteId(String(data[0].id));
    }
  }

  async function loadDatabases(search = dbSearch, showLoading = false) {
    const query = String(search || '').trim();
    const suffix = query ? `?q=${encodeURIComponent(query)}` : '';
    setDbSearching(true);
    const data = await request(`/databases${suffix}`, {}, showLoading ? 'Loading databases...' : '');
    setDbSearching(false);
    if (data) setDatabases(data);
  }

  async function loadPackages() {
    const data = await request('/packages');
    if (data) setPackages(data);
  }

  async function loadApiTokens() {
    const data = await request('/provisioning/v1/tokens');
    if (data) setApiTokens(data);
  }

  async function createApiToken() {
    if (!newApiToken.name.trim()) { setError('Token name is required.'); return; }
    const data = await request('/provisioning/v1/tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: newApiToken.name.trim(),
        scopes: 'provisioning:read,provisioning:write',
        allowed_ips: newApiToken.allowed_ips.trim(),
      }),
    }, 'Creating API token...');
    if (data) {
      setCreatedApiToken(data.token || '');
      setNotice('API token created. Copy it now; it will not be shown again. Paste it into WHMCS Server Access Hash.');
      setNewApiToken({ name: 'WHMCS', allowed_ips: '' });
      await loadApiTokens();
    }
  }

  async function copyApiToken() {
    if (!createdApiToken) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(createdApiToken);
      } else {
        const input = document.getElementById('created-api-token');
        input?.focus();
        input?.select();
        document.execCommand('copy');
      }
      setNotice('API token copied. Paste it into WHMCS Server Access Hash.');
    } catch {
      const input = document.getElementById('created-api-token');
      input?.focus();
      input?.select();
      setError('Copy failed. The token is selected; press Ctrl+C.');
    }
  }

  async function revokeApiToken(token) {
    if (!confirm(`Revoke API token ${token.name}? WHMCS using it will stop working.`)) return;
    const data = await request(`/provisioning/v1/tokens/${token.id}`, { method: 'DELETE' }, `Revoking ${token.name}...`);
    if (data) {
      setNotice(`Revoked API token ${token.name}.`);
      await loadApiTokens();
    }
  }

  async function loadUsers() {
    const data = await request('/users');
    if (data) {
      setUsers(data);
      if (!selectedBackupUserId && data[0]) setSelectedBackupUserId(String(data[0].id));
      setNewBackupSchedule(prev => (!prev.all_users && (!prev.user_ids || prev.user_ids.length === 0) && data[0]) ? ({ ...prev, user_ids: [String(data[0].id)] }) : prev);
    }
  }

  async function loadResourceUsage() {
    const data = await request('/services/resource-usage');
    if (data) setResourceUsage(data);
  }

  async function createUser() {
    const payload = {
      ...newUser,
      package_id: newUser.package_id ? Number(newUser.package_id) : null,
      website_limit: Number(newUser.website_limit),
      storage_limit_mb: Number(newUser.storage_limit_mb),
    };
    const data = await request('/users', { method: 'POST', body: JSON.stringify(payload) }, 'Creating user...');
    if (data) {
      setNotice(`Created user ${data.username}`);
      setNewUser({ username: '', email: '', password: '', role: 'end_user', package_id: '', website_limit: 5, storage_limit_mb: 1024 });
      await loadUsers();
      setUserTab('list');
    }
  }

  function applyPackageToNewUser(packageId) {
    const selected = packages.find(item => String(item.id) === String(packageId));
    setNewUser(prev => ({
      ...prev,
      package_id: packageId,
      website_limit: selected ? selected.website_limit : 5,
      storage_limit_mb: selected ? selected.storage_limit_mb : 1024,
    }));
  }

  function applyPackageToEditingUser(packageId) {
    const selected = packages.find(item => String(item.id) === String(packageId));
    setEditingUserForm(prev => ({
      ...prev,
      package_id: packageId,
      website_limit: selected ? selected.website_limit : 5,
      storage_limit_mb: selected ? selected.storage_limit_mb : 1024,
    }));
  }

  function startEditingUser(user) {
    setEditingUser(user);
    setEditingUserForm({
      email: user.email || '',
      role: user.role || 'end_user',
      package_id: user.package_id ? String(user.package_id) : '',
      website_limit: user.website_limit ?? 5,
      storage_limit_mb: user.storage_limit_mb ?? 1024,
      new_password: '',
      confirm_password: '',
    });
  }

  function cancelEditingUser() {
    setEditingUser(null);
    setEditingUserForm({ email: '', role: 'end_user', package_id: '', website_limit: 5, storage_limit_mb: 1024, new_password: '', confirm_password: '' });
    setNewPackage({ name: '', website_limit: 5, storage_limit_mb: 1024 });
    setEditingPackageId('');
    setEditingPackageForm({ name: '', website_limit: 5, storage_limit_mb: 1024 });
  }

  async function updatePanelUser() {
    if (!editingUser) return;
    const websiteLimit = Number(editingUserForm.website_limit);
    const storageLimitMb = Number(editingUserForm.storage_limit_mb);
    if (!editingUserForm.email.trim()) { setError('Email is required.'); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError('Website limit must be between 0 and 1000.');
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError('Storage limit must be between 0 and 1048576 MB.');
      return;
    }
    const payload = {
      email: editingUserForm.email.trim(),
      package_id: editingUserForm.package_id ? Number(editingUserForm.package_id) : null,
      website_limit: websiteLimit,
      storage_limit_mb: storageLimitMb,
    };
    if (editingUser.id !== currentUser?.id) payload.role = editingUserForm.role;
    const data = await request(`/users/${editingUser.id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }, `Updating ${editingUser.username}...`);
    if (data) {
      setNotice(`Updated user ${data.username}.`);
      if (data.id === currentUser?.id) setCurrentUser(prev => ({ ...prev, ...data }));
      cancelEditingUser();
      await loadUsers();
    }
  }

  async function submitPasswordChange(user) {
    if (!user) return;
    const pw = editingUserForm.new_password;
    if (pw.length < 12) { setError('Password must be at least 12 characters.'); return; }
    if (pw !== editingUserForm.confirm_password) { setError('Passwords do not match.'); return; }
    const payload = { password: pw };
    if (user.id === currentUser?.id) {
      const currentPassword = prompt('Enter your current password to confirm this change:');
      if (!currentPassword) return;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        const code = prompt('Enter the 6-digit code from your authenticator:');
        if (!code) return;
        payload.code = code.trim();
      }
    }
    const data = await request(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify(payload) }, `Changing password for ${user.username}...`);
    if (data?.message) {
      setNotice(data.message);
      setEditingUserForm(prev => ({ ...prev, new_password: '', confirm_password: '' }));
    }
  }

  async function createPackage() {
    const websiteLimit = Number(newPackage.website_limit);
    const storageLimitMb = Number(newPackage.storage_limit_mb);
    if (!newPackage.name.trim()) { setError('Package name is required.'); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError('Website limit must be between 0 and 1000.');
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError('Storage limit must be between 0 and 1048576 MB.');
      return;
    }
    const data = await request('/packages', {
      method: 'POST',
      body: JSON.stringify({ name: newPackage.name.trim(), website_limit: websiteLimit, storage_limit_mb: storageLimitMb }),
    }, 'Creating package...');
    if (data) {
      setNotice(`Created package ${data.name}.`);
      setNewPackage({ name: '', website_limit: 5, storage_limit_mb: 1024 });
      await loadPackages();
    }
  }

  function startEditingPackage(item) {
    setEditingPackageId(String(item.id));
    setEditingPackageForm({
      name: item.name || '',
      website_limit: item.website_limit ?? 5,
      storage_limit_mb: item.storage_limit_mb ?? 1024,
    });
  }

  function cancelEditingPackage() {
    setEditingPackageId('');
    setEditingPackageForm({ name: '', website_limit: 5, storage_limit_mb: 1024 });
  }

  async function updatePackage(packageId) {
    const websiteLimit = Number(editingPackageForm.website_limit);
    const storageLimitMb = Number(editingPackageForm.storage_limit_mb);
    if (!editingPackageForm.name.trim()) { setError('Package name is required.'); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError('Website limit must be between 0 and 1000.');
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError('Storage limit must be between 0 and 1048576 MB.');
      return;
    }
    const data = await request(`/packages/${packageId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: editingPackageForm.name.trim(), website_limit: websiteLimit, storage_limit_mb: storageLimitMb }),
    }, 'Updating package...');
    if (data) {
      setNotice(`Updated package ${data.name}.`);
      cancelEditingPackage();
      await loadPackages();
      await loadUsers();
    }
  }

  async function deletePackage(item) {
    if (!confirm(`Delete package ${item.name}?`)) return;
    const data = await request(`/packages/${item.id}`, { method: 'DELETE' }, `Deleting ${item.name}...`);
    if (data) {
      setNotice(`Deleted package ${item.name}.`);
      if (String(editingPackageId) === String(item.id)) cancelEditingPackage();
      await loadPackages();
    }
  }

  async function changeUserPassword(user) {
    const password = prompt(`Enter a new password for ${user.username} (minimum 12 characters):`);
    if (!password) return;
    if (password.length < 12) { setError('Password must be at least 12 characters.'); return; }
    const payload = { password };
    if (user.id === currentUser?.id) {
      const currentPassword = prompt('Enter your current password to confirm this change:');
      if (!currentPassword) return;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        const code = prompt('Enter the 6-digit code from your authenticator:');
        if (!code) return;
        payload.code = code.trim();
      }
    }
    const data = await request(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify(payload) }, `Changing password for ${user.username}...`);
    if (data?.message) setNotice(data.message);
  }

  async function deletePanelUser(user) {
    if (!user || user.id === currentUser?.id) return;
    if (!confirm(`Delete panel user ${user.username} and permanently delete all owned websites, files, databases, SSL certificates, and Linux user data?`)) return;
    const data = await request(`/users/${user.id}`, { method: 'DELETE' }, `Deleting user ${user.username}...`);
    if (data) {
      const count = data.deleted_websites?.length || 0;
      setNotice(`Deleted user ${user.username}${count ? ` and ${count} website(s)` : ''}`);
      await loadUsers();
      await refreshAll();
    }
  }

  async function suspendUser(user) {
    if (!user || user.id === currentUser?.id) return;
    const siteCount = websites.filter(w => w.owner_id === user.id).length;
    if (!confirm(`Suspend user ${user.username}? This will block login, disable all ${siteCount} website(s), lock SFTP, and kill active sessions.`)) return;
    const data = await request(`/users/${user.id}/suspend`, { method: 'POST' }, `Suspending user ${user.username}...`);
    if (data) {
      await loadUsers();
      await refreshAll();
    }
  }

  async function unsuspendUser(user) {
    if (!user || user.id === currentUser?.id) return;
    if (!confirm(`Unsuspend user ${user.username}? This will restore login, websites, and SFTP access.`)) return;
    const data = await request(`/users/${user.id}/unsuspend`, { method: 'POST' }, `Unsuspending user ${user.username}...`);
    if (data) {
      await loadUsers();
      await refreshAll();
    }
  }

  async function quickLoginUser(user) {
    if (!user) return;
    const suspendedNote = user.is_active ? '' : ' This user is SUSPENDED — websites and SFTP are disabled.';
    if (!confirm(`Login as ${user.username}?${suspendedNote}`)) return;
    // Impersonation re-prompts TOTP when the calling admin has 2FA enabled.
    // Try without the code first; if the backend says one is required, ask
    // and resend. Sending the OTP via FormData keeps it out of the URL.
    let body;
    if (currentUser?.totp_enabled) {
      const code = prompt(`Enter the 6-digit code from your authenticator to confirm impersonation of ${user.username}:`);
      if (!code) return;
      body = new URLSearchParams({ otp: code.trim() });
    }
    const data = await request(
      `/auth/impersonate/${user.id}`,
      body
        ? { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        : { method: 'POST' },
      `Logging in as ${user.username}...`,
    );
    // Handle case where backend says 2FA is required (e.g., stale user object).
    if (data?.requires_2fa) {
      const code = prompt(`Enter the 6-digit code from your authenticator to confirm impersonation of ${user.username}:`);
      if (!code) return;
      const retryBody = new URLSearchParams({ otp: code.trim() });
      const retryData = await request(
        `/auth/impersonate/${user.id}`,
        { method: 'POST', body: retryBody, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
        `Logging in as ${user.username}...`,
      );
      if (retryData?.access_token) {
        setNotice(`Logged in as ${user.username}.`);
        await loadCurrentUser();
        navigateToPage('websites');
        await refreshAll();
      }
      return;
    }
    if (data?.access_token) {
      setNotice(`Logged in as ${user.username}.`);
      await loadCurrentUser();
      navigateToPage('websites');
      await refreshAll();
    }
  }

  async function loadTwoFactorStatus() {
    const data = await request('/auth/2fa/status');
    if (data) setTwoFactorStatus(data);
  }

  async function setupTwoFactorAuth() {
    const currentPassword = prompt('Enter your current password to generate a new 2FA secret:');
    if (!currentPassword) return;
    const payload = { current_password: currentPassword };
    if (currentUser?.totp_enabled) {
      const code = prompt('Enter the 6-digit code from your authenticator:');
      if (!code) return;
      payload.code = code.trim();
    }
    const data = await request('/auth/2fa/setup', { method: 'POST', body: JSON.stringify(payload) }, 'Preparing 2FA...');
    if (data) {
      setTwoFactorSetup(data);
      setTwoFactorStatus({ enabled: false });
    }
  }

  async function enableTwoFactorAuth() {
    const data = await request('/auth/2fa/enable', { method: 'POST', body: JSON.stringify({ code: twoFactorCode }) }, 'Enabling 2FA...');
    if (data) {
      setTwoFactorStatus(data);
      setTwoFactorSetup(null);
      setTwoFactorCode('');
      await loadCurrentUser();
      setNotice('2FA enabled.');
    }
  }

  async function disableTwoFactorAuth() {
    const currentPassword = prompt('Enter your current password to disable 2FA:');
    if (!currentPassword) return;
    const data = await request(
      '/auth/2fa/disable',
      { method: 'POST', body: JSON.stringify({ current_password: currentPassword, code: twoFactorCode }) },
      'Disabling 2FA...',
    );
    if (data) {
      setTwoFactorStatus(data);
      setTwoFactorCode('');
      await loadCurrentUser();
      setNotice('2FA disabled.');
    }
  }

  async function resetUserTwoFactor(user) {
    if (!confirm(`Reset 2FA for ${user.username}?`)) return;
    const data = await request(`/users/${user.id}/2fa/reset`, { method: 'POST' }, `Resetting 2FA for ${user.username}...`);
    if (data?.message) { setNotice(data.message); await loadUsers(); }
  }

  async function loadMalwareScanStatus() {
    const data = await request('/malware/status', {}, 'Đang tải trạng thái quét...');
    if (data) setMalwareScanStatus(data);
  }

  async function toggleIpv6(enable) {
    const ipv6 = panelSettings.ipv6 || {};
    if (enable && !ipv6.available) {
      setError(ipv6.detail || 'VPS của bạn không có IPv6 nên không thể dùng tính năng này.');
      return;
    }
    if (!confirm(enable
      ? 'Bật IPv6 cho toàn bộ website và panel?\n\nSNPanel sẽ thêm listen [::] vào cấu hình nginx của mọi website, kiểm tra bằng nginx -t và tự hoàn tác nếu có lỗi. Panel sẽ khởi động lại.'
      : 'Tắt IPv6?\n\nWebsite và panel sẽ chỉ còn nhận kết nối IPv4. Nếu domain đang có bản ghi AAAA, khách đi bằng IPv6 sẽ không vào được.')) return;
    const data = await request('/panel-settings/ipv6', {
      method: 'POST',
      body: JSON.stringify({ enabled: enable }),
    }, enable ? 'Đang bật IPv6...' : 'Đang tắt IPv6...');
    if (data) {
      setPanelSettings(data);
      setNotice(data.message || (enable ? 'Đã bật IPv6.' : 'Đã tắt IPv6.'));
    }
  }

  async function toggleMalwareScan(enable) {
    if (enable && !malwareScanStatus?.installed) {
      if (!confirm('Trình quét chưa được cài trên máy chủ này. Panel sẽ cài đặt ngay bây giờ (mất khoảng 1-2 phút). Tiếp tục?')) return;
    }
    const data = await request('/malware/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled: enable }),
    }, enable ? 'Đang bật trình quét...' : 'Đang tắt trình quét...');
    if (data) {
      setPanelSettings(data);
      setNotice(data.message || `Đã ${enable ? 'bật' : 'tắt'} trình quét.`);
      await loadMalwareScanStatus();
    }
  }

  async function loadMalwareSchedule() {
    const data = await request('/malware/schedule', { silent: true }, '');
    if (data) {
      setMalwareSchedules(data);
      setMalwareSchedulesForm(data);
    }
  }

  async function saveMalwareSchedule() {
    const f = malwareSchedulesForm;
    if (f.server?.enabled && malwareScanStatus?.memory_warning) {
      if (!confirm(`${malwareScanStatus.memory_warning}\n\nVẫn đặt lịch quét toàn bộ VPS?`)) return;
    }
    const body = {};
    for (const name of ['websites', 'server']) {
      const e = f[name] || {};
      body[name] = { enabled: !!e.enabled, weekday: Number(e.weekday ?? 6), hour: Number(e.hour ?? 3) };
    }
    const data = await request('/malware/schedule', { method: 'PUT', body: JSON.stringify(body) }, 'Đang lưu lịch quét...');
    if (data) {
      setMalwareSchedules(data);
      setMalwareSchedulesForm(data);
      const on = ['websites', 'server'].filter(n => data[n]?.enabled).map(n => MALWARE_SCHEDULE_LABELS[n]);
      setNotice(on.length ? `Đã lưu lịch: ${on.join(', ')}.` : 'Đã tắt tất cả lịch quét.');
    }
  }

  async function toggleMalwareRealtime(enabled) {
    if (enabled && !confirm('Bật bảo vệ thời gian thực? Panel sẽ theo dõi và quét ngay tệp mới trong thư mục website. Nếu chưa cài, panel sẽ cài thêm (1-3 phút).')) return;
    const data = await request('/malware/realtime', { method: 'POST', body: JSON.stringify({ enabled }) },
      enabled ? 'Đang bật bảo vệ thời gian thực...' : 'Đang tắt...');
    if (data) { setMalwareScanStatus(data); setNotice(enabled ? 'Đã bật bảo vệ thời gian thực (cấp 2).' : 'Đã tắt bảo vệ thời gian thực.'); }
  }

  async function installLmd() {
    const data = await request('/malware/lmd/install', { method: 'POST' }, 'Đang cài đặt...');
    if (data) { setMalwareScanStatus(data); setNotice('Đang cài đặt trình quét trong nền (1-3 phút). Bấm Refresh để cập nhật.'); }
  }

  async function updateMalwareSignatures() {
    const data = await request('/malware/lmd/update-sigs', { method: 'POST' }, 'Đang cập nhật chữ ký...');
    if (data) { setMalwareScanStatus(data); setNotice(data.message || 'Đã cập nhật chữ ký.'); }
  }

  async function runMalwareScan() {
    if (!scanTargetWebsiteId) return;
    if (scanTargetWebsiteId === 'server' && malwareScanStatus?.memory_warning) {
      if (!confirm(`${malwareScanStatus.memory_warning}\n\nVẫn quét toàn bộ VPS?`)) return;
    }
    setScanResults(null);
    setScanJob(null);
    setScanLoading(true);
    try {
      const body = scanTargetWebsiteId === 'server'
        ? { server: true }
        : scanTargetWebsiteId === 'incremental'
        ? { mode: 'incremental', days: Number(incrementalDays) || 2 }
        : scanTargetWebsiteId === 'all'
        ? { all: true }
        : { website_id: Number(scanTargetWebsiteId) };
      const data = await request('/malware/run', {
        method: 'POST',
        body: JSON.stringify(body),
      }, 'Đang bắt đầu quét...');
      if (data) {
        setScanJob(data);
        await loadMalwareScanJobs();
        setNotice('Đã bắt đầu quét.');
      }
    } finally {
      setScanLoading(false);
    }
  }

  async function loadMalwareScanJob(jobId) {
    const data = await request(`/malware/jobs/${jobId}`, {}, '');
    if (!data) return null;
    if (['done', 'infected', 'error', 'interrupted'].includes(data.status)) {
      setScanLoading(false);
      setScanJob(null);
      setScanResults(null);
      if (data.status === 'infected' || data.infected > 0) {
        setNotice(`Phát hiện ${data.infected} mối đe doạ.`);
      } else if (['error', 'interrupted'].includes(data.status)) {
        setError(data.error || data.message || 'Quét thất bại.');
      } else {
        setNotice(`Quét xong: đã kiểm tra ${data.scanned || 0} tệp, không phát hiện mối đe doạ.`);
      }
      await loadMalwareScanJobs();
    } else {
      setScanJob(data);
    }
    return data;
  }

  async function loadMalwareScanJobs() {
    const data = await request('/malware/jobs', { silent: true }, '');
    if (data?.jobs) setScanJobs(data.jobs);
    return data?.jobs || [];
  }

  function showMalwareScanJob(job) {
    setScanJob(job);
    setScanResults(job);
    setScanLoading(['queued', 'running'].includes(job?.status));
  }

  async function loadLatestMalwareScanJob() {
    const data = await request('/malware/jobs/latest', { silent: true }, '');
    if (!data) return null;
    if (['done', 'infected', 'error', 'interrupted'].includes(data.status)) {
      setScanJob(null);
      setScanResults(null);
      setScanLoading(false);
    } else {
      setScanJob(data);
    }
    return data;
  }

  async function startClamavDaemon() {
    const data = await request('/malware/start-daemon', { method: 'POST' }, 'Starting ClamAV daemon...');
    if (data) {
      setNotice(data.message || 'ClamAV daemon started.');
      await loadMalwareScanStatus();
    }
  }

  async function assignDomainToUser() {
    if (!assignWebsiteId || !assignUserId) return;
    const data = await request(`/websites/${assignWebsiteId}`, { method: 'PATCH', body: JSON.stringify({ owner_id: Number(assignUserId) }) }, 'Assigning domain to user...');
    if (data) { setNotice(`Assigned domain ${data.domain} to user ID ${assignUserId}`); await refreshAll(); }
  }

  async function createWordPress() {
    const cleanDomain = domain.trim().toLowerCase();
    const cleanAdminEmail = adminEmail.trim();
    if (!cleanDomain) { setError('Please enter a domain name.'); return; }
    const installWp = siteType === 'wordpress' && installWordPress;
    if (siteType === 'application' && !createSiteAppId) {
      setError('Pick which application this website should serve.');
      return;
    }
    const body = {
      domain: cleanDomain,
      php_version: phpVersion,
      app_type: siteType,
      install_wordpress: installWp,
      title: cleanDomain,
    };
    if (siteType === 'application') body.app_id = Number(createSiteAppId);
    if (installWp) {
      body.admin_user = wpAdminUser;
      body.admin_email = cleanAdminEmail || `admin@${cleanDomain}`;
      body.admin_password = wpAdminPassword || 'StrongPass123!';
    }
    const data = await request('/websites', { method: 'POST', body: JSON.stringify(body) },
      installWp ? 'Creating WordPress website...' : 'Creating website...');
    if (data) {
      if (installWp) {
        setNotice(`Created WordPress site: https://${cleanDomain}\nAdmin: ${wpAdminUser} | Password: ${wpAdminPassword || 'StrongPass123!'}`);
      } else if (siteType === 'application') {
        setNotice(`Created ${cleanDomain}, serving the selected application.`);
        setCreateSiteAppId('');
      } else {
        setNotice(`Created site ${cleanDomain}. Upload your files to public_html/ folder.`);
      }
      if (createSslMode !== 'none') await applyCreateSsl(data.id, cleanDomain);
      refreshAll();
    }
  }

  async function deleteWebsite(id) {
    if (!confirm('Delete this website including files, vhost, database, and its SSL certificate?')) return;
    const data = await request(`/websites/${id}?delete_files=true&delete_database=true`, { method: 'DELETE' }, 'Deleting website...');
    if (data) refreshAll();
  }

  async function enableSsl(id) {
    const data = await request(`/websites/${id}/ssl`, { method: 'POST' }, "Installing Let's Encrypt SSL...");
    if (data) refreshAll();
  }

  // Run the SSL step chosen in the "Create website" form, on the site that was
  // just created. The site already exists at this point, so a failure here is
  // reported but never rolls the site back — the operator can retry from the
  // SSL page.
  async function applyCreateSsl(id, siteDomain) {
    if (createSslMode === 'letsencrypt') {
      await enableSsl(id);
      return;
    }
    if (createSslMode === 'wildcard') {
      const body = {};
      if (createSslToken.trim()) body.cloudflare_api_token = createSslToken.trim();
      const data = await request(`/websites/${id}/ssl/wildcard`,
        { method: 'POST', body: JSON.stringify(body) },
        'Issuing wildcard certificate via Cloudflare...');
      if (data) {
        setCreateSslToken('');
        setNotice(`Created ${siteDomain}. Wildcard SSL active — *.${data.ssl_source_domain} covers it.`);
      }
      return;
    }
    if (createSslMode === 'shared') {
      const sources = await request(`/websites/${id}/ssl/sources`, { silent: true });
      const list = Array.isArray(sources) ? sources : [];
      if (!list.length) {
        setError(`Created ${siteDomain}, but no existing certificate covers it. Enable SSL from the SSL page.`);
        return;
      }
      // Prefer a wildcard cert, then the longest-matching source domain.
      const pick = [...list].sort((a, b) =>
        (b.wildcard - a.wildcard) || (b.domain.length - a.domain.length))[0];
      const data = await request(`/websites/${id}/ssl/shared`,
        { method: 'POST', body: JSON.stringify({ source_domain: pick.domain }) },
        `Using ${pick.domain}'s certificate...`);
      if (data) setNotice(`Created ${siteDomain}, now serving ${pick.domain}'s certificate.`);
      return;
    }
    if (createSslMode === 'manual') {
      // Manual SSL needs the cert and key pasted in; send the operator to the
      // SSL page for this site to finish it there.
      setSelectedWebsiteId(String(id));
      setNotice(`Created ${siteDomain}. Open the Manual tab on the SSL page to paste its certificate.`);
      navigateToPage('ssl');
    }
  }

  async function addWebsiteAlias(site) {
    const cleanAlias = String(aliasDrafts[site.id] || '').trim().toLowerCase();
    const aliasMode = aliasModes[site.id] || 'alias';
    if (!cleanAlias) { setError('Enter a domain.'); return; }
    const data = await request(`/websites/${site.id}/aliases`, {
      method: 'POST',
      body: JSON.stringify({ domain: cleanAlias, mode: aliasMode }),
    }, `Adding ${aliasMode === 'redirect' ? 'redirect' : 'alias'} ${cleanAlias}...`);
    if (data) {
      const label = aliasMode === 'redirect' ? 'redirect' : 'alias';
      // Adding a domain only wires it into Nginx - same split DirectAdmin
      // uses. Getting it a certificate is the separate, explicit step on the
      // SSL page (Install / Renew SSL there already asks for every alias and
      // redirect), so nothing SSL-related is attempted or claimed here.
      setNotice(site.ssl_mode === 'letsencrypt' && !data.ssl_enabled
        ? `Đã thêm ${label} ${cleanAlias}. Vào trang SSL, bấm "Install / Renew SSL" để cấp chứng chỉ cho domain này.`
        : `Đã thêm ${label} ${cleanAlias}.`);
      setAliasDrafts(prev => ({ ...prev, [site.id]: '' }));
      setNginxCustomEditing(prev => {
        if (!prev || prev.id !== site.id) return prev;
        const nextSite = prev.site || site;
        return { ...prev, site: { ...nextSite, aliases: [...(nextSite.aliases || []), data] } };
      });
      await refreshAll();
    }
  }

  async function deleteWebsiteAlias(site, alias) {
    const label = alias.mode === 'redirect' ? 'redirect' : 'alias';
    if (!confirm(`Remove ${label} ${alias.domain} from ${site.domain}?`)) return;
    const data = await request(`/websites/${site.id}/aliases/${alias.id}`, { method: 'DELETE' }, `Removing ${label} ${alias.domain}...`);
    if (data) {
      setNotice(`Removed ${label} ${alias.domain}.`);
      setNginxCustomEditing(prev => {
        if (!prev || prev.id !== site.id) return prev;
        const nextSite = prev.site || site;
        return { ...prev, site: { ...nextSite, aliases: (nextSite.aliases || []).filter(item => item.id !== alias.id) } };
      });
      await refreshAll();
    }
  }

  async function installManualSsl() {
    if (!selectedWebsiteId) return;
    const hasCert = manualSslFiles.certificate || manualSslForm.certificate.trim();
    const hasKey = manualSslFiles.private_key || manualSslForm.private_key.trim();
    if (!hasCert || !hasKey) {
      setError('Certificate and private key are required.');
      return;
    }
    const form = new FormData();
    if (manualSslFiles.certificate) form.append('certificate', manualSslFiles.certificate);
    else form.append('certificate_text', manualSslForm.certificate);
    if (manualSslFiles.private_key) form.append('private_key', manualSslFiles.private_key);
    else form.append('private_key_text', manualSslForm.private_key);
    if (manualSslFiles.ca_bundle) form.append('ca_bundle', manualSslFiles.ca_bundle);
    else if (manualSslForm.ca_bundle.trim()) form.append('ca_bundle_text', manualSslForm.ca_bundle);
    const data = await request(`/websites/${selectedWebsiteId}/ssl/manual`, { method: 'POST', body: form }, 'Installing manual SSL...');
    if (data) {
      setManualSslForm({ certificate: '', private_key: '', ca_bundle: '' });
      setManualSslFiles({ certificate: null, private_key: null, ca_bundle: null });
      refreshAll();
    }
  }

  async function loadCfZone(id) {
    const data = await request(`/websites/${id}/ssl/cloudflare-zone`, { silent: true });
    if (data) setCfZone({ zone: data.zone || null, has_token: !!data.has_token });
  }

  async function loadSslSources(id) {
    const data = await request(`/websites/${id}/ssl/sources`, { silent: true });
    setSslSources(Array.isArray(data) ? data : []);
  }

  async function installWildcardSsl() {
    if (!selectedWebsiteId) return;
    const body = {};
    if (wildcardToken.trim()) body.cloudflare_api_token = wildcardToken.trim();
    else if (!cfZone.has_token) { setError('Paste a Cloudflare API token (Zone.DNS Edit).'); return; }
    const data = await request(`/websites/${selectedWebsiteId}/ssl/wildcard`,
      { method: 'POST', body: JSON.stringify(body) }, 'Issuing wildcard certificate via Cloudflare...');
    if (data) {
      setWildcardToken('');
      setNotice(`Wildcard SSL active — *.${data.ssl_source_domain} covers this site.`);
      refreshAll();
    }
  }

  async function installSharedSsl() {
    if (!selectedWebsiteId || !sharedSource) return;
    const data = await request(`/websites/${selectedWebsiteId}/ssl/shared`,
      { method: 'POST', body: JSON.stringify({ source_domain: sharedSource }) },
      `Using ${sharedSource}'s certificate...`);
    if (data) {
      setNotice(`Now serving ${sharedSource}'s certificate.`);
      refreshAll();
    }
  }

  async function openNginxCustom(site) {
    setWordpressInstaller(null);
    setLogViewer(null);
    setTerminalViewer(null);
    setWebsiteSettingsForm(websiteConfigForm(site));
    const data = await request(`/websites/${site.id}/nginx-custom`, {}, 'Loading Custom Nginx...');
    if (data !== null) {
      setNginxCustomEditing({
        id: site.id,
        domain: site.domain,
        site,
        mode: 'custom',
        content: data?.nginx_custom || '',
      });
      await loadSiteApps();
    }
  }

  async function loadSiteApps() {
    const data = await request('/site-apps', { silent: true });
    if (data) setSiteApps({ port_range: [21000, 21999], ...data });
  }

  async function loadAddons() {
    const data = await request('/addons', { silent: true });
    setAddons({ items: data?.items || [], can_manage: !!data?.can_manage, loaded: true });
  }

  async function setAddonInstalled(slug, install) {
    const addon = addons.items.find(item => item.slug === slug);
    const label = addon?.name || slug;
    if (!install && !confirm(`Gỡ addon ${label}?\n\nCác ứng dụng đang chạy sẽ được dừng. Thư mục, volume và dữ liệu trong panel giữ nguyên, cài lại là chạy tiếp.`)) return;
    const data = await request(`/addons/${slug}/${install ? 'install' : 'uninstall'}`, { method: 'POST' },
      install ? `Đang cài ${label}...` : `Đang gỡ ${label}...`);
    if (data) {
      setNotice(install
        ? `Đã cài ${label}. ${data.next_step || ''}`.trim()
        : `Đã gỡ ${label}.${data.stopped?.length ? ` Đã dừng ${data.stopped.length} ứng dụng.` : ''}`);
      await loadAddons();
      // The nav and the website mode picker both hang off this.
      if (install) await loadSiteApps();
      else if (page === 'applications') navigateToPage('dashboard');
    }
  }

  async function validateCompose(source, webService, env, webPort) {
    return await request('/site-apps/compose/validate', {
      method: 'POST',
      body: JSON.stringify({
        compose_source: source,
        web_service: webService || null,
        env: env || '',
        web_port: Number(webPort) || null,
      }),
    }, 'Checking the compose file...');
  }

  async function checkComposeFile() {
    const data = await validateCompose(siteAppDraft.compose_source, siteAppDraft.web_service, siteAppDraft.env, siteAppDraft.container_port);
    if (data) {
      setComposePlan(data);
      if (data.web_service && !siteAppDraft.web_service) {
        setSiteAppDraft(prev => ({ ...prev, web_service: data.web_service }));
      }
    }
  }

  function openSiteAppEdit(app) {
    if (siteAppEdit?.id === app.id) { setSiteAppEdit(null); setSiteAppEditPlan(null); return; }
    setSiteAppEditPlan(null);
    setSiteAppEdit({
      id: app.id,
      kind: app.kind,
      compose_source: app.compose_source || '',
      web_service: app.web_service || '',
      container_port: app.container_port || '',
      env: app.env || '',
    });
  }

  async function checkSiteAppEdit() {
    const data = await validateCompose(siteAppEdit.compose_source, siteAppEdit.web_service, siteAppEdit.env, siteAppEdit.container_port);
    if (data) {
      setSiteAppEditPlan(data);
      if (data.web_service && !siteAppEdit.web_service) {
        setSiteAppEdit(prev => ({ ...prev, web_service: data.web_service }));
      }
    }
  }

  async function saveSiteAppEdit(app) {
    const patch = app.kind === 'compose'
      ? {
          compose_source: siteAppEdit.compose_source,
          web_service: siteAppEdit.web_service || null,
          env: siteAppEdit.env,
          container_port: Number(siteAppEdit.container_port) || null,
        }
      : { env: siteAppEdit.env };
    const data = await request(`/site-apps/${app.id}`, { method: 'PUT', body: JSON.stringify(patch) }, 'Saving configuration...');
    if (data) {
      setSiteAppEdit(null);
      setSiteAppEditPlan(null);
      setNotice(`Saved ${data.name}.`);
      await loadSiteApps();
    }
  }

  async function loadSiteRuntimes() {
    const data = await request('/site-runtimes/status', { silent: true });
    if (data) setSiteRuntimes(data);
  }

  async function deploySiteApp(app) {
    const data = await request(`/site-apps/${app.id}/deploy`, { method: 'POST' }, `Deploying ${app.name}...`);
    if (data) {
      setNotice(data.running ? `${app.name} is running on port ${app.port}.` : `${app.name} was deployed but is not running — check the log.`);
      // What it downloaded and installed, which is otherwise invisible.
      if (data.output) setSiteAppLog({ name: `${app.name} deploy`, log: data.output });
      await loadSiteApps();
    }
  }

  async function controlSiteApp(app, action) {
    const data = await request(`/site-apps/${app.id}/control`, { method: 'POST', body: JSON.stringify({ action }) }, `${action} ${app.name}...`);
    if (data) {
      setNotice(`${app.name} is ${data.running ? 'running' : 'stopped'}.`);
      await loadSiteApps();
    }
  }

  async function openSiteAppLog(app) {
    const data = await request(`/site-apps/${app.id}/logs?lines=300`, {}, `Loading ${app.name} log...`);
    if (data) setSiteAppLog({ name: app.name, log: data.log || 'No output yet.' });
  }

  async function installDockerEngine() {
    const data = await request('/site-runtimes/docker-install', { method: 'POST' }, 'Installing Docker, this takes a few minutes...');
    if (data) {
      setNotice(data.message || 'Docker is ready.');
      await loadSiteRuntimes();
    }
  }

  async function pruneDocker() {
    const data = await request('/site-runtimes/docker-prune', { method: 'POST' }, 'Đang dọn layer Docker không dùng...');
    if (data) {
      setNotice(data.message || 'Đã dọn.');
      if (data.output) setSiteAppLog({ name: 'docker prune', log: data.output });
      await loadSiteRuntimes();
    }
  }

  async function installNodeMajor(major) {
    const data = await request('/site-runtimes/node-install', { method: 'POST', body: JSON.stringify({ major }) }, `Installing Node ${major}...`);
    if (data) {
      setNotice(data.message || `Node ${major} is ready.`);
      await loadSiteRuntimes();
    }
  }

  async function createSiteApp() {
    const body = {
      name: siteAppDraft.name,
      kind: siteAppDraft.kind,
    };
    if (String(siteAppDraft.port).trim()) body.port = Number(siteAppDraft.port);
    if (String(siteAppDraft.memory_limit_mb).trim()) body.memory_limit_mb = Number(siteAppDraft.memory_limit_mb);
    if (siteAppDraft.env.trim()) body.env = siteAppDraft.env;
    if (siteAppDraft.kind === 'node') {
      body.start_kind = siteAppDraft.start_kind;
      body.start_arg = siteAppDraft.start_arg;
      body.node_major = siteAppDraft.node_major;
    }
    if (siteAppDraft.kind === 'docker') {
      body.image = siteAppDraft.image.trim();
      body.container_port = Number(siteAppDraft.container_port) || 3000;
      body.cpu_limit = siteAppDraft.cpu_limit;
    }
    if (siteAppDraft.kind === 'compose') {
      body.compose_source = siteAppDraft.compose_source;
      body.cpu_limit = siteAppDraft.cpu_limit;
      if (siteAppDraft.web_service) body.web_service = siteAppDraft.web_service;
      if (siteAppDraft.container_port) body.container_port = Number(siteAppDraft.container_port);
    }
    const data = await request('/site-apps', { method: 'POST', body: JSON.stringify(body) }, 'Creating application...');
    if (data) {
      setNotice(`Application ${data.name} created. Upload your files to ${data.directory} and press Deploy.`);
      setSiteAppDraft(EMPTY_SITE_APP_DRAFT);
      setComposePlan(null);
      await loadSiteApps();
    }
  }

  async function updateSiteApp(app, patch, label = 'Updating application...') {
    const data = await request(`/site-apps/${app.id}`, { method: 'PUT', body: JSON.stringify(patch) }, label);
    if (data) {
      setNotice(`Updated ${data.name}.`);
      await loadSiteApps();
    }
  }

  async function deleteSiteApp(app) {
    if (!confirm(`Delete application ${app.name}? Its files stay on disk; only the runtime is removed.`)) return;
    const data = await request(`/site-apps/${app.id}`, { method: 'DELETE' }, 'Deleting application...');
    if (data) {
      setNotice(`Deleted ${app.name}.`);
      await loadSiteApps();
    }
  }

  async function suggestSiteAppPort() {
    const data = await request('/site-apps/suggest-port', { silent: true });
    if (data?.port) setSiteAppDraft(prev => ({ ...prev, port: String(data.port) }));
  }

  async function viewFullNginxConfig() {
    if (!nginxCustomEditing) return;
    const data = await request(`/websites/${nginxCustomEditing.id}/nginx-config`, {}, 'Loading full Nginx config...');
    if (data !== null) {
      setNginxCustomEditing(prev => ({ ...prev, mode: 'full', customContent: prev?.content || '', content: data?.nginx_config || '' }));
    }
  }

  async function saveNginxCustom() {
    if (!nginxCustomEditing) return;
    if (nginxCustomEditing.mode === 'full') return;
    const data = await request(`/websites/${nginxCustomEditing.id}/nginx-custom`, {
      method: 'PUT',
      body: JSON.stringify({ nginx_custom: nginxCustomEditing.content }),
    }, 'Applying Custom Nginx and reloading...');
    if (data) {
      setNotice(`Updated Custom Nginx for ${nginxCustomEditing.domain}`);
      setNginxCustomEditing(null);
      refreshAll();
    }
  }

  async function saveWebsiteSettings() {
    if (!nginxCustomEditing) return;
    const original = nginxCustomEditing.site || {};
    const body = {};
    const nextAppType = websiteSettingsForm.app_type || original.app_type || 'wordpress';
    const nextPhp = websiteSettingsForm.php_version || original.php_version || '8.4';
    const nextRewrite = nextAppType === 'wordpress'
      ? 'front_controller'
      : nextAppType === 'static' || isProxiedAppType(nextAppType)
        ? 'none'
        : websiteSettingsForm.nginx_rewrite_mode || 'none';

    if (isProxiedAppType(nextAppType)) {
      if (siteApps.items.length === 0) {
        setError('Install an application first, on the Applications page.');
        return;
      }
      if (!websiteSettingsForm.app_id) {
        setError('Pick which application this website should serve.');
        return;
      }
      if (String(websiteSettingsForm.app_id) !== String(original.app_id || '')) {
        body.app_id = Number(websiteSettingsForm.app_id);
      }
    }
    if (nextAppType !== (original.app_type || 'wordpress')) body.app_type = nextAppType;
    if (nextAppType !== 'static' && !isProxiedAppType(nextAppType) && nextPhp !== original.php_version) body.php_version = nextPhp;
    if (nextRewrite !== (original.nginx_rewrite_mode || (original.app_type === 'wordpress' ? 'front_controller' : 'none'))) {
      body.nginx_rewrite_mode = nextRewrite;
    }
    if (Object.keys(body).length === 0) return;

    const data = await request(`/websites/${nginxCustomEditing.id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }, `Saving ${nginxCustomEditing.domain} settings...`);
    if (data) {
      setNotice(`Updated settings for ${nginxCustomEditing.domain}.`);
      setWebsiteSettingsForm(websiteConfigForm(data));
      setNginxCustomEditing(prev => prev ? ({ ...prev, site: data }) : prev);
      await refreshAll();
    }
  }

  async function resetNginxDefault() {
    if (!nginxCustomEditing) return;
    if (!confirm(`Clear Custom Nginx for ${nginxCustomEditing.domain}?`)) return;
    const data = await request(`/websites/${nginxCustomEditing.id}/nginx-custom`, {
      method: 'PUT',
      body: JSON.stringify({ nginx_custom: '' }),
    }, 'Clearing Custom Nginx...');
    if (data) {
      setNotice(`Cleared Custom Nginx for ${nginxCustomEditing.domain}.`);
      setNginxCustomEditing(null);
      await refreshAll();
    }
  }

  async function loadWebsiteLog(siteOrId = logViewer?.id, kind = logViewer?.kind || 'access', lines = logViewer?.lines || 200, domainLabel = logViewer?.domain || '') {
    const websiteId = typeof siteOrId === 'object' ? siteOrId.id : siteOrId;
    const domainName = typeof siteOrId === 'object' ? siteOrId.domain : domainLabel;
    if (!websiteId) return;
    const data = await request(`/websites/${websiteId}/logs?kind=${encodeURIComponent(kind)}&lines=${encodeURIComponent(lines)}`, {}, `Loading ${kind} log...`);
    if (data) {
      setLogViewer({
        id: websiteId,
        domain: data.domain || domainName,
        kind: data.kind || kind,
        lines: data.lines || lines,
        path: data.path || '',
        content: data.content || '',
        exists: !!data.exists,
      });
    }
  }

  async function openWebsiteLogs(site) {
    setNginxCustomEditing(null);
    setWordpressInstaller(null);
    setTerminalViewer(null);
    setLogViewer({ id: site.id, domain: site.domain, kind: 'access', lines: 200, path: '', content: '', exists: true });
    await loadWebsiteLog(site, 'access', 200, site.domain);
  }

  function openWebsiteTerminal(site) {
    setNginxCustomEditing(null);
    setWordpressInstaller(null);
    setLogViewer(null);
    setTerminalViewer({ id: site.id, domain: site.domain });
  }

  function openWordPressInstaller(site) {
    setNginxCustomEditing(null);
    setLogViewer(null);
    setTerminalViewer(null);
    setWordpressInstaller({
      website_id: site.id,
      domain: site.domain,
      php_version: site.php_version || phpVersion,
      title: site.domain,
      admin_user: 'admin',
      admin_email: `admin@${site.domain}`,
      admin_password: generateRandomPassword(20),
    });
  }

  async function installWordPressOnSite() {
    if (!wordpressInstaller) return;
    const title = String(wordpressInstaller.title || '').trim() || wordpressInstaller.domain;
    const adminUser = String(wordpressInstaller.admin_user || '').trim();
    const adminEmailValue = String(wordpressInstaller.admin_email || '').trim();
    const adminPasswordValue = String(wordpressInstaller.admin_password || '').trim();
    if (!adminUser || !adminEmailValue || !adminPasswordValue) {
      setError('Please fill all WordPress admin fields.');
      return;
    }
    if (adminPasswordValue.length < 10) {
      setError('WordPress admin password must be at least 10 characters.');
      return;
    }
    const data = await request(`/websites/${wordpressInstaller.website_id}/wordpress`, {
      method: 'POST',
      body: JSON.stringify({
        title,
        admin_user: adminUser,
        admin_email: adminEmailValue,
        admin_password: adminPasswordValue,
      }),
    }, `Installing WordPress for ${wordpressInstaller.domain}...`);
    if (data) {
      setNotice(`Installed WordPress: https://${wordpressInstaller.domain}\nAdmin: ${adminUser} | Password: ${adminPasswordValue}`);
      setWordpressInstaller(null);
      await refreshAll();
    }
  }

  async function runWordPressAction(site, action) {
    const labels = { core: 'core', plugins: 'plugins', themes: 'themes' };
    const label = labels[action] || action;
    const data = await request('/maintenance/wordpress', {
      method: 'POST',
      body: JSON.stringify({ website_id: site.id, action }),
    }, `Updating WordPress ${label}...`);
    if (data?.returncode && data.returncode !== 0) {
      setError(data.stderr || data.stdout || `WordPress ${label} update failed.`);
      return;
    }
    if (data) {
      setNotice(`Updated WordPress ${label} for ${site.domain}.`);
    }
  }

  async function updateWordPressAll(site) {
    if (!site) return;
    setLoading('Updating WordPress...');
    for (const action of ['core', 'plugins', 'themes']) {
      const data = await request('/maintenance/wordpress', {
        method: 'POST',
        body: JSON.stringify({ website_id: site.id, action }),
      });
      if (data?.returncode && data.returncode !== 0) {
        setError(data.stderr || data.stdout || `WordPress ${action} update failed.`);
        setLoading('');
        return;
      }
    }
    setLoading('');
    setNotice(`Updated WordPress core, plugins, and themes for ${site.domain}.`);
  }

  async function toggleWebsiteWaf(site) {
    const next = !site.waf_enabled;
    const data = await request(`/websites/${site.id}/waf`, {
      method: 'PATCH',
      body: JSON.stringify({ waf_enabled: next }),
    }, `${next ? 'Enabling' : 'Disabling'} WAF for ${site.domain}...`);
    if (data) {
      setNotice(`${next ? 'Enabled' : 'Disabled'} WAF for ${site.domain}.`);
      await refreshAll();
      if (String(selectedWafWebsiteId) === String(site.id)) await loadWebsiteWafConfig(site.id, false);
    }
  }

  async function fixWordPressPermissions(id) {
    const data = await request(`/maintenance/wordpress/${id}/fix-permissions`, { method: 'POST' }, 'Fixing permissions...');
    if (data?.message) setNotice(data.message);
  }

  async function fixNginxSecurity(id) {
    const data = await request(`/websites/${id}/fix-nginx-security`, { method: 'POST' }, 'Rewriting Nginx security template...');
    if (data?.message) setNotice(data.message);
  }

  async function changeDbPassword(id) {
    const newPass = prompt('Enter a new database password, minimum 12 characters:');
    if (!newPass) return;
    await request(`/databases/${id}/password`, { method: 'POST', body: JSON.stringify({ password: newPass }) }, 'Changing database password...');
  }

  async function deleteDatabase(id, dbName) {
    if (!confirm(`Delete database "${dbName}"? This action cannot be undone.`)) return;
    const data = await request(`/databases/${id}`, { method: 'DELETE' }, 'Deleting database...');
    if (data) {
      setNotice(`Database "${dbName}" deleted successfully.`);
      await refreshAll();
    }
  }

  function generateRandomPassword(length = 20) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*_+-';
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => chars[b % chars.length]).join('');
  }

  async function createDatabase() {
    const validDbName = /^[a-zA-Z0-9_]+$/;
    const dbName = newDatabase.db_name.trim();
    const dbUser = newDatabase.db_user.trim();
    const dbPass = newDatabase.db_password.trim();
    if (!dbName) { setError('Please enter a database name.'); return; }
    if (!validDbName.test(dbName)) { setError('Database name can only contain letters, numbers and underscores (no spaces or special characters).'); return; }
    if (dbUser && !validDbName.test(dbUser)) { setError('Database user can only contain letters, numbers and underscores (no spaces or special characters).'); return; }
    if (dbPass && dbPass.length < 12) { setError('Password must be at least 12 characters.'); return; }
    if (dbPass && /[^\x20-\x7E]/.test(dbPass)) { setError('Password contains invalid characters. Use only ASCII characters.'); return; }
    const body = {
      db_name: dbName,
      db_user: dbUser || null,
      db_password: dbPass || null,
    };
    const data = await request('/databases', { method: 'POST', body: JSON.stringify(body) }, 'Creating database...');
    if (data) {
      setCreatedDbInfo({ db_name: data.db_name, db_user: data.db_user, db_password: data.db_password });
      setNewDatabase({ db_name: '', db_user: '', db_password: '' });
      await refreshAll();
    }
  }

  async function addCron() {
    const data = await request('/maintenance/cron', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId), schedule: cronSchedule, command: cronCommand }) }, 'Adding cron job...');
    if (data) {
      if (data.cron_user) setCronUser(data.cron_user);
      setNotice(`Cron job added${data.cron_user ? ` as ${data.cron_user}` : ''}.`);
      await listCron();
    }
  }

  async function listCron() {
    if (!selectedWebsiteId) return;
    const data = await request(`/maintenance/cron/${selectedWebsiteId}`, {}, 'Loading cron jobs...');
    if (data?.items) setCronItems(data.items);
    if (data?.cron_user) setCronUser(data.cron_user);
    if (data?.php_binary) setCronPhpInfo({ php_binary: data.php_binary, php_version: data.php_version || '' });
  }

  async function deleteCron(index) {
    if (!confirm(`Delete cron #${index}?`)) return;
    index = Number(index);
    if (Number.isNaN(index)) return;
    const data = await request('/maintenance/cron', { method: 'DELETE', body: JSON.stringify({ website_id: Number(selectedWebsiteId), index }) }, 'Deleting cron job...');
    if (data) {
      if (data.cron_user) setCronUser(data.cron_user);
      setNotice('Cron job deleted.');
      await listCron();
    }
  }

  async function listFiles(path = fileListPath) {
    if (!hasFileTarget()) return;
    const data = await request(`${fileTargetBase()}?path=${encodeURIComponent(path)}`, {}, 'Loading file list...');
    if (data?.items) { setFiles(data.items); setFileListPath(path); setFileUploadDir(path || ''); setSelectedFilePaths([]); }
  }

  async function readFile(pathOverride = filePath) {
    const targetPath = pathOverride || filePath;
    if (!hasFileTarget() || !targetPath) return;
    if (pathOverride) setFilePath(pathOverride);
    const data = await request(`${fileTargetBase()}/read?path=${encodeURIComponent(targetPath)}`, {}, 'Reading file...');
    if (data?.content !== undefined) {
      setFileContent(data.content);
      setEditorCursor({ line: 1, column: 1 });
    }
  }

  async function writeFile() {
    const data = await request('/maintenance/files/write', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: filePath, content: fileContent }) }, 'Saving file...');
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function downloadFile(path) {
    if (!hasFileTarget() || !path) return;
    try {
      setError(''); setLoading('Downloading file...');
      const res = await fetch(`${API}${fileTargetBase()}/download?path=${encodeURIComponent(path)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Download failed.')); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = path.split('/').pop() || 'download';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
    } catch (err) { setError('File download failed.'); }
    finally { setLoading(''); }
  }

  function fileEditorUrl(path) {
    const url = new URL(window.location.href);
    url.pathname = routeForPage('files');
    url.search = '';
    url.hash = '';
    url.searchParams.set('view', 'editor');
    if (fileAppId) url.searchParams.set('app_id', String(fileAppId));
    else url.searchParams.set('website_id', String(selectedWebsiteId));
    url.searchParams.set('path', path);
    return url.toString();
  }

  function openFileEditorTab(path) {
    if (!hasFileTarget() || !path) return;
    window.open(fileEditorUrl(path), '_blank', 'noopener,noreferrer');
  }

  async function makeFileDirectory() {
    if (!hasFileTarget()) return;
    const name = prompt('Folder name:');
    if (!name) return;
    const data = await request('/maintenance/files/mkdir', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: fileListPath || '', name }) }, 'Creating folder...');
    if (data) await listFiles(fileListPath);
  }

  async function makeFile() {
    if (!hasFileTarget()) return;
    const name = prompt('File name:', 'new-file.txt');
    if (!name) return;
    const data = await request('/maintenance/files/create', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: fileListPath || '', name }) }, 'Creating file...');
    if (data) {
      await listFiles(fileListPath);
      const newPath = [fileListPath, name].filter(Boolean).join('/');
      openFileEditorTab(newPath);
    }
  }

  async function renameFileItem(item) {
    if (!item) return;
    const newName = prompt('New name:', item.name);
    if (!newName || newName === item.name) return;
    const data = await request('/maintenance/files/rename', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: item.path, new_name: newName }) }, 'Renaming...');
    if (data) await listFiles(fileListPath);
  }

  function openChmodDialog(items) {
    const targets = (Array.isArray(items) ? items : [items]).filter(Boolean);
    if (targets.length === 0) return;
    setChmodTarget(targets);
    if (targets.length === 1 && normalizeOctalMode(targets[0].mode)) {
      setChmodMode(normalizeOctalMode(targets[0].mode));
      return;
    }
    // With a mixed selection, keep the special bits only when every target
    // already agrees on them, so a bulk chmod never silently drops setgid.
    const specials = targets.map(item => octalToPermissionBits(item.mode).special);
    const special = specials.every(value => value === specials[0]) ? specials[0] : 0;
    const base = targets.every(item => item.is_dir)
      ? { owner: 7, group: 5, other: 5 }
      : { special: 0, owner: 6, group: 4, other: 4 };
    setChmodMode(permissionBitsToOctal({ special, ...base }));
  }

  async function applyChmod() {
    const targets = chmodTarget || [];
    const mode = chmodMode.trim();
    if (targets.length === 0) return;
    if (!/^[0-7]{3,4}$/.test(mode)) { setError('Mode must be octal, for example 644 or 755.'); return; }
    for (const item of targets) {
      const data = await request('/maintenance/files/chmod', {
        method: 'POST',
        body: JSON.stringify({ ...fileTargetBody(), path: item.path, mode }),
      }, `Setting permissions on ${item.name}...`);
      // request() already surfaced the reason; stop so the dialog keeps the mode.
      if (!data) return;
    }
    setChmodTarget(null);
    setNotice(`Permissions set to ${mode} on ${targets.length} item(s).`);
    await listFiles(fileListPath);
  }

  async function deleteSelectedFiles() {
    if (selectedFilePaths.length === 0) return;
    if (!confirm(`Delete ${selectedFilePaths.length} selected item(s)?`)) return;
    const data = await request('/maintenance/files/delete', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), paths: selectedFilePaths }) }, 'Deleting selected files...');
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function transferFileItems(action, paths) {
    if (!hasFileTarget() || !paths?.length) return;
    const verb = action === 'copy' ? 'Copy' : 'Move';
    const destination = prompt(`${verb} to folder:`, fileListPath || 'public_html');
    if (destination === null) return;
    const targetPath = destination.trim() || fileListPath || 'public_html';
    const data = await request(`/maintenance/files/${action}`, {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), paths, destination_path: targetPath }),
    }, `${verb}ing files...`);
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function copySelectedFiles() {
    await transferFileItems('copy', selectedFilePaths);
  }

  async function moveSelectedFiles() {
    await transferFileItems('move', selectedFilePaths);
  }

  async function archiveSelectedFiles() {
    if (selectedFilePaths.length === 0) return;
    const ext = archiveFormat === 'tar.gz' ? 'tar.gz' : 'zip';
    const outputName = prompt('Archive file name:', `archive-${Date.now()}.${ext}`);
    if (!outputName) return;
    const data = await request('/maintenance/files/archive', {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), base_path: fileListPath || '', paths: selectedFilePaths, output_name: outputName, format: archiveFormat }),
    }, 'Creating archive...');
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function extractArchiveFile(path) {
    if (!hasFileTarget() || !path) return;
    const destination = prompt('Extract to folder:', fileListPath || '.');
    if (destination === null) return;
    const targetPath = destination.trim() || fileListPath || '.';
    const data = await request('/maintenance/files/extract', {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), archive_path: path, destination_path: targetPath }),
    }, 'Starting extraction...');
    if (data?.job_id) upsertFileJob(data);
    else if (data) { await listFiles(targetPath === '.' ? '' : targetPath); await loadCurrentUser(); }
  }

  function upsertFileJob(job) {
    if (!job?.job_id) return;
    setFileJobs(prev => [job, ...prev.filter(item => item.job_id !== job.job_id)].slice(0, 6));
  }

  function dismissFileJob(jobId) {
    setFileJobs(prev => prev.filter(item => item.job_id !== jobId));
  }

  async function loadFileJob(jobId) {
    try {
      const res = await fetch(`${API}/maintenance/files/jobs/${jobId}`, { credentials: 'include' });
      const text = await res.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text || `HTTP ${res.status}` }; }
      if (!res.ok && handleAuthExpired(res.status, data.detail)) return null;
      if (!res.ok) return null;
      return data;
    } catch {
      return null;
    }
  }

  async function loadFileJobs() {
    const data = await request('/maintenance/files/jobs');
    if (data?.jobs) setFileJobs(data.jobs.filter(job => job.status !== 'done').slice(0, 6));
  }

  useEffect(() => {
    const activeJobs = fileJobs.filter(job => ['queued', 'running'].includes(job.status));
    if (activeJobs.length === 0) return undefined;

    const poll = async () => {
      for (const job of activeJobs) {
        const data = await loadFileJob(job.job_id);
        if (!data) continue;
        if (data.status === 'done') {
          // Drop the card rather than parking it on "completed" forever; the
          // notice and the refreshed listing are the confirmation.
          dismissFileJob(job.job_id);
          setNotice(data.message || 'Extraction completed');
          await listFiles(data.destination_path || fileListPath);
          await loadCurrentUser();
          continue;
        }
        upsertFileJob(data);
        if (data.status === 'error') {
          setError(formatApiError(data.error, 'Extraction failed'));
        }
      }
    };

    const timer = window.setInterval(poll, 3000);
    return () => window.clearInterval(timer);
  }, [fileJobs]);

  useEffect(() => {
    if (page === 'files' && hasFileTarget()) loadFileJobs();
  }, [page, selectedWebsiteId, fileAppId]);

  async function openWebsiteFileManager(site) {
    setNginxCustomEditing(null);
    setWordpressInstaller(null);
    setLogViewer(null);
    setTerminalViewer(null);
    setFileAppId('');
    setSelectedWebsiteId(String(site.id));
    navigateToPage('files');
    setFileListPath('public_html');
    setFileUploadDir('public_html');
    setFiles([]);
    setSelectedFilePaths([]);
  }

  function openAppFileManager(app) {
    setNginxCustomEditing(null);
    setLogViewer(null);
    setTerminalViewer(null);
    setFileAppId(String(app.id));
    // An app root has no public_html; the listing effect picks it up from here.
    setFileListPath('');
    setFileUploadDir('');
    setFiles([]);
    setSelectedFilePaths([]);
    navigateToPage('files');
  }

  async function uploadSiteFile(file) {
    if (!file) return;
    if (!hasFileTarget()) { setError('Please select a website or application first.'); return; }
    const uploadDir = fileUploadDir.trim();
    const form = new FormData();
    form.append('file', file);
    try {
      setError('');
      setLoading('Uploading file...');
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}${fileTargetBase()}/upload?path=${encodeURIComponent(uploadDir)}`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      });
      const responseText = await res.text();
      let data;
      try { data = responseText ? JSON.parse(responseText) : {}; } catch { data = { detail: responseText || `HTTP ${res.status}` }; }
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Upload failed.')); return; }
      setNotice(`Uploaded ${file.name} to ${uploadDir || 'site root'}.`);
      if (String(fileListPath || '') === uploadDir) await listFiles(uploadDir);
      await loadCurrentUser();
    } catch (err) { setError('File upload failed.'); }
    finally { setLoading(''); }
  }

  async function createBackup() {
    const data = await request('/maintenance/backup', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId) }) }, 'Queueing backup...');
    if (data?.job_id) { setNotice('Backup queued. It will keep running on the server.'); await loadBackupJobs(); }
    else if (data?.backup_file) { setNotice(`Created backup: ${data.backup_file}`); await listBackups(); }
  }

  async function listBackups() {
    const data = await request(`/maintenance/backups/${selectedWebsiteId}`);
    if (data?.items) setBackups(data.items);
  }

  async function loadBackupJobs() {
    const data = await request('/maintenance/backup-jobs');
    if (data?.jobs) {
      const visibleJobs = data.jobs.filter(job => job.status !== 'done');
      const hasActive = data.jobs.some(job => ['queued', 'running'].includes(job.status));
      setBackupJobs(prev => {
        const hadActive = prev.some(job => ['queued', 'running'].includes(job.status));
        if (hadActive && !hasActive) {
          setTimeout(() => {
            if (selectedWebsiteId) listBackups();
            if (selectedBackupUserId) listUserBackups(selectedBackupUserId);
          }, 0);
        }
        return visibleJobs;
      });
    }
  }

  async function refreshBackupArea() {
    await listBackups();
    await loadBackupJobs();
    if (selectedBackupUserId) await listUserBackups(selectedBackupUserId);
  }

  async function refreshUserBackupArea() {
    await loadUsers();
    await loadRestoreBackups();
    await loadBackupJobs();
    if (selectedBackupUserId) await listUserBackups(selectedBackupUserId);
  }

  async function refreshScheduledBackupArea() {
    await loadUsers();
    await loadSftpTargets();
    await loadBackupSchedules();
    await loadBackupJobs();
  }

  async function listUserBackups(userId = selectedBackupUserId) {
    if (!userId) return;
    const data = await request(`/maintenance/user-backups/${userId}`);
    if (data?.items) setUserBackups(data.items);
  }

  async function createUserBackup() {
    if (!selectedBackupUserId) return;
    const body = {
      user_id: Number(selectedBackupUserId),
      target_id: selectedSftpTargetId ? Number(selectedSftpTargetId) : null,
    };
    const data = await request('/maintenance/user-backup', { method: 'POST', body: JSON.stringify(body) }, 'Queueing full user backup...');
    if (data?.job_id) { setNotice('Full user backup queued. It will keep running on the server.'); await loadBackupJobs(); }
    else if (data?.backup_file) {
      setNotice(data.remote_file ? `Full user backup uploaded: ${data.remote_file}` : `Created full user backup: ${data.backup_file}`);
      await listUserBackups();
    }
  }

  async function loadBackupSchedules() {
    const data = await request('/maintenance/backup-schedules');
    if (data) setBackupSchedules(data);
  }

  async function loadRestoreBackups() {
    const data = await request('/maintenance/user-restore-backups');
    if (data?.items) setRestoreBackups(data.items);
    if (data?.directory) setRestoreBackupDir(data.directory);
  }

  async function createBackupSchedule() {
    const selectedUserIds = (newBackupSchedule.user_ids || []).map(Number).filter(Boolean);
    if (!newBackupSchedule.all_users && selectedUserIds.length === 0) return;
    const body = {
      user_id: selectedUserIds[0] || null,
      user_ids: newBackupSchedule.all_users ? [] : selectedUserIds,
      all_users: !!newBackupSchedule.all_users,
      schedule: newBackupSchedule.schedule,
      target_id: newBackupSchedule.target_id ? Number(newBackupSchedule.target_id) : null,
      retention: Number(newBackupSchedule.retention || 7),
      is_active: true,
    };
    const data = await request('/maintenance/backup-schedules', { method: 'POST', body: JSON.stringify(body) }, 'Saving backup schedule...');
    if (data) {
      setNotice('Backup schedule saved.');
      await loadBackupSchedules();
    }
  }

  async function deleteBackupSchedule(id) {
    if (!confirm('Delete this backup schedule?')) return;
    const data = await request(`/maintenance/backup-schedules/${id}`, { method: 'DELETE' }, 'Deleting backup schedule...');
    if (data) await loadBackupSchedules();
  }

  async function loadSftpTargets() {
    const data = await request('/maintenance/sftp-targets');
    if (data) {
      setSftpTargets(data);
      if (!selectedSftpTargetId && data[0]) setSelectedSftpTargetId(String(data[0].id));
    }
  }

  async function createSftpTarget() {
    const body = {
      ...newSftpTarget,
      port: Number(newSftpTarget.port || 22),
      password: newSftpTarget.password || null,
      private_key: newSftpTarget.private_key || null,
    };
    const data = await request('/maintenance/sftp-targets', { method: 'POST', body: JSON.stringify(body) }, 'Saving SFTP target...');
    if (data) {
      setNotice(`Saved SFTP target ${data.name}`);
      setNewSftpTarget({ name: '', host: '', port: 22, username: '', password: '', private_key: '', remote_path: '/backups/snpanel' });
      await loadSftpTargets();
    }
  }

  async function deleteSftpTarget(id) {
    if (!confirm('Delete this SFTP target?')) return;
    const data = await request(`/maintenance/sftp-targets/${id}`, { method: 'DELETE' }, 'Deleting SFTP target...');
    if (data) await loadSftpTargets();
  }

  async function createSftpBackup() {
    if (!selectedWebsiteId || !selectedSftpTargetId) return;
    const data = await request('/maintenance/backup-sftp', {
      method: 'POST',
      body: JSON.stringify({ website_id: Number(selectedWebsiteId), target_id: Number(selectedSftpTargetId) }),
    }, 'Queueing SFTP backup...');
    if (data?.job_id) {
      setNotice('SFTP backup queued. It will keep running on the server.');
      await loadBackupJobs();
    } else if (data?.remote_file) {
      setNotice(`SFTP backup uploaded: ${data.remote_file}`);
      await listBackups();
    }
  }

  async function restoreBackup(file) {
    if (!confirm(`Restore this backup to the current website?\n${file}`)) return;
    await request('/maintenance/restore', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId), backup_file: file }) }, 'Restoring backup...');
  }

  async function downloadBackup(file) {
    if (!selectedWebsiteId) return;
    try {
      setError(''); setLoading('Downloading backup...');
      const res = await fetch(`${API}/maintenance/backups/${selectedWebsiteId}/download?backup_file=${encodeURIComponent(file)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Download failed.')); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = file.split('/').pop() || 'backup.tar.gz';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice('Backup downloaded.');
    } catch (err) { setError('Backup download failed.'); }
    finally { setLoading(''); }
  }

  async function downloadUserBackup(file) {
    try {
      setError(''); setLoading('Downloading full user backup...');
      const res = await fetch(`${API}/maintenance/user-backups-download?backup_file=${encodeURIComponent(file)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Download failed.')); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = file.split('/').pop() || 'user-backup.tar.gz';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice('Full user backup downloaded.');
    } catch (err) { setError('Full user backup download failed.'); }
    finally { setLoading(''); }
  }

  async function restoreUserBackup(file) {
    if (!confirm(`Restore this full user backup? Missing panel user and websites will be created.\n${file}`)) return;
    const data = await request('/maintenance/user-restore', { method: 'POST', body: JSON.stringify({ backup_file: file }) }, 'Restoring full user backup...');
    if (data) {
      setNotice(`Restored user ${data.username}. Websites: ${data.websites?.length || 0}`);
      await refreshAll();
      await loadUsers();
      await listUserBackups();
      await loadRestoreBackups();
    }
  }

  async function deleteUserBackup(file) {
    if (!confirm(`Delete this full user backup?\n${file}`)) return;
    const data = await request(`/maintenance/user-backups?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, 'Deleting full user backup...');
    if (data) {
      await listUserBackups();
      await loadRestoreBackups();
    }
  }

  async function deleteRestoreBackup(file) {
    if (!confirm(`Delete this restore backup?\n${file}`)) return;
    const data = await request(`/maintenance/user-restore-backups?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, 'Deleting restore backup...');
    if (data) {
      await loadRestoreBackups();
      await listUserBackups();
    }
  }

  async function uploadUserBackups(files) {
    const selectedFiles = Array.from(files || []);
    if (selectedFiles.length === 0) return;
    const form = new FormData();
    selectedFiles.forEach(file => form.append('files', file));
    try {
      setError(''); setLoading('Uploading full user backups...');
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/maintenance/user-restore-backups/upload`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      });
      const responseText = await res.text();
      let data;
      try { data = responseText ? JSON.parse(responseText) : {}; } catch { data = { detail: responseText || `HTTP ${res.status}` }; }
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Upload failed.')); return; }
      setNotice(`Uploaded ${data.items?.length || selectedFiles.length} full user backup file(s).`);
      await loadRestoreBackups();
      await listUserBackups();
    } catch (err) { setError('Full user backup upload failed.'); }
    finally { setLoading(''); }
  }

  // --- DirectAdmin Import ---
  async function listDaBackups() {
    const data = await request('/maintenance/da-import/backups');
    if (data) setDaBackups(Array.isArray(data) ? data : []);
  }

  async function uploadDaBackup(file) {
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    try {
      setError(''); setLoading('Uploading DA backup...');
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/maintenance/da-import/upload`, {
        method: 'POST', credentials: 'include', headers, body: form,
      });
      const text = await res.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text || `HTTP ${res.status}` }; }
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Upload failed.')); return; }
      setNotice(`Uploaded: ${data.filename}`);
      await listDaBackups();
    } catch (err) { setError('DA backup upload failed.'); }
    finally { setLoading(''); }
  }

  async function scanDaBackup(archivePath) {
    setDaScanResult(null);
    const data = await request('/maintenance/da-import/scan', { method: 'POST', body: JSON.stringify({ archive_path: archivePath }) }, 'Scanning DA backup...');
    if (data) setDaScanResult(data);
  }

  async function importDaBackup(archivePath, force = daReplaceExisting) {
    const message = force
      ? 'Import and REPLACE? Any existing panel user, website, files and databases with the same names are deleted first.'
      : 'Import this DirectAdmin backup? This will create users, websites, databases, and nginx configs.';
    if (!confirm(message)) return;
    setDaImportJob(null);
    const data = await request('/maintenance/da-import/import', { method: 'POST', body: JSON.stringify({ archive_path: archivePath, force }) }, 'Starting DA import...');
    if (data?.job_id) {
      setNotice('DA import started. Polling for result...');
      setDaImportJob(data);
      pollDaImportJob(data.job_id);
    }
  }

  async function pollDaImportJob(jobId) {
    let attempts = 0;
    const maxAttempts = 360;
    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      const data = await request(`/maintenance/da-import/jobs/${jobId}`, { silent: true });
      if (!data) { attempts++; continue; }
      setDaImportJob(data);
      if (data.status === 'completed') { setNotice('DA import completed successfully!'); await listDaBackups(); return; }
      if (data.status === 'failed') { setError(`DA import failed: ${data.error || 'Unknown error'}`); return; }
      attempts++;
    }
  }

  async function deleteDaBackup(archivePath) {
    if (!confirm('Delete this DA backup file?')) return;
    const data = await request('/maintenance/da-import/backups', { method: 'DELETE', body: JSON.stringify({ archive_path: archivePath }) }, 'Deleting DA backup...');
    if (data) { setNotice(`Deleted: ${data.deleted}`); setDaScanResult(null); await listDaBackups(); }
  }

  function toggleDaBackupSelect(path) {
    setSelectedDaBackups(prev => prev.includes(path) ? prev.filter(p => p !== path) : [...prev, path]);
  }

  function toggleSelectAllDaBackups() {
    setSelectedDaBackups(prev => prev.length === daBackups.length ? [] : daBackups.map(f => f.path));
  }

  async function bulkImportDaBackups(force = daReplaceExisting) {
    if (selectedDaBackups.length === 0) return;
    const message = force
      ? `Restore and REPLACE ${selectedDaBackups.length} backup(s)? Existing users, websites, files and databases with the same names are deleted first.`
      : `Restore ${selectedDaBackups.length} backup(s)? This will create users, websites, databases, and nginx configs for each.`;
    if (!confirm(message)) return;
    setDaBulkImportJob(null);
    setDaImportJob(null);
    setDaScanResult(null);
    const data = await request('/maintenance/da-import/bulk-import', { method: 'POST', body: JSON.stringify({ archive_paths: selectedDaBackups, force }) }, 'Starting bulk restore...');
    if (data?.job_id) {
      setNotice(`Bulk restore started: ${data.total} backup(s). Processing sequentially...`);
      setSelectedDaBackups([]);
      pollDaBulkImportJob(data.job_id);
    }
  }

  async function pollDaBulkImportJob(jobId) {
    let attempts = 0;
    const maxAttempts = 720;
    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      const data = await request(`/maintenance/da-import/bulk-jobs/${jobId}`, { silent: true });
      if (!data) { attempts++; continue; }
      setDaBulkImportJob(data);
      if (data.status === 'completed') {
        const ok = (data.results || []).filter(r => r.status === 'completed').length;
        const fail = (data.results || []).filter(r => r.status === 'failed').length;
        setNotice(`Bulk restore done: ${ok} succeeded, ${fail} failed.`);
        await listDaBackups();
        return;
      }
      attempts++;
    }
  }

  async function bulkDeleteDaBackups() {
    if (selectedDaBackups.length === 0) return;
    if (!confirm(`Delete ${selectedDaBackups.length} selected backup file(s)?`)) return;
    for (const path of selectedDaBackups) {
      await request('/maintenance/da-import/backups', { method: 'DELETE', body: JSON.stringify({ archive_path: path }) }, 'Deleting...');
    }
    setNotice(`Deleted ${selectedDaBackups.length} backup(s).`);
    setSelectedDaBackups([]);
    setDaScanResult(null);
    await listDaBackups();
  }

  async function openPhpMyAdmin(databaseId) {
    try {
      setError(''); setLoading('Opening phpMyAdmin...');
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/databases/${databaseId}/phpmyadmin-sso`, {
        method: 'POST',
        credentials: 'include',
        headers,
      });
      const data = await res.json().catch(() => ({}));
      if (handleAuthExpired(res.status, data.detail)) return;
      if (!res.ok || !data.url) { setError(formatApiError(data.detail, 'Cannot open phpMyAdmin.')); return; }
      window.open(data.url, '_blank', 'noopener,noreferrer');
    } catch (err) { setError('Cannot open phpMyAdmin.'); }
    finally { setLoading(''); }
  }

  async function downloadDatabase(databaseId, databaseName) {
    try {
      setError(''); setLoading('Downloading database...');
      const res = await fetch(`${API}/databases/${databaseId}/download`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Download failed.')); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `${databaseName || 'database'}.sql`;
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice('Database SQL downloaded.');
    } catch (err) { setError('Database download failed.'); }
    finally { setLoading(''); }
  }

  async function deleteBackup(file) {
    if (!confirm(`Delete this backup?\n${file}`)) return;
    const data = await request(`/maintenance/backups/${selectedWebsiteId}?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, 'Deleting backup...');
    if (data) await listBackups();
  }

  async function uploadBackup(file) {
    if (!file || !selectedWebsiteId) return;
    const form = new FormData();
    form.append('file', file);
    try {
      setError(''); setLoading('Uploading backup...');
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/maintenance/backups/${selectedWebsiteId}/upload`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      });
      const responseText = await res.text();
      let data;
      try { data = responseText ? JSON.parse(responseText) : {}; } catch { data = { detail: responseText || `HTTP ${res.status}` }; }
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, 'Upload failed.')); return; }
      if (data.backup_file) { setNotice(`Uploaded backup: ${data.backup_file}`); await listBackups(); }
    } catch (err) { setError('Upload backup failed.'); }
    finally { setLoading(''); }
  }

  async function checkService(name) {
    const data = await request('/services/action', { method: 'POST', body: JSON.stringify({ name, action: 'status' }) });
    setServiceStates(prev => ({ ...prev, [name]: data || { stdout: '', stderr: error || 'Cannot check', returncode: 1 } }));
    return data;
  }

  async function loadServiceNames() {
    const data = await request('/services/list');
    const names = data?.services?.length ? data.services : serviceNames;
    setServiceNames(names);
    return names;
  }

  async function checkAllServices() {
    setLoading('Checking services...');
    const names = await loadServiceNames();
    for (const name of names) { await checkService(name); }
    setLoading('');
  }

  async function runServiceAction(name, action) {
    await request('/services/action', { method: 'POST', body: JSON.stringify({ name, action }) }, `${action} ${name}...`);
    await checkService(name);
  }

  async function loadPhpTune(version) {
    const data = await request(`/maintenance/php-tune?php_version=${encodeURIComponent(version)}`, { silent: true });
    setPhpTune(data || null);
    setPhpTuneApplied(false);
  }

  async function toggleOpcache() {
    const version = phpTune?.php_version || phpConfig.php_version;
    const next = !phpTune?.opcache_enabled;
    const data = await request('/maintenance/php-opcache', {
      method: 'POST',
      body: JSON.stringify({ php_version: version, enabled: next }),
    }, next ? `Đang bật OPcache cho PHP ${version}...` : `Đang tắt OPcache cho PHP ${version}...`);
    if (data) {
      setNotice(data.message || 'Đã đổi OPcache.');
      await loadPhpTune(version);
    }
  }

  async function applyPhpTune() {
    const version = phpTune?.php_version || phpConfig.php_version;
    const data = await request('/maintenance/php-tune', {
      method: 'POST',
      body: JSON.stringify({ php_version: version }),
    }, 'Đang tối ưu PHP theo cấu hình máy...');
    if (data) {
      if (data.plan) setPhpTune(data.plan);
      setPhpTuneApplied(true);
      await loadPhpConfig(version);
    }
  }

  async function loadPhpConfig(version = phpConfig.php_version) {
    const data = await request(`/maintenance/php-config?php_version=${encodeURIComponent(version)}`, {}, 'Loading PHP config...');
    if (data) setPhpConfig(prev => ({ ...prev, ...data, php_version: version }));
  }

  async function updatePhpConfig() {
    const data = await request('/maintenance/php-config', {
      method: 'POST',
      body: JSON.stringify({ ...phpConfig, max_execution_time: Number(phpConfig.max_execution_time), max_input_time: Number(phpConfig.max_input_time), max_input_vars: Number(phpConfig.max_input_vars) }),
    }, 'Updating PHP config...');
    if (data?.target) { setNotice(`Updated PHP config: ${data.target}`); await loadPhpConfig(phpConfig.php_version); }
  }

  async function restorePhpDefaults() {
    if (!confirm(`Restore default PHP ${phpConfig.php_version} values?`)) return;
    const data = await request('/maintenance/php-config/defaults', {
      method: 'POST',
      body: JSON.stringify({ php_version: phpConfig.php_version }),
    }, 'Restoring PHP defaults...');
    if (data?.values) {
      setPhpConfig(prev => ({ ...prev, ...data.values }));
      setNotice(`Restored PHP ${phpConfig.php_version} defaults.`);
    }
  }

  async function loadPhpVersions() {
    const data = await request('/maintenance/php-versions', {}, 'Loading PHP versions...');
    if (data) setPhpVersions({
      installed: sortPhpVersions(data.installed || []),
      supported: sortPhpVersions(data.supported || []),
    });
  }

  async function installPhpVersion(version) {
    if (!confirm(`Install PHP ${version}? This will install php${version}-fpm via apt.`)) return;
    const data = await request(`/maintenance/php-versions/${version}/install`, { method: 'POST' }, `Installing PHP ${version}...`);
    if (data) { setNotice(`PHP ${version} installed successfully.`); await loadPhpVersions(); await loadServiceNames(); }
  }

  async function loadFirewall() {
    const data = await request('/firewall/status', {}, 'Loading firewall...');
    if (data) setFirewallStatus(data);
  }

  async function runFirewallAction(path, options = {}, label = 'Updating firewall...') {
    const data = await request(path, options, label);
    if (data) { setNotice((data.stdout || data.stderr || 'Firewall updated.').trim()); await loadFirewall(); }
  }

  async function enableFirewall() {
    if (!confirm('Enable the firewall now? SSH, the panel port and 80/443/465/587 stay open automatically.')) return;
    await runFirewallAction('/firewall/enable', { method: 'POST' }, 'Enabling firewall...');
  }
  async function disableFirewall() {
    if (!confirm('Disable the firewall? Every port will be reachable again.')) return;
    await runFirewallAction('/firewall/disable', { method: 'POST' }, 'Disabling firewall...');
  }
  async function reloadFirewall() { await runFirewallAction('/firewall/reload', { method: 'POST' }, 'Reloading firewall...'); }
  async function openFirewallPort() { await runFirewallAction('/firewall/allow-port', { method: 'POST', body: JSON.stringify({ port: firewallPort, protocol: firewallProtocol }) }, 'Opening port...'); }
  async function allowFirewallIp() { await runFirewallAction('/firewall/allow-ip', { method: 'POST', body: JSON.stringify({ ip: firewallAllowIp, port: firewallAllowPort || null, protocol: firewallAllowProtocol }) }, 'Allowing IP...'); }
  async function blockFirewallIp() {
    if (!confirm(`Block ${firewallBlockIp || 'this IP'}?`)) return;
    await runFirewallAction('/firewall/block-ip', { method: 'POST', body: JSON.stringify({ ip: firewallBlockIp, port: firewallBlockPort || null, protocol: firewallBlockProtocol }) }, 'Blocking IP...');
  }
  async function deleteFirewallRule(numberOverride = firewallDeleteNumber) {
    const ruleNumber = String(numberOverride || '').trim();
    if (!ruleNumber) return;
    if (!confirm(`Delete firewall rule #${ruleNumber}?`)) return;
    await runFirewallAction(`/firewall/rules/${encodeURIComponent(ruleNumber)}`, { method: 'DELETE' }, 'Deleting rule...');
    setFirewallDeleteNumber('');
  }

  function parseFirewallBlocklistUrls(text) {
    const lines = String(text || '').split('\n');
    const urls = [];
    let inUrls = false;
    for (const raw of lines) {
      const line = raw.trim();
      if (line === 'URLs:') { inUrls = true; continue; }
      if (line === 'Networks:' || line === 'Timer:') break;
      if (inUrls && /^https?:\/\//i.test(line)) urls.push(line);
    }
    return urls;
  }

  async function loadFirewallBlocklists() {
    const data = await request('/firewall/blocklists', {}, 'Loading IP blocklists...');
    if (data) setFirewallBlocklists(data);
  }

  async function addFirewallBlocklistUrl() {
    const url = firewallBlocklistUrl.trim();
    if (!url) return;
    const data = await request('/firewall/blocklists', { method: 'POST', body: JSON.stringify({ url }) }, 'Adding IP blocklist URL...');
    if (data) {
      setNotice((data.stdout || data.stderr || 'IP blocklist URL added.').trim());
      setFirewallBlocklistUrl('');
      await loadFirewallBlocklists();
    }
  }

  async function deleteFirewallBlocklistUrl(url) {
    if (!confirm(`Delete blocklist URL?\n${url}`)) return;
    const data = await request('/firewall/blocklists/delete', { method: 'POST', body: JSON.stringify({ url }) }, 'Deleting IP blocklist URL...');
    if (data) {
      setNotice((data.stdout || data.stderr || 'IP blocklist URL removed.').trim());
      await loadFirewallBlocklists();
    }
  }

  async function updateFirewallBlocklistsNow() {
    const data = await request('/firewall/blocklists/update', { method: 'POST' }, 'Refreshing IP blocklists...');
    if (data) {
      setNotice((data.stdout || data.stderr || 'IP blocklists refreshed.').trim());
      await loadFirewall();
      await loadFirewallBlocklists();
    }
  }

  async function loadWafRules() {
    const data = await request('/waf/rules', {}, 'Loading WAF rules...');
    if (data) {
      setWafRules(data);
      const firstWebsiteId = selectedWafWebsiteId || selectedWebsiteId || websites[0]?.id || '';
      if (firstWebsiteId) {
        setSelectedWafWebsiteId(String(firstWebsiteId));
        await loadWebsiteWafConfig(firstWebsiteId, false);
      }
    }
  }

  async function loadWebsiteWafConfig(websiteId = selectedWafWebsiteId, showLoading = true) {
    if (!websiteId) {
      setWafSiteConfig(null);
      setHttpFloodForm({ http_flood_enabled: false, ...HTTP_FLOOD_DEFAULTS });
      return;
    }
    const data = await request(`/waf/websites/${websiteId}`, {}, showLoading ? 'Loading website WAF...' : '');
    if (data) {
      setSelectedWafWebsiteId(String(websiteId));
      setWafSiteConfig(data);
      setWafCustomRules(data.custom_rules || '');
      setHttpFloodForm({ http_flood_enabled: !!data.http_flood_enabled, ...normalizeHttpFloodConfig(data.http_flood_config) });
      setSiteBotText((data.blocked_bots || []).join('\n'));
    }
  }

  async function openWafSite(websiteId) {
    await loadWebsiteWafConfig(websiteId);
    navigateToPage('waf-site');
  }

  async function saveSiteBots() {
    if (!selectedWafWebsiteId) return;
    const data = await request(`/waf/websites/${selectedWafWebsiteId}/bots`, {
      method: 'PUT',
      body: JSON.stringify({ blocked_bots: siteBotText }),
    }, 'Saving blocked bots...');
    if (data) {
      setSiteBotText((data.blocked_bots || []).join('\n'));
      setNotice(data.message || 'Blocked bots saved.');
      await loadBotBlocks();
    }
  }

  function toggleWafDefaultRule(ruleId, enabled) {
    setWafSiteConfig(prev => {
      if (!prev) return prev;
      const current = new Set(prev.enabled_rule_ids || []);
      if (enabled) current.add(ruleId); else current.delete(ruleId);
      return {
        ...prev,
        enabled_rule_ids: Array.from(current),
        default_rules: (prev.default_rules || []).map(rule => rule.id === ruleId ? { ...rule, enabled } : rule),
      };
    });
  }

  async function loadBotBlocks() {
    const data = await request('/waf/bots', {}, 'Loading blocked bots...');
    if (data) {
      setBotBlocks(data);
      setGlobalBots(data.global_blocked_bots || []);
    }
  }

  async function saveGlobalBots(nextList) {
    const data = await request('/waf/bots/global', {
      method: 'PUT',
      body: JSON.stringify({ blocked_bots: nextList.join('\n') }),
    }, 'Saving global bad bots...');
    if (data) {
      setGlobalBots(data.global_blocked_bots || []);
      setNotice(data.failed?.length
        ? `${data.message} Failed: ${data.failed.map(f => `${f.domain} (${f.error})`).join('; ')}`
        : (data.message || 'Global bad bots saved.'));
      await loadBotBlocks();
    }
  }

  async function loadCrs() {
    const data = await request('/waf/crs', { silent: true });
    if (data) setCrs(data);
  }

  async function saveCrsMode(mode) {
    if (mode === 'block' && !confirm(
      'Switch OWASP CRS to blocking?\n\n'
      + 'Every website with the WAF on will start refusing requests that score above the threshold. '
      + 'Run detect mode first and read the logs, or a legitimate request somebody depends on may be the one it stops.'
    )) return;
    const data = await request('/waf/crs', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }, `Switching OWASP CRS to ${mode}...`);
    if (data) await loadCrs();
  }

  async function toggleSiteCrs(row) {
    const turningOn = !row.crs_enabled;
    if (turningOn && !confirm(
      `Load OWASP CRS on ${row.domain}?\n\n`
      + `This adds roughly ${crs?.rss_mb_per_site || 50} MB to nginx for this site. `
      + 'Check the measured figure on this page afterwards rather than trusting the estimate.'
    )) return;
    const data = await request(`/waf/websites/${row.website_id}/crs`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: turningOn }),
    }, `${turningOn ? 'Enabling' : 'Disabling'} CRS on ${row.domain}...`);
    if (data) {
      await loadCrs();
      // The site page reads its own copy of this, so refresh it when that is
      // where the toggle was pressed.
      if (String(selectedWafWebsiteId) === String(row.website_id)) {
        await loadWebsiteWafConfig(row.website_id, false);
      }
    }
  }

  function addGlobalBots(text) {
    const incoming = String(text || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    if (incoming.length === 0) return;
    const seen = new Set(globalBots.map(s => s.toLowerCase()));
    const merged = [...globalBots];
    for (const name of incoming) {
      if (!seen.has(name.toLowerCase())) { seen.add(name.toLowerCase()); merged.push(name); }
    }
    setGlobalBots(merged);
  }

  async function saveWebsiteWafRules() {
    if (!selectedWafWebsiteId || !wafSiteConfig) return;
    const data = await request(`/waf/websites/${selectedWafWebsiteId}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled_rule_ids: wafSiteConfig.enabled_rule_ids || [], custom_rules: wafCustomRules }),
    }, 'Saving website WAF rules...');
    if (data) {
      setWafSiteConfig(data);
      setWafCustomRules(data.custom_rules || '');
      setNotice(data.message || 'Website WAF rules saved.');
      await refreshAll();
    }
  }

  async function saveWebsiteHttpFlood() {
    if (!selectedWafWebsiteId || !wafSiteConfig) return;
    const config = normalizeHttpFloodConfig(httpFloodForm);
    const data = await request(`/websites/${selectedWafWebsiteId}/http-flood`, {
      method: 'PATCH',
      body: JSON.stringify({ http_flood_enabled: !!httpFloodForm.http_flood_enabled, ...config }),
    }, 'Saving HTTP Flood settings...');
    if (data) {
      setNotice(`HTTP Flood settings saved for ${data.domain}.`);
      await refreshAll();
      await loadWebsiteWafConfig(selectedWafWebsiteId, false);
    }
  }

  async function loadWafAccessLogs(filters = wafAccessLogFilters, showLoading = true) {
    const params = new URLSearchParams();
    if (filters.websiteId) params.set('website_id', filters.websiteId);
    params.set('verdict', filters.verdict || 'all');
    params.set('limit', String(filters.limit || 50));
    params.set('lines', '5000');
    if (filters.query?.trim()) params.set('q', filters.query.trim());
    const data = await request(`/waf/access-logs?${params.toString()}`, {}, showLoading ? 'Loading access logs...' : '');
    if (data) setWafAccessLogs(data);
  }

  async function applyWafAccessLogFilters() {
    await loadWafAccessLogs(wafAccessLogFilters, true);
  }

  function updateWafAccessLogFilters(patch, shouldLoad = false) {
    setWafAccessLogFilters(prev => {
      const next = { ...prev, ...patch };
      if (shouldLoad) loadWafAccessLogs(next, false);
      return next;
    });
  }

  async function clearWafAccessLogs() {
    const selected = websites.find(site => String(site.id) === String(wafAccessLogFilters.websiteId));
    const label = selected?.domain || 'all websites';
    if (!confirm(`Clear access logs for ${label}?`)) return;
    const params = new URLSearchParams();
    if (wafAccessLogFilters.websiteId) params.set('website_id', wafAccessLogFilters.websiteId);
    const suffix = params.toString() ? `?${params.toString()}` : '';
    const data = await request(`/waf/access-logs${suffix}`, { method: 'DELETE' }, 'Clearing access logs...');
    if (data) {
      setNotice(data.message || 'Access logs cleared.');
      await loadWafAccessLogs(wafAccessLogFilters, false);
    }
  }

  function exportWafAccessLogs() {
    const rows = wafAccessLogs.items || [];
    const header = ['verdict', 'time', 'domain', 'method', 'path', 'ip', 'country', 'country_code', 'reason', 'status', 'duration_ms', 'user_agent'];
    const csv = [
      header.join(','),
      ...rows.map(item => header.map(key => csvCell(key === 'time' ? item.timestamp : item[key])).join(',')),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const site = websites.find(item => String(item.id) === String(wafAccessLogFilters.websiteId));
    link.href = url;
    link.download = `snpanel-access-logs-${site?.domain || 'all'}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function loadUpdates(force = false) {
    const data = await request(`/updates/status${force ? '?refresh=true' : ''}`, {}, 'Loading update status...');
    if (data) setUpdatesStatus(data);
  }

  async function toggleUpdateLog() {
    if (!showUpdateLog && !updatesStatus) await loadUpdates();
    setShowUpdateLog(prev => !prev);
  }

  async function runOsUpdate() {
    if (!confirm('Run apt-get update && apt-get upgrade now?')) return;
    setOsUpdating(true);
    const data = await request('/updates/os/run', { method: 'POST' }, 'Updating OS packages...');
    setOsUpdating(false);
    if (data) { setNotice((data.stdout || data.stderr || 'OS update completed.').trim()); if (showUpdateLog) await loadUpdates(); }
  }

  async function saveOsAutoUpdate() {
    const data = await request('/updates/os/auto', { method: 'POST', body: JSON.stringify(osAutoUpdate) }, 'Saving OS auto update...');
    if (data) { setNotice((data.stdout || data.stderr || 'OS auto update saved.').trim()); if (showUpdateLog) await loadUpdates(); }
  }

  async function runPanelUpdate() {
    if (!confirm('Update SNPanel from GitHub now? The API may restart and this page will reload when done.')) return;
    setPanelUpdating(true);
    setShowUpdateLog(true);
    setPanelUpdateLog([]);
    const data = await request('/updates/panel/run', { method: 'POST' }, 'Updating SNPanel...');
    if (!data) {
      setPanelUpdating(false);
      return;
    }
    // Poll /updates/status every 2s until the update finishes, then reload.
    const pollOnce = async () => {
      const status = await request('/updates/status', {}, null);
      if (!status) return;
      setUpdatesStatus(status);
      if (Array.isArray(status.panel_update_log)) {
        setPanelUpdateLog(status.panel_update_log);
      } else if (typeof status.panel_update_log === 'string' && status.panel_update_log) {
        setPanelUpdateLog(status.panel_update_log.split('\n'));
      }
      const st = status.panel || {};
      const done = st.last_update_status === 'completed' || st.last_update_status === 'failed';
      if (done) {
        if (panelUpdateInterval.current) {
          clearInterval(panelUpdateInterval.current);
          panelUpdateInterval.current = null;
        }
        setPanelUpdating(false);
        if (st.last_update_status === 'completed' && Number(st.progress_percent) === 100) {
          setNotice('Panel update completed. Reloading to apply the new version...');
          setTimeout(() => { window.location.reload(); }, 2000);
        } else if (st.last_update_status === 'failed') {
          setNotice((st.progress_message || st.last_update_message || 'Panel update failed.').trim());
        }
      }
    };
    await pollOnce();
    if (panelUpdateInterval.current) clearInterval(panelUpdateInterval.current);
    panelUpdateInterval.current = setInterval(pollOnce, 2000);
  }

  useEffect(() => {
    if (isAuthenticated) {
      refreshAll();
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (standaloneEditor) return undefined;
    const syncPageFromLocation = () => setPage(pageFromPathname(window.location.pathname));
    syncPageFromLocation();
    window.addEventListener('popstate', syncPageFromLocation);
    return () => window.removeEventListener('popstate', syncPageFromLocation);
  }, [standaloneEditor]);

  useEffect(() => {
    if (!isAuthenticated || !standaloneEditor) return;
    setSelectedWebsiteId(standaloneEditor.websiteId);
    setFileAppId(standaloneEditor.appId || '');
    setFilePath(standaloneEditor.path);
    readFile(standaloneEditor.path);
  }, [isAuthenticated, standaloneEditor]);

  useEffect(() => {
    if (!standaloneEditor || !isAuthenticated) return undefined;
    const handler = event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
        event.preventDefault();
        writeFile();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [standaloneEditor, isAuthenticated, selectedWebsiteId, filePath, fileContent]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'dashboard' || !isAdmin) return undefined;
    loadResourceUsage();
    const timer = setInterval(loadResourceUsage, 5000);
    return () => clearInterval(timer);
  }, [isAuthenticated, page, isAdmin]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'services') return undefined;
    checkAllServices();
    const timer = setInterval(checkAllServices, 10000);
    return () => clearInterval(timer);
  }, [isAuthenticated, page]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'websites') return undefined;
    const timer = window.setTimeout(() => {
      loadWebsiteList(websiteSearch, false);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [isAuthenticated, page, websiteSearch]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'databases') return undefined;
    const timer = window.setTimeout(() => {
      loadDatabases(dbSearch, false);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [isAuthenticated, page, dbSearch]);

  useEffect(() => {
    if (!currentSite) return;
    const modeMap = { manual: 'manual', cloudflare: 'wildcard', shared: 'shared' };
    setSslMode(modeMap[currentSite.ssl_mode] || 'letsencrypt');
    setManualSslForm({ certificate: '', private_key: '', ca_bundle: '' });
    setManualSslFiles({ certificate: null, private_key: null, ca_bundle: null });
    setWildcardToken('');
    setSharedSource('');
    setCfZone({ zone: null, has_token: false });
    setSslSources([]);
  }, [currentSite?.id]);

  useEffect(() => {
    if (page === 'ssl' && selectedWebsiteId) { loadCfZone(selectedWebsiteId); loadSslSources(selectedWebsiteId); }
  }, [page, selectedWebsiteId]);

  useEffect(() => { if (selectedWebsiteId && page === 'backups') { listBackups(); loadBackupJobs(); } }, [selectedWebsiteId, page]);

  useEffect(() => { if (selectedWebsiteId && page === 'backups' && backupTab === 'da-import') { listDaBackups(); setSelectedDaBackups([]); setDaBulkImportJob(null); } }, [backupTab, page]);

  useEffect(() => { if (selectedWebsiteId && page === 'cron') listCron(); }, [selectedWebsiteId, page]);
  // Which optional features exist decides what the nav shows, so this is asked
  // once per session rather than per page.
  useEffect(() => { if (currentUser) loadAddons(); }, [currentUser]);

  // The websites page needs the list too, for the Application picker on create.
  useEffect(() => {
    if (!currentUser || !applicationAddonInstalled) return;
    if (page === 'applications') { loadSiteApps(); loadSiteRuntimes(); }
    else if (page === 'websites' || page === 'files') loadSiteApps();
  }, [page, currentUser, applicationAddonInstalled]);

  useEffect(() => {
    if (page !== 'files' || !hasFileTarget()) return;
    // An app has no public_html; its root is the code directory itself.
    listFiles(fileAppId ? '' : 'public_html');
  }, [selectedWebsiteId, fileAppId, page]);

  useEffect(() => { if (selectedBackupUserId && page === 'backups') listUserBackups(selectedBackupUserId); }, [selectedBackupUserId, page]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'backups') return undefined;
    loadBackupJobs();
    const timer = setInterval(loadBackupJobs, 5000);
    return () => clearInterval(timer);
  }, [isAuthenticated, page, selectedWebsiteId, selectedBackupUserId]);

  useEffect(() => {
    if (isAuthenticated && page === 'users') { loadUsers(); loadPackages(); }
    if (isAuthenticated && page === 'php') { loadPhpConfig(); loadPhpTune(phpConfig.php_version); }
    if (isAuthenticated && page === 'firewall') { loadFirewall(); loadFirewallBlocklists(); }
    if (isAuthenticated && ['waf', 'waf-site'].includes(page)) {
      loadBotBlocks();
      // /waf/rules and /waf/crs describe the whole server and stay admin-only.
      if (isAdmin) { loadWafRules(); loadCrs(); }
    }
    if (isAuthenticated && page === 'malware' && isAdmin) {
      loadMalwareScanStatus();
      loadMalwareScanJobs();
      loadLatestMalwareScanJob();
      loadMalwareSchedule();
      if (websites.length === 0) loadWebsiteList('', false);
    }
    if (isAuthenticated && page === 'access-logs' && currentUser?.role === 'admin') {
      loadWafAccessLogs(wafAccessLogFilters, true);
    }
    if (isAuthenticated && page === 'updates' && currentUser?.role === 'admin') loadUpdates();
    if (isAuthenticated && page === 'security') {
      loadTwoFactorStatus();
      if (isAdmin) { loadMalwareScanStatus(); loadMalwareScanJobs(); loadLatestMalwareScanJob(); }
      if (!websites.length) refreshAll();
    }
    if (isAuthenticated && page === 'api-tokens' && currentUser?.role === 'admin') loadApiTokens();
    if (isAuthenticated && page === 'settings') loadPanelSettings();
    if (isAuthenticated && page === 'backups' && currentUser?.role === 'admin') { loadUsers(); loadSftpTargets(); loadBackupSchedules(); loadRestoreBackups(); }
  }, [isAuthenticated, page, currentUser?.role]);

  useEffect(() => {
    if (!isAuthenticated || page !== 'access-logs' || currentUser?.role !== 'admin') return undefined;
    if (!wafAccessLogFilters.refresh) return undefined;
    const timer = setInterval(() => loadWafAccessLogs(wafAccessLogFilters, false), Number(wafAccessLogFilters.refresh) * 1000);
    return () => clearInterval(timer);
  }, [isAuthenticated, page, currentUser?.role, wafAccessLogFilters]);

  useEffect(() => {
    if (!scanJob?.job_id || !['queued', 'running'].includes(scanJob.status)) return undefined;
    setScanLoading(true);
    const poll = () => loadMalwareScanJob(scanJob.job_id);
    const timer = window.setInterval(poll, 2000);
    poll();
    return () => window.clearInterval(timer);
  }, [scanJob?.job_id, scanJob?.status]);

  useEffect(() => {
    // Only on the per-site page: the overview does not need one selected, and
    // picking one there used to load a site's rules nobody had asked for.
    if (!isAuthenticated || page !== 'waf-site' || selectedWafWebsiteId || websites.length === 0) return;
    loadWebsiteWafConfig(websites[0].id, false);
  }, [isAuthenticated, page, selectedWafWebsiteId, websites.length]);

  useEffect(() => { setMobileMenuOpen(false); }, [page]);

  useEffect(() => {
    if (SETTINGS_PAGE_KEYS.includes(page)) setSettingsMenuOpen(true);
  }, [page]);

  function roleLabel(role) {
    return role === 'admin' ? 'Admin' : 'End user';
  }

  const mainNavItems = [
    ['dashboard', 'Dashboard', Home],
    ['websites', 'Websites', Globe],
    ...(appsFeatureEnabled ? [['applications', 'Applications', Server]] : []),
    ['ssl', 'SSL', Lock],
    ['databases', 'Database', Database],
    ['cron', 'Cron', Clock],
    ['files', 'File manager', FolderOpen],
    ['backups', 'Backups', Archive],
    ...(isAdmin ? [['users', 'Panel users', Users]] : []),
  ];

  const settingsNavItems = [
    ...(isAdmin ? [['settings', 'Panel settings', SettingsIcon]] : []),
    ...(isAdmin ? [['api-tokens', 'API Tokens', KeyRound]] : []),
    ['security', 'Security', Shield],
    ...(isAdmin ? [['php', 'PHP config', Code2]] : []),
    ...(isAdmin ? [['firewall', 'Firewall', Shield]] : []),
    ['waf', 'WAF', Shield],
    ...(isAdmin ? [['malware', 'Malware Scanner', Search]] : []),
    ...(isAdmin ? [['access-logs', 'Access Logs', FileText]] : []),
    ...(isAdmin ? [['updates', 'Updates', RefreshCw]] : []),
    ...(isAdmin ? [['addons', 'Addons', Boxes]] : []),
    ['services', 'Services Status', Server],
  ];

  const navItems = [...mainNavItems, ...settingsNavItems];
  const navPage = NAV_PARENT_PAGE[page] || page;
  const activeNavItem = navItems.find(([key]) => key === navPage) || navItems[0];
  const settingsIsActive = SETTINGS_PAGE_KEYS.includes(page);

  function renderNotifications() {
    const errorMessage = formatApiError(error, '').trim();
    const noticeMessage = formatApiError(notice, '').trim();
    if (!errorMessage && !noticeMessage) return null;
    return <div className="app-toast-stack" aria-label="Notifications">
      <NotificationToast type="error" message={errorMessage} onClose={() => setError('')} />
      <NotificationToast type="success" message={noticeMessage} onClose={() => setNotice('')} />
    </div>;
  }

  function websiteUrl(site) {
    const value = (site?.domain || '').trim();
    if (/^https?:\/\//i.test(value)) return value;
    return `${site?.ssl_enabled ? 'https' : 'http'}://${value}`;
  }

  // The file manager browses either a website root or an application root.
  function fileTargetBody() {
    return fileAppId ? { app_id: Number(fileAppId) } : { website_id: Number(selectedWebsiteId) };
  }

  function fileTargetBase() {
    return fileAppId ? `/maintenance/app-files/${fileAppId}` : `/maintenance/files/${selectedWebsiteId}`;
  }

  function fileTargetKey() {
    return fileAppId ? `app:${fileAppId}` : (selectedWebsiteId ? `site:${selectedWebsiteId}` : '');
  }

  function hasFileTarget() {
    return !!(fileAppId || selectedWebsiteId);
  }

  function currentFileApp() {
    return siteApps.items.find(app => String(app.id) === String(fileAppId)) || null;
  }

  function FileTargetSelect() {
    return <select
      value={fileAppId ? `app:${fileAppId}` : selectedWebsiteId}
      onChange={e => {
        const value = e.target.value;
        if (value.startsWith('app:')) setFileAppId(value.slice(4));
        else { setFileAppId(''); setSelectedWebsiteId(value); }
        setFileListPath(value.startsWith('app:') ? '' : 'public_html');
        setFiles([]);
        setSelectedFilePaths([]);
      }}
    >
      <option value="">-- Select website or application --</option>
      {websites.map(site => <option key={`site-${site.id}`} value={site.id}>{site.domain}</option>)}
      {siteApps.items.map(app => <option key={`app-${app.id}`} value={`app:${app.id}`}>App: {app.name}</option>)}
    </select>;
  }

  function parentFilePath(path) {
    const parts = String(path || '').split('/').filter(Boolean);
    parts.pop();
    return parts.join('/');
  }

  function fileBreadcrumbs(path) {
    const parts = String(path || '').split('/').filter(Boolean);
    let current = '';
    return parts.map(part => {
      current = current ? `${current}/${part}` : part;
      return { label: part, path: current };
    });
  }

  function isTextEditable(item) {
    if (!item || item.is_dir) return false;
    const name = (item.name || '').toLowerCase();
    const editableDotfiles = new Set(['.env', '.env.example', '.htaccess', '.user.ini', '.gitignore', '.gitattributes']);
    return editableDotfiles.has(name) || /\.(txt|md|json|css|js|jsx|ts|tsx|html|htm|xml|yml|yaml|ini|conf|log|php|env|htaccess)$/.test(name) || !name.includes('.');
  }

  function isArchiveFile(item) {
    if (!item || item.is_dir) return false;
    const name = (item.name || '').toLowerCase();
    return name.endsWith('.zip') || name.endsWith('.tar.gz') || name.endsWith('.tgz');
  }

  function toggleFileSelection(path) {
    setSelectedFilePaths(prev => prev.includes(path) ? prev.filter(item => item !== path) : [...prev, path]);
  }

  function toggleAllFiles() {
    setSelectedFilePaths(prev => prev.length === files.length ? [] : files.map(item => item.path));
  }

  function editorLanguage(path) {
    const name = String(path || '').toLowerCase();
    if (/\.php\d?$/.test(name) || name.endsWith('.phtml')) return 'PHP';
    if (/\.(js|jsx|ts|tsx)$/.test(name)) return 'JavaScript';
    if (/\.css$/.test(name)) return 'CSS';
    if (/\.html?$/.test(name)) return 'HTML';
    if (/\.json$/.test(name)) return 'JSON';
    if (/\.ya?ml$/.test(name)) return 'YAML';
    if (/\.(conf|ini|env|htaccess)$/.test(name)) return 'Config';
    return 'Text';
  }

  function WebsiteSelect() {
    return <select value={selectedWebsiteId} onChange={e => setSelectedWebsiteId(e.target.value)}>
      <option value="">-- Select website --</option>
      {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
    </select>;
  }

  function EmptyState({ icon: Icon = AlertCircle, message = 'No data yet' }) {
    return <div className="empty-state"><Icon size={40} /><p>{message}</p></div>;
  }

  function formatBytes(value) {
    const amount = Number(value);
    if (!Number.isFinite(amount) || amount < 0) return '--';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = amount;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
  }

  function formatPercent(value) {
    const amount = Number(value);
    if (!Number.isFinite(amount)) return '--';
    return `${Math.round(amount)}%`;
  }

  function clampPercent(value) {
    const amount = Number(value);
    if (!Number.isFinite(amount)) return 0;
    return Math.max(0, Math.min(100, amount));
  }

  function storageLimitBytes(user) {
    if (!user) return null;
    if (user.storage_limit_bytes === null) return null;
    if (user.storage_limit_bytes !== undefined) return user.storage_limit_bytes;
    return Number(user.storage_limit_mb || 0) * 1024 * 1024;
  }

  function storageUsageText(user) {
    const used = Number(user?.storage_used_bytes || 0);
    const limit = storageLimitBytes(user);
    if (limit === null) return formatBytes(used);
    return `${formatBytes(used)} / ${formatBytes(limit)}`;
  }

  function ResourceCard({ icon: Icon, label, value, detail, percent }) {
    const safePercent = percent == null ? null : clampPercent(percent);
    return <article className="resource-card">
      <div className="resource-head"><span className="resource-icon"><Icon size={16}/></span><span>{label}</span></div>
      <strong>{value}</strong>
      {safePercent !== null && <div className="resource-track"><span style={{ width: `${safePercent}%` }}></span></div>}
      <small>{detail}</small>
    </article>;
  }

  function renderDashboard() {
    const cpu = resourceUsage?.cpu || {};
    const memory = resourceUsage?.memory || {};
    const disk = resourceUsage?.disk || {};
    const network = resourceUsage?.network || {};
    const networkTotal = (Number(network.rx_per_sec) || 0) + (Number(network.tx_per_sec) || 0);
    const emptyWebsiteMessage = currentUser?.package_name
      ? `${currentUser.package_name} is ready. Attach your first domain to start hosting.`
      : 'No domain attached yet.';
    return <>
      {isAdmin && <section className="resource-grid">
        <ResourceCard icon={Cpu} label="CPU" value={formatPercent(cpu.percent)} percent={cpu.percent} detail={cpu.load?.length ? `Load ${cpu.load.join(' / ')}` : `${cpu.cores || '--'} cores`} />
        <ResourceCard icon={MemoryStick} label="RAM" value={formatPercent(memory.percent)} percent={memory.percent} detail={`${formatBytes(memory.used)} / ${formatBytes(memory.total)}`} />
        <ResourceCard icon={HardDrive} label="Disk" value={formatPercent(disk.percent)} percent={disk.percent} detail={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}`} />
        <ResourceCard icon={Network} label="Network" value={`${formatBytes(networkTotal)}/s`} detail={`Down ${formatBytes(network.rx_per_sec)}/s / Up ${formatBytes(network.tx_per_sec)}/s`} />
      </section>}
      <section className="stats-grid">
        <div className="stat-card"><strong>{websites.length}</strong><span>Websites</span></div>
        <div className="stat-card"><strong>{databases.length}</strong><span>Databases</span></div>
        <div className="stat-card"><strong>{websites.filter(s => s.ssl_enabled).length}</strong><span>SSL active</span></div>
        {currentUser && !isAdmin && <div className="stat-card"><strong>{formatBytes(currentUser.storage_used_bytes)}</strong><span>Storage / {formatBytes(storageLimitBytes(currentUser))}</span></div>}
      </section>
      {websites.length > 0 && <section className="section">
        <h2>Quick overview</h2>
        <div className="site-grid">
          {websites.slice(0, 4).map(site => <article className="site-card" key={site.id}>
            <div className="site-head">
              <div><a className="site-link" href={websiteUrl(site)} target="_blank" rel="noopener noreferrer">{site.domain}</a></div>
            </div>
            <div className="site-meta">
              <span className={`badge site-ssl-badge ${site.ssl_enabled ? 'ok' : ''}`}>{site.ssl_enabled ? 'SSL' : 'No SSL'}</span>
              <span>PHP <strong>{site.php_version}</strong></span>
              <span>Root <strong>{site.document_root || 'public_html'}</strong></span>
            </div>
          </article>)}
        </div>
        {websites.length > 4 && <p className="hint" style={{marginTop:8}}>Showing 4 of {websites.length} websites. Go to Websites for full list.</p>}
      </section>}
      {websites.length === 0 && <section className="section">
        <EmptyState icon={Globe} message={emptyWebsiteMessage} />
        <button className="secondary-light first-site-action" onClick={() => navigateToPage('websites')}><Plus size={15}/> Add domain</button>
      </section>}
    </>;
  }

  function renderAddonMissing() {
    return <section className="section">
      <div className="section-title"><div><h2>Applications</h2></div></div>
      <EmptyState
        icon={Boxes}
        message={applicationAddonInstalled
          ? 'Gói của bạn chưa có tính năng Application. Liên hệ quản trị để nâng cấp.'
          : 'Addon Application chưa được cài trên server này.'}
      />
      {isAdmin && !applicationAddonInstalled && <div className="site-app-form-actions">
        <button disabled={!!loading} onClick={() => navigateToPage('addons')}><Boxes size={14}/> Đi tới Addons</button>
      </div>}
    </section>;
  }

  function renderAddons() {
    return <section className="section">
      <div className="section-title">
        <div>
          <h2>Addons</h2>
          <p className="hint">
            Những phần không nằm trong bản cài mặc định. Cài khi cần, gỡ lúc không dùng —
            gỡ chỉ tắt tính năng, không xoá dữ liệu đã tạo.
          </p>
        </div>
        <button className="secondary-light" disabled={!!loading} onClick={loadAddons}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="addon-list">
        {addons.items.map(addon => <div className={`addon-card ${addon.installed ? 'installed' : ''}`} key={addon.slug}>
          <div className="addon-head">
            <strong>{addon.name}</strong>
            <code>v{addon.installed ? (addon.installed_version || addon.version) : addon.version}</code>
            <span className={`badge ${addon.installed ? 'ok' : ''}`}>{addon.installed ? 'Đã cài' : 'Chưa cài'}</span>
            {addon.installed && addon.installed_version && addon.installed_version !== addon.version
              && <span className="badge">Có bản v{addon.version}</span>}
          </div>
          <p className="addon-summary">{addon.summary}</p>
          {addon.details?.length > 0 && <ul className="addon-details">
            {addon.details.map((line, index) => <li key={index}>{line}</li>)}
          </ul>}
          {addon.notes?.length > 0 && <div className="addon-notes">
            <strong><AlertCircle size={13}/> Cần biết trước khi bật</strong>
            <ul>{addon.notes.map((line, index) => <li key={index}>{line}</li>)}</ul>
          </div>}
          {addons.can_manage && <div className="addon-actions">
            {addon.installed
              ? <>
                  {addon.slug === 'application' && <button className="secondary-light" disabled={!!loading} onClick={() => navigateToPage('applications')}>Mở {addon.name}</button>}
                  <button className="danger" disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, false)}><Trash2 size={14}/> Gỡ</button>
                </>
              : <button disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, true)}><Download size={14}/> Cài</button>}
          </div>}
        </div>)}
        {addons.loaded && addons.items.length === 0 && <EmptyState icon={Boxes} message="Chưa có addon nào." />}
      </div>
    </section>;
  }

  function renderApplications() {
    const [portFrom, portTo] = siteApps.port_range || [21000, 21999];
    const atLimit = !isAdmin && siteApps.limit > 0 && siteApps.used >= siteApps.limit;
    const dockerReady = !!siteRuntimes.docker?.installed;
    const kindHint = (SITE_APP_KINDS.find(([value]) => value === siteAppDraft.kind) || [])[2];
    return <>
      <section className="section">
        <div className="section-title">
          <div>
            <h2>Applications</h2>
            <p className="hint">
              Each application runs on its own port under its own systemd unit. Point a website at one by setting its
              mode to <strong>Application</strong>.
              {siteApps.limit > 0 && <> Using {siteApps.used} of {siteApps.limit} allowed.</>}
            </p>
          </div>
          <button disabled={!!loading} onClick={() => { loadSiteApps(); loadSiteRuntimes(); }}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="site-runtime-strip">
          <span>Docker: <strong>{dockerReady ? (siteRuntimes.docker.version || 'installed') : 'not installed'}</strong></span>
          <span>Node: <strong>{siteRuntimes.node_majors?.length ? siteRuntimes.node_majors.map(major => `v${major}`).join(', ') : 'system version only'}</strong></span>
          {isAdmin && !dockerReady && <button className="mini secondary-light" disabled={!!loading} onClick={installDockerEngine}>Install Docker</button>}
          {isAdmin && <button className="mini secondary-light" disabled={!!loading} onClick={() => { const major = prompt('Install which Node major version?', '22'); if (major) installNodeMajor(major.trim()); }}>Add Node version</button>}
        </div>
        {isAdmin && dockerReady && siteRuntimes.docker?.disk?.length > 0 && <div className="site-runtime-strip">
          <span>Đĩa Docker (toàn server, không tính vào quota khách):</span>
          {siteRuntimes.docker.disk.map(row => <span key={row.type}>
            {row.type}: <strong>{row.size}</strong>{row.reclaimable && !row.reclaimable.startsWith('0B') ? <> · dọn được {row.reclaimable}</> : null}
          </span>)}
          <button className="mini secondary-light" disabled={!!loading} onClick={pruneDocker}>Dọn layer không dùng</button>
        </div>}
        {!atLimit && <div className="site-app-form">
          <label><span>Name</span>
            <input value={siteAppDraft.name} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, name: e.target.value }))} />
          </label>
          <label><span>Runtime</span>
            <select value={siteAppDraft.kind} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, kind: e.target.value }))}>
              {SITE_APP_KINDS.map(([value, label]) => <option key={value} value={value} disabled={value === 'docker' && !dockerReady}>{label}</option>)}
            </select>
          </label>
          <label><span>Port</span>
            <input
              type="number"
              value={siteAppDraft.port}
              min={portFrom}
              max={portTo}
              disabled={!!loading}
              placeholder={`auto (${portFrom}-${portTo})`}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, port: e.target.value }))}
            />
          </label>
          <label><span>Memory (MB)</span>
            <input
              type="number"
              value={siteAppDraft.memory_limit_mb}
              min={64}
              max={siteApps.memory_ceiling_mb || 512}
              disabled={!!loading}
              placeholder={String(siteApps.memory_ceiling_mb || 512)}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, memory_limit_mb: e.target.value }))}
            />
          </label>
          {siteAppDraft.kind === 'node' && <>
            <label><span>Start with</span>
              <select value={siteAppDraft.start_kind} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, start_kind: e.target.value }))}>
                <option value="npm">npm run</option>
                <option value="npx">npx</option>
                <option value="yarn">yarn</option>
                <option value="node">node</option>
              </select>
            </label>
            <label><span>{siteAppDraft.start_kind === 'node' ? 'Entry file' : 'Script or package'}</span>
              <input value={siteAppDraft.start_arg} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, start_arg: e.target.value }))} placeholder={siteAppDraft.start_kind === 'node' ? 'server.js' : 'start'} />
            </label>
            <label><span>Node version</span>
              <select value={siteAppDraft.node_major} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, node_major: e.target.value }))}>
                {(siteRuntimes.node_majors?.length ? siteRuntimes.node_majors : ['22']).map(major => <option key={major} value={major}>Node {major}</option>)}
              </select>
            </label>
          </>}
          {siteAppDraft.kind === 'compose' && <>
            <label className="site-app-env"><span>docker-compose.yml</span>
              <textarea
                className="code-editor"
                rows={12}
                value={siteAppDraft.compose_source}
                disabled={!!loading}
                onChange={e => { setSiteAppDraft(prev => ({ ...prev, compose_source: e.target.value })); setComposePlan(null); }}
                placeholder={'services:\n  app:\n    image: myorg/app:1.0\n    ports: ["3000:3000"]\n  db:\n    image: postgres:16\n    volumes: ["pgdata:/var/lib/postgresql/data"]\nvolumes:\n  pgdata:'}
              />
            </label>
            {composePlan?.services?.length > 0 && <label><span>Service phục vụ domain</span>
              <select value={siteAppDraft.web_service} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, web_service: e.target.value }))}>
                <option value="">Tự chọn</option>
                {composePlan.services.map(service => <option key={service.name} value={service.name}>{service.name}{service.container_port ? ` · :${service.container_port}` : ''}</option>)}
              </select>
            </label>}
            {composeWebPorts(composePlan, siteAppDraft.web_service).length > 1 && <label><span>Cổng phục vụ domain</span>
              <select value={siteAppDraft.container_port} disabled={!!loading} onChange={e => { setSiteAppDraft(prev => ({ ...prev, container_port: e.target.value })); setComposePlan(null); }}>
                {composeWebPorts(composePlan, siteAppDraft.web_service).map(port => <option key={port} value={port}>{port}</option>)}
              </select>
            </label>}
            <label><span>CPU mỗi service</span>
              <input value={siteAppDraft.cpu_limit} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, cpu_limit: e.target.value }))} placeholder="1" />
            </label>
            <p className="compose-hint">File tham chiếu <code>{'${BIẾN}'}</code> thì khai giá trị ở ô <strong>.env</strong> bên dưới,
              đúng như file <code>.env</code> nằm cạnh <code>docker-compose.yml</code>. Riêng địa chỉ công khai
              (callback OAuth, webhook) dùng <code>{'${SNPANEL_URL}'}</code> / <code>{'${SNPANEL_DOMAIN}'}</code>:
              ứng dụng chỉ thấy cổng nội bộ, panel sẽ điền domain của website trỏ vào nó.</p>
          </>}
          {siteAppDraft.kind === 'docker' && <>
            <label><span>Image</span>
              <input value={siteAppDraft.image} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, image: e.target.value }))} placeholder="n8nio/n8n:latest" />
            </label>
            <label><span>Port in container</span>
              <input type="number" value={siteAppDraft.container_port} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, container_port: e.target.value }))} placeholder="3000" />
            </label>
            <label><span>CPU</span>
              <input value={siteAppDraft.cpu_limit} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, cpu_limit: e.target.value }))} placeholder="1" />
            </label>
          </>}
          <label className="site-app-env"><span>{siteAppDraft.kind === 'compose' ? '.env (KEY=value, one per line)' : 'Environment (KEY=value, one per line)'}</span>
            <textarea
              className="code-editor"
              rows={4}
              value={siteAppDraft.env}
              disabled={!!loading}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, env: e.target.value }))}
              placeholder={'N8N_ENCRYPTION_KEY=...\nGENERIC_TIMEZONE=Asia/Ho_Chi_Minh'}
            />
          </label>
          <div className="site-app-form-actions">
            {siteAppDraft.kind === 'compose' && <button className="secondary-light" disabled={!!loading || !siteAppDraft.compose_source.trim()} onClick={checkComposeFile}>Check file</button>}
            <button className="secondary-light" disabled={!!loading} onClick={suggestSiteAppPort}>Pick free port</button>
            <button disabled={!!loading || !siteAppDraft.name.trim()} onClick={createSiteApp}><Plus size={14}/> Install application</button>
          </div>
          {composePlan && <div className={`compose-report ${composePlan.ok ? 'ok' : 'bad'}`}>
            {composePlan.ok
              ? <p><Check size={14}/> Chạy được {composePlan.services.length} service. <strong>{composePlan.web_service}</strong> phục vụ domain.</p>
              : <p><AlertCircle size={14}/> Còn {composePlan.issues.length} chỗ phải sửa trước khi import:</p>}
            {composePlan.issues.length > 0 && <ul>
              {composePlan.issues.map((issue, index) => <li key={index}>
                {issue.service && <code>{issue.service}</code>} {issue.message}
              </li>)}
            </ul>}
            {composePlan.notes?.length > 0 && <ul className="compose-notes">
              {composePlan.notes.map((note, index) => <li key={index}>{note}</li>)}
            </ul>}
            {composePlan.ok && <ul className="compose-services">
              {composePlan.services.map(service => <li key={service.name}>
                <code>{service.name}</code> {service.image}
                {service.web ? ' · phục vụ domain' : ' · chỉ nội bộ'}
                {service.container_port ? ` · cổng ${service.container_port}` : ''}
              </li>)}
            </ul>}
          </div>}
        </div>}
        {atLimit && <p className="hint">This package allows {siteApps.limit} application(s). Delete one to install another.</p>}
        {kindHint && <p className="hint site-apps-note">{kindHint} Containers publish on <code>127.0.0.1</code> only, run as your own user with no capabilities, and are capped at the memory shown. Images come from {(siteRuntimes.allowed_registries || []).join(', ') || 'the allowed registries'}.</p>}
      </section>

      <section className="section">
        <div className="section-title">
          <div><h2>Installed</h2><p className="hint">{siteApps.items.length} application(s)</p></div>
        </div>
        {siteApps.items.length === 0 && <EmptyState icon={Server} message="No applications yet. Install one above." />}
        <div className="site-app-list">
          {siteApps.items.map(app => <div className="site-app-item" key={app.id}>
            <div className="site-app-head">
              <strong>{app.name}</strong>
              <span className="badge">{SITE_APP_KIND_LABELS[app.kind] || app.kind}</span>
              <code>127.0.0.1:{app.port}</code>
              <span className={`badge ${app.status === 'running' ? 'ok' : app.status === 'error' ? 'bad' : ''}`}>
                {app.status === 'running' ? 'Running' : app.status === 'error' ? 'Failed' : 'Stopped'}
              </span>
              {app.websites?.length > 0 && <span className="site-app-domains">{app.websites.join(', ')}</span>}
            </div>
            {app.last_error && <p className="site-app-error">{app.last_error}</p>}
            <dl className="site-app-meta">
              <div><dt>Upload code to</dt><dd><code>{app.directory}</code></dd></div>
              {app.kind === 'node' && <div><dt>Start</dt><dd><code>{app.start_kind} {app.start_arg}</code></dd></div>}
              {app.kind === 'node' && <div><dt>Node</dt><dd>v{app.node_major || '22'}</dd></div>}
              {app.kind === 'compose' && <div><dt>Serves domain</dt><dd><code>{app.web_service}</code></dd></div>}
              {app.kind === 'docker' && <div><dt>Image</dt><dd><code>{app.image}</code></dd></div>}
              {app.kind === 'docker' && <div><dt>In container</dt><dd>port {app.container_port} · {app.cpu_limit} CPU</dd></div>}
              <div><dt>Unit</dt><dd><code>{app.unit}</code></dd></div>
            </dl>
            <div className="site-app-actions">
              <div className="site-app-fields">
                <label className="site-app-port">
                  <span>Port</span>
                  <input
                    type="number"
                    defaultValue={app.port}
                    min={portFrom}
                    max={portTo}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = Number(e.target.value);
                      if (next && next !== app.port) updateSiteApp(app, { port: next }, 'Moving application port...');
                    }}
                  />
                </label>
                <label className="site-app-port">
                  <span>Memory (MB)</span>
                  <input
                    type="number"
                    defaultValue={app.memory_limit_mb}
                    min={64}
                    max={isAdmin ? 16384 : (siteApps.memory_ceiling_mb || 512)}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = Number(e.target.value);
                      if (next && next !== app.memory_limit_mb) updateSiteApp(app, { memory_limit_mb: next }, 'Applying the new memory limit...');
                    }}
                  />
                </label>
                {app.kind === 'docker' && <label className="site-app-port">
                  <span>CPU</span>
                  <input
                    defaultValue={app.cpu_limit}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = e.target.value.trim();
                      if (next && next !== app.cpu_limit) updateSiteApp(app, { cpu_limit: next }, 'Applying the new CPU limit...');
                    }}
                  />
                </label>}
              </div>
              <div className="site-app-buttons">
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openSiteAppEdit(app)}><Pencil size={13}/> {app.kind === 'compose' ? 'Compose' : 'Environment'}</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openAppFileManager(app)}><FolderOpen size={13}/> Files</button>
                <button className="mini" disabled={!!loading} onClick={() => deploySiteApp(app)}><Play size={13}/> Deploy</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => controlSiteApp(app, 'restart')}><RotateCcw size={13}/> Restart</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => controlSiteApp(app, 'stop')}><Square size={13}/> Stop</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openSiteAppLog(app)}><FileText size={13}/> Log</button>
                <button className="mini danger" disabled={!!loading} onClick={() => deleteSiteApp(app)}><Trash2 size={13}/> Delete</button>
              </div>
            </div>
            {siteAppEdit?.id === app.id && <div className="site-app-editor">
              {app.kind === 'compose' ? <>
                <label className="site-app-env"><span>docker-compose.yml</span>
                  <textarea
                    className="code-editor"
                    rows={14}
                    value={siteAppEdit.compose_source}
                    disabled={!!loading}
                    onChange={e => { setSiteAppEdit(prev => ({ ...prev, compose_source: e.target.value })); setSiteAppEditPlan(null); }}
                  />
                </label>
                <p className="compose-hint">Panel đọc lại file này rồi tự sinh file chạy thật. Biến <code>{'${BIẾN}'}</code> lấy
                  từ ô .env; địa chỉ công khai dùng <code>{'${SNPANEL_URL}'}</code> / <code>{'${SNPANEL_DOMAIN}'}</code>
                  {app.websites?.length > 0 ? ` (hiện là ${app.websites[0]})` : ' (cần trỏ một website vào ứng dụng trước)'}.</p>
                <label className="site-app-env"><span>.env (KEY=value, one per line)</span>
                  <textarea
                    className="code-editor"
                    rows={6}
                    value={siteAppEdit.env}
                    disabled={!!loading}
                    onChange={e => { setSiteAppEdit(prev => ({ ...prev, env: e.target.value })); setSiteAppEditPlan(null); }}
                  />
                </label>
                {siteAppEditPlan?.services?.length > 0 && <label><span>Service phục vụ domain</span>
                  <select value={siteAppEdit.web_service} disabled={!!loading} onChange={e => setSiteAppEdit(prev => ({ ...prev, web_service: e.target.value }))}>
                    <option value="">Tự chọn</option>
                    {siteAppEditPlan.services.map(service => <option key={service.name} value={service.name}>{service.name}{service.container_port ? ` · :${service.container_port}` : ''}</option>)}
                  </select>
                </label>}
                {composeWebPorts(siteAppEditPlan, siteAppEdit.web_service).length > 1 && <label><span>Cổng phục vụ domain</span>
                  <select value={siteAppEdit.container_port} disabled={!!loading} onChange={e => { setSiteAppEdit(prev => ({ ...prev, container_port: e.target.value })); setSiteAppEditPlan(null); }}>
                    {composeWebPorts(siteAppEditPlan, siteAppEdit.web_service).map(port => <option key={port} value={port}>{port}</option>)}
                  </select>
                </label>}
              </> : <label className="site-app-env"><span>Environment (KEY=value, one per line)</span>
                <textarea
                  className="code-editor"
                  rows={8}
                  value={siteAppEdit.env}
                  disabled={!!loading}
                  onChange={e => setSiteAppEdit(prev => ({ ...prev, env: e.target.value }))}
                />
              </label>}
              <div className="site-app-form-actions">
                {app.kind === 'compose' && <button className="secondary-light" disabled={!!loading || !siteAppEdit.compose_source.trim()} onClick={checkSiteAppEdit}>Check file</button>}
                <button disabled={!!loading} onClick={() => saveSiteAppEdit(app)}><Save size={14}/> Save</button>
                <button className="secondary-light" disabled={!!loading} onClick={() => { setSiteAppEdit(null); setSiteAppEditPlan(null); }}><X size={14}/> Cancel</button>
              </div>
              {siteAppEditPlan && <div className={`compose-report ${siteAppEditPlan.ok ? 'ok' : 'bad'}`}>
                {siteAppEditPlan.ok
                  ? <p><Check size={14}/> Chạy được {siteAppEditPlan.services.length} service. <strong>{siteAppEditPlan.web_service}</strong> phục vụ domain.</p>
                  : <p><AlertCircle size={14}/> Còn {siteAppEditPlan.issues.length} chỗ phải sửa:</p>}
                {siteAppEditPlan.issues.length > 0 && <ul>
                  {siteAppEditPlan.issues.map((issue, index) => <li key={index}>
                    {issue.service && <code>{issue.service}</code>} {issue.message}
                  </li>)}
                </ul>}
                {siteAppEditPlan.notes?.length > 0 && <ul className="compose-notes">
                  {siteAppEditPlan.notes.map((note, index) => <li key={index}>{note}</li>)}
                </ul>}
              </div>}
            </div>}
          </div>)}
        </div>
        {siteAppLog && <div className="site-app-log">
          <div className="site-app-log-head">
            <h4>{siteAppLog.name} log</h4>
            <button className="mini secondary-light" onClick={() => setSiteAppLog(null)}><X size={13}/> Close</button>
          </div>
          <pre>{siteAppLog.log}</pre>
        </div>}
      </section>
    </>;
  }

  function renderNginxEditor() {
    if (!nginxCustomEditing) return null;
    const fullConfig = nginxCustomEditing.mode === 'full';
    const selectedAppType = websiteSettingsForm.app_type || nginxCustomEditing.site?.app_type || 'wordpress';
    const rewriteDisabled = selectedAppType !== 'php';
    const proxied = isProxiedAppType(selectedAppType);
    const settingsSite = nginxCustomEditing.site || {};
    const siteDomains = settingsSite.aliases || [];
    const aliasMode = aliasModes[nginxCustomEditing.id] || 'alias';
    return <section className="section nginx-modal inline-nginx-editor">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>{fullConfig ? 'Full Nginx config' : 'Website settings'} - {nginxCustomEditing.domain}</h2>
          <p className="hint">{fullConfig
            ? 'This is read-only. SNPanel manages the main vhost template.'
            : 'Managed settings rewrite the main vhost safely. Custom Nginx is still stored as a separate include.'}</p>
        </div>
        <div className="actions">
          {!fullConfig && isAdmin && <button className="secondary-light" disabled={!!loading} onClick={viewFullNginxConfig}><FileText size={14}/> View all</button>}
          {fullConfig && <button className="secondary-light" disabled={!!loading} onClick={() => setNginxCustomEditing(prev => ({ ...prev, mode: 'custom', content: prev?.customContent ?? prev?.content ?? '' }))}><SettingsIcon size={14}/> Settings</button>}
          <button className="secondary-light" onClick={() => setNginxCustomEditing(null)}><X size={14}/> Close</button>
        </div>
      </div>
      {!fullConfig && <div className="website-settings-grid">
        <label><span>Website mode</span><select
          value={websiteSettingsForm.app_type}
          onChange={e => setWebsiteSettingsForm(prev => ({
            ...prev,
            app_type: e.target.value,
            nginx_rewrite_mode: e.target.value === 'php' ? prev.nginx_rewrite_mode || 'none' : e.target.value === 'wordpress' ? 'front_controller' : 'none',
          }))}
          disabled={!!loading}
        >
          {WEBSITE_MODES.map(([value, label]) => <option
            key={value}
            value={value}
            disabled={value === 'application' && !appsFeatureEnabled}
          >{label}</option>)}
        </select></label>
        {proxied && <label><span>Application</span><select
          value={websiteSettingsForm.app_id || ''}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, app_id: e.target.value }))}
          disabled={!!loading}
        >
          <option value="">Select an application</option>
          {siteApps.items.map(app => <option key={app.id} value={app.id}>{app.name} · {SITE_APP_KIND_LABELS[app.kind] || app.kind} · :{app.port}</option>)}
        </select></label>}
        {selectedAppType !== 'static' && !proxied && <label><span>PHP version</span><select
          value={websiteSettingsForm.php_version}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, php_version: e.target.value }))}
          disabled={!!loading}
        >
          {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
        </select></label>}
        <label><span>Nginx rewrite</span><select
          value={rewriteDisabled ? (selectedAppType === 'wordpress' ? 'front_controller' : 'none') : websiteSettingsForm.nginx_rewrite_mode}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, nginx_rewrite_mode: e.target.value }))}
          disabled={!!loading || rewriteDisabled}
        >
          {NGINX_REWRITE_MODES.map(mode => <option key={mode.value} value={mode.value}>{mode.label}</option>)}
        </select></label>
        <div className="website-settings-actions">
          <button disabled={!!loading} onClick={saveWebsiteSettings}><Save size={14}/> Save settings</button>
        </div>
      </div>}
      {!fullConfig && <div className="site-aliases settings-domain-manager">
        <div className="domain-manager-head">
          <h3>Domains</h3>
          <p className="hint">Alias serves the same app. Redirect sends visitors to {nginxCustomEditing.domain}.</p>
        </div>
        <div className="alias-list">
          <span className="alias-chip primary-domain"><Globe size={12}/>{nginxCustomEditing.domain}<span>Main</span></span>
          {siteDomains.length === 0
            ? <span className="alias-empty">No extra domains</span>
            : siteDomains.map(alias => <span className="alias-chip" key={alias.id}>
              <Globe size={12}/>{alias.domain}<span>{alias.mode === 'redirect' ? 'Redirect' : 'Alias'}</span>
              <button type="button" disabled={!!loading} title={`Remove ${alias.domain}`} aria-label={`Remove ${alias.domain}`} onClick={() => deleteWebsiteAlias(settingsSite, alias)}><X size={12}/></button>
            </span>)}
        </div>
        <div className="alias-form settings-domain-form">
          <input
            value={aliasDrafts[nginxCustomEditing.id] || ''}
            onChange={e => setAliasDrafts(prev => ({ ...prev, [nginxCustomEditing.id]: e.target.value }))}
            onKeyDown={e => { if (e.key === 'Enter') addWebsiteAlias(settingsSite); }}
            placeholder="domain-alias.com"
            disabled={!!loading}
          />
          <select
            value={aliasMode}
            onChange={e => setAliasModes(prev => ({ ...prev, [nginxCustomEditing.id]: e.target.value }))}
            disabled={!!loading}
          >
            <option value="alias">Alias</option>
            <option value="redirect">Redirect</option>
          </select>
          <button className="secondary-light" disabled={!!loading || !(aliasDrafts[nginxCustomEditing.id] || '').trim()} onClick={() => addWebsiteAlias(settingsSite)}><Plus size={14}/> Add domain</button>
        </div>
      </div>}
      <div className="custom-nginx-block">
        {!fullConfig && <h3>Custom Nginx</h3>}
        <textarea
          className="code-editor"
          value={nginxCustomEditing.content}
          onChange={e => setNginxCustomEditing(prev => ({ ...prev, content: e.target.value, customContent: e.target.value }))}
          placeholder={fullConfig
            ? `server {\n    listen 80;\n    server_name ${nginxCustomEditing.domain};\n}`
            : `# Optional extra directives only. Use Nginx rewrite above for location / routing.`}
          spellCheck={false}
          rows={fullConfig ? 18 : 10}
          readOnly={fullConfig}
        />
      </div>
      <div className="actions">
        {!fullConfig && <button disabled={!!loading} onClick={saveNginxCustom}>Save and reload Nginx</button>}
        {!fullConfig && <button className="secondary-light" disabled={!!loading} onClick={resetNginxDefault}><RotateCcw size={14}/> Reset custom</button>}
        <button className="secondary-light" disabled={!!loading} onClick={() => setNginxCustomEditing(null)}>{fullConfig ? 'Close' : 'Cancel'}</button>
      </div>
    </section>;
  }

  function renderWordPressInstaller() {
    if (!wordpressInstaller) return null;
    return <section className="section nginx-modal inline-nginx-editor wordpress-install-modal">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>Install WordPress - {wordpressInstaller.domain}</h2>
          <p className="hint">PHP {wordpressInstaller.php_version || '8.4'}</p>
        </div>
        <button className="secondary-light" onClick={() => setWordpressInstaller(null)}><X size={14}/> Close</button>
      </div>
      <div className="website-settings-grid">
        <label><span>Site title</span><input
          value={wordpressInstaller.title}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, title: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>Admin user</span><input
          value={wordpressInstaller.admin_user}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_user: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>Admin email</span><input
          value={wordpressInstaller.admin_email}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_email: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>Admin password</span><input
          value={wordpressInstaller.admin_password}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_password: e.target.value }))}
          disabled={!!loading}
        /></label>
        <div className="website-settings-actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => setWordpressInstaller(prev => prev ? ({ ...prev, admin_password: generateRandomPassword(20) }) : prev)}><Dices size={14}/> Generate</button>
          <button disabled={!!loading || !wordpressInstaller.admin_user || !wordpressInstaller.admin_email || !wordpressInstaller.admin_password} onClick={installWordPressOnSite}><WordPressIcon size={14}/> Install</button>
        </div>
      </div>
    </section>;
  }


  function renderWebsiteTerminal() {
    if (!terminalViewer) return null;
    return <section className="section nginx-modal terminal-modal">
      <div className="section-title">
        <h2>Terminal - {terminalViewer.domain}</h2>
        <button className="secondary-light" onClick={() => setTerminalViewer(null)}><X size={14}/> Close</button>
      </div>
      <div style={{ height: '500px', marginTop: '8px' }}>
        <Terminal websiteId={terminalViewer.id} apiBase={API} />
      </div>
    </section>;
  }

  function renderWebsiteLogViewer() {
    if (!logViewer) return null;
    return <section className="section nginx-modal log-viewer">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>Nginx logs - {logViewer.domain}</h2>
          <p className="hint">{logViewer.path || `/var/log/nginx/${logViewer.domain}.${logViewer.kind}.log`}</p>
        </div>
        <button className="secondary-light" onClick={() => setLogViewer(null)}><X size={14}/> Close</button>
      </div>
      <div className="log-toolbar">
        <div className="segmented-control">
          <button className={logViewer.kind === 'access' ? 'active' : ''} disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, 'access', logViewer.lines, logViewer.domain)}>Access</button>
          <button className={logViewer.kind === 'error' ? 'active' : ''} disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, 'error', logViewer.lines, logViewer.domain)}>Error</button>
        </div>
        <select value={logViewer.lines} onChange={e => loadWebsiteLog(logViewer.id, logViewer.kind, Number(e.target.value), logViewer.domain)} disabled={!!loading}>
          <option value={100}>100 lines</option>
          <option value={200}>200 lines</option>
          <option value={500}>500 lines</option>
          <option value={1000}>1000 lines</option>
          <option value={2000}>2000 lines</option>
        </select>
        <button disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, logViewer.kind, logViewer.lines, logViewer.domain)}><RefreshCw size={14}/> Refresh</button>
      </div>
      <pre className="log-output">{logViewer.exists ? (logViewer.content || 'Log is empty.') : 'Log file has not been created yet.'}</pre>
    </section>;
  }

  function renderWebsites() {
    const wpFieldsEnabled = siteType === 'wordpress' && installWordPress;
    const searchActive = !!websiteSearch.trim();
    const visibleWebsites = searchActive ? websiteList : (websiteList.length ? websiteList : websites);
    const createTitle = websites.length ? 'Create website' : 'Attach first domain';
    const createHint = websites.length
      ? null
      : 'This creates the first hosted site for the current account.';
    return <>
      <section className="section">
        <h2>{createTitle}</h2>
        {createHint && <p className="hint">{createHint}</p>}
        <div className="form-row create-site-row">
          <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="domain.com" />
          <select value={siteType} onChange={e => setSiteType(e.target.value)}>
            {WEBSITE_MODES.map(([value, label]) => <option
              key={value}
              value={value}
              disabled={value === 'application' && !appsFeatureEnabled}
            >{label}</option>)}
          </select>
          {siteType === 'application'
            ? <select value={createSiteAppId} onChange={e => setCreateSiteAppId(e.target.value)}>
              <option value="">Select an application</option>
              {siteApps.items.map(app => <option key={app.id} value={app.id}>{app.name} · {SITE_APP_KIND_LABELS[app.kind] || app.kind} · :{app.port}</option>)}
            </select>
            : <select value={phpVersion} onChange={e => setPhpVersion(e.target.value)}>
              {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
            </select>}
          {wpFieldsEnabled && <input value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder="admin@domain.com" />}
          {wpFieldsEnabled && <input value={wpAdminUser} onChange={e => setWpAdminUser(e.target.value)} placeholder="WP admin user" />}
          {wpFieldsEnabled && <input value={wpAdminPassword} onChange={e => setWpAdminPassword(e.target.value)} placeholder="WP admin password" type="password" />}
          <button disabled={!!loading || !domain} onClick={createWordPress}><Plus size={15}/> Create</button>
        </div>
        {siteType === 'application' && siteApps.items.length === 0 && <p className="hint">
          No applications installed yet. Install one on the <button type="button" className="link-button" onClick={() => navigateToPage('applications')}>Applications</button> page first.
        </p>}
        {siteType === 'wordpress' && <label className="check-line">
          <input type="checkbox" checked={installWordPress} onChange={e => setInstallWordPress(e.target.checked)} />
          Install WordPress (creates database, downloads WP, configures vhost)
        </label>}
        <div className="create-ssl-row">
          <span className="create-ssl-label">SSL after creating</span>
          <div className="segmented ssl-mode-tabs">
            <button type="button" className={createSslMode === 'none' ? 'active' : ''} onClick={() => setCreateSslMode('none')}>Off</button>
            <button type="button" className={createSslMode === 'letsencrypt' ? 'active' : ''} onClick={() => setCreateSslMode('letsencrypt')}><Lock size={13}/> Let's Encrypt</button>
            <button type="button" className={createSslMode === 'wildcard' ? 'active' : ''} onClick={() => setCreateSslMode('wildcard')}><Globe size={13}/> Wildcard</button>
            <button type="button" className={createSslMode === 'shared' ? 'active' : ''} onClick={() => setCreateSslMode('shared')}><Copy size={13}/> Existing cert</button>
            <button type="button" className={createSslMode === 'manual' ? 'active' : ''} onClick={() => setCreateSslMode('manual')}><KeyRound size={13}/> Manual</button>
          </div>
        </div>
        {createSslMode !== 'none' && <div className="ssl-sub-form create-ssl-sub">
          {createSslMode === 'letsencrypt' && <p className="hint">A certificate is issued right after the site is created — the domain must already point to this server.</p>}
          {createSslMode === 'wildcard' && <>
            <p className="hint">Issues <code>zone + *.zone</code> over Cloudflare DNS. Leave the token blank to reuse one already saved for the zone.</p>
            <input type="password" autoComplete="off" placeholder="Cloudflare API token (Zone → DNS → Edit)"
              value={createSslToken} onChange={e => setCreateSslToken(e.target.value)} />
          </>}
          {createSslMode === 'shared' && <p className="hint">After the site is created the panel points it at an existing certificate that covers this domain (a wildcard first). If none does, the site is created without SSL.</p>}
          {createSslMode === 'manual' && <p className="hint">The site is created, then the panel opens the SSL page so you can paste the certificate and key.</p>}
        </div>}
        <p className="hint">{wpFieldsEnabled
          ? 'WordPress will be installed and the panel will show the URL, admin account, and password after creation.'
          : siteType === 'application'
            ? 'Nginx will forward this domain to the selected application on 127.0.0.1, including WebSocket upgrades.'
            : 'A PHP-FPM vhost will be created with public_html/ folder. Upload your PHP, HTML, or static files via File Manager.'}</p>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>Website list</h2><p className="hint">{searchActive ? `${visibleWebsites.length} result(s)` : `${visibleWebsites.length} website(s)`}</p></div>
          <button disabled={!!loading || websiteSearching} onClick={() => loadWebsiteList(websiteSearch, true)}><RefreshCw size={15} className={websiteSearching ? 'spin' : ''}/> Refresh</button>
        </div>
        <div className="website-search-bar">
          <Search size={16}/>
          <input
            value={websiteSearch}
            onChange={e => setWebsiteSearch(e.target.value)}
            placeholder="Search domain, alias, path, or Linux user"
            aria-label="Search websites"
          />
          {websiteSearch && <button className="secondary-light icon-button" type="button" onClick={() => setWebsiteSearch('')} aria-label="Clear website search" title="Clear search"><X size={15}/></button>}
        </div>
        {visibleWebsites.length === 0 && <EmptyState icon={Globe} message={searchActive ? "No websites match this search." : "No websites yet."} />}
        <div className="site-grid">
          {visibleWebsites.map(site => <div className="site-stack" key={site.id}>
          <article className="site-card">
            <div className="site-head">
              <div>
                <a className="site-link" href={websiteUrl(site)} target="_blank" rel="noopener noreferrer">{site.domain}</a>
                <small>{site.root_path}</small>
              </div>
            </div>
            <div className="site-meta">
              <span className={`badge site-ssl-badge ${site.ssl_enabled ? 'ok' : ''}`}>{site.ssl_enabled ? 'SSL OK' : 'No SSL'}</span>
              <span>Type <strong>{site.app_type || 'wordpress'}</strong></span>
              <span>PHP <strong>{site.php_version}</strong></span>
              {site.app_type === 'php' && site.nginx_rewrite_mode && site.nginx_rewrite_mode !== 'none' && <span>Rewrite <strong>{site.nginx_rewrite_mode}</strong></span>}
              {site.nginx_custom && <span className="badge ok">Custom Nginx</span>}
              {site.waf_enabled && <span className="badge ok">WAF</span>}
              {site.http_flood_enabled && <span className="badge ok">HTTP Flood</span>}
              {(site.aliases || []).length > 0 && <span>Domains <strong>{(site.aliases || []).length + 1}</strong></span>}
            </div>
            <div className="site-actions" aria-label={`Website actions for ${site.domain}`}>
              <div className="site-feature-actions">
                <button className="site-icon-button secondary-light" data-tooltip="Files" title="Files" aria-label={`Open file manager for ${site.domain}`} disabled={!!loading} onClick={() => openWebsiteFileManager(site)}><FolderOpen size={15}/></button>
                <button className="site-icon-button secondary-light" data-tooltip="Logs" title="Logs" aria-label={`View logs for ${site.domain}`} disabled={!!loading} onClick={() => openWebsiteLogs(site)}><FileText size={15}/></button>
                <button className="site-icon-button secondary-light" data-tooltip="Terminal" title="Terminal" aria-label={`Open terminal for ${site.domain}`} disabled={!!loading} onClick={() => openWebsiteTerminal(site)}><TerminalIcon size={15}/></button>
                {site.wordpress_installed ? <>
                  <button className="site-icon-button secondary-light" data-tooltip="Update WordPress" title="Update WordPress (core + plugins + themes)" aria-label={`Update WordPress for ${site.domain}`} disabled={!!loading} onClick={() => updateWordPressAll(site)}><RefreshCw size={15}/></button>
                </> : <button className="site-icon-button secondary-light" data-tooltip="Install WP" title="Install WordPress" aria-label={`Install WordPress for ${site.domain}`} disabled={!!loading} onClick={() => openWordPressInstaller(site)}><WordPressIcon size={15}/></button>}
                <button className="site-icon-button secondary-light" data-tooltip="Settings" title="Settings" aria-label={`Edit settings for ${site.domain}`} disabled={!!loading} onClick={() => openNginxCustom(site)}><SettingsIcon size={15}/></button>
                <button className="site-icon-button danger" data-tooltip="Delete" title="Delete" aria-label={`Delete ${site.domain}`} disabled={!!loading} onClick={() => deleteWebsite(site.id)}><Trash2 size={15}/></button>
              </div>
            </div>
          </article>
          {String(wordpressInstaller?.website_id || '') === String(site.id) && renderWordPressInstaller()}
          {nginxCustomEditing?.id === site.id && renderNginxEditor()}
          {logViewer?.id === site.id && renderWebsiteLogViewer()}
          {terminalViewer?.id === site.id && renderWebsiteTerminal()}
          </div>)}
        </div>
      </section>
    </>;
  }

  function renderSsl() {
    const sslLabels = {
      manual: 'Manual SSL', cloudflare: 'Wildcard (Cloudflare)', shared: `Using ${currentSite?.ssl_source_domain || ''}`,
    };
    const sslLabel = currentSite?.ssl_enabled
      ? (sslLabels[currentSite?.ssl_mode] || 'SSL Enabled')
      : 'SSL Disabled';
    const sslUpdated = currentSite?.ssl_updated_at ? new Date(currentSite.ssl_updated_at).toLocaleString() : '';
    return <section className="section">
      <h2>SSL Certificate</h2>
      <WebsiteSelect />
      {currentSite && <div className="info-box" style={{marginTop:8}}>
        <strong>{currentSite.domain}</strong>
        <span className={currentSite.ssl_enabled ? 'badge ok' : 'badge'} style={{justifySelf:'start'}}>{sslLabel}</span>
        {sslUpdated && <span className="hint">Updated {sslUpdated}</span>}
        {currentSite.ssl_mode === 'manual' && currentSite.ssl_has_ca && <span className="badge ok" style={{justifySelf:'start'}}>CA Bundle</span>}
      </div>}
      <div className="segmented ssl-mode-tabs">
        <button className={sslMode === 'letsencrypt' ? 'active' : ''} onClick={() => setSslMode('letsencrypt')}><Lock size={14}/> Let's Encrypt</button>
        <button className={sslMode === 'manual' ? 'active' : ''} onClick={() => setSslMode('manual')}><KeyRound size={14}/> Manual</button>
        <button className={sslMode === 'wildcard' ? 'active' : ''} onClick={() => setSslMode('wildcard')}><Globe size={14}/> Wildcard (Cloudflare)</button>
        <button className={sslMode === 'shared' ? 'active' : ''} onClick={() => setSslMode('shared')}><Copy size={14}/> Use existing</button>
      </div>
      {sslMode === 'letsencrypt' && <>
        <button disabled={!selectedWebsiteId || !!loading} onClick={() => enableSsl(selectedWebsiteId)} style={{marginTop:8}}><Lock size={15}/> Install / Renew SSL</button>
        <p className="hint">The domain must point to the correct VPS IP before issuing SSL.</p>
      </>}
      {sslMode === 'wildcard' && <div className="ssl-sub-form">
        <p className="hint">
          Issues <code>{cfZone.zone ? `${cfZone.zone} + *.${cfZone.zone}` : 'zone + *.zone'}</code> over
          Cloudflare DNS. Needs an API token with <strong>Zone → DNS → Edit</strong> for the zone.
        </p>
        {cfZone.has_token
          ? <p className="hint">✓ Token saved for <strong>{cfZone.zone}</strong>. Leave the field blank to reuse it.</p>
          : null}
        <input type="password" autoComplete="off" placeholder="Cloudflare API token"
          value={wildcardToken} onChange={e => setWildcardToken(e.target.value)} />
        <button disabled={!selectedWebsiteId || !!loading} onClick={installWildcardSsl}>
          <Globe size={15}/> Issue wildcard certificate
        </button>
      </div>}
      {sslMode === 'shared' && <div className="ssl-sub-form">
        <p className="hint">Point this site at another SNPanel website's certificate (e.g. a wildcard). No new certificate is issued.</p>
        {sslSources.length === 0
          ? <p className="hint">No other website has a certificate that covers <strong>{currentSite?.domain}</strong>.</p>
          : <>
            <select value={sharedSource} onChange={e => setSharedSource(e.target.value)}>
              <option value="">Select a source website…</option>
              {sslSources.map(s => <option key={s.domain} value={s.domain}>
                {s.domain}{s.wildcard ? ' (wildcard)' : ''}{s.not_after ? ` — expires ${s.not_after}` : ''}
              </option>)}
            </select>
            <button disabled={!selectedWebsiteId || !sharedSource || !!loading} onClick={installSharedSsl}>
              <Copy size={15}/> Use this certificate
            </button>
          </>}
      </div>}
      {sslMode === 'manual' && <div className="manual-ssl-grid">
        <label>
          Certificate (.crt/.pem)
          <input type="file" accept=".crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, certificate: e.target.files?.[0] || null }))} />
        </label>
        <label>
          Private key (.key/.pem)
          <input type="file" accept=".key,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, private_key: e.target.files?.[0] || null }))} />
        </label>
        <label>
          CA bundle (.ca/.crt/.pem)
          <input type="file" accept=".ca,.crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, ca_bundle: e.target.files?.[0] || null }))} />
        </label>
        <textarea rows={7} disabled={!!manualSslFiles.certificate} value={manualSslForm.certificate} onChange={e => setManualSslForm(prev => ({ ...prev, certificate: e.target.value }))} placeholder="-----BEGIN CERTIFICATE-----" />
        <textarea rows={7} disabled={!!manualSslFiles.private_key} value={manualSslForm.private_key} onChange={e => setManualSslForm(prev => ({ ...prev, private_key: e.target.value }))} placeholder="-----BEGIN PRIVATE KEY-----" />
        <textarea rows={7} disabled={!!manualSslFiles.ca_bundle} value={manualSslForm.ca_bundle} onChange={e => setManualSslForm(prev => ({ ...prev, ca_bundle: e.target.value }))} placeholder="Optional CA bundle" />
        <button className="manual-ssl-submit" disabled={!selectedWebsiteId || !!loading} onClick={installManualSsl}><Upload size={15}/> Install Manual SSL</button>
      </div>}
    </section>;
  }

  function renderDatabases() {
    function copyToClipboard(text, field) {
      const doCopy = navigator.clipboard ? navigator.clipboard.writeText(text) : new Promise((resolve, reject) => {
        try { const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); resolve(); } catch(e) { reject(e); }
      });
      doCopy.then(() => { setCopiedField(field); setTimeout(() => setCopiedField(null), 2000); }).catch(() => setError('Copy failed.'));
    }
    const dbSearchActive = !!dbSearch.trim();
    return <section className="section">
      <div className="section-title">
        <h2>Databases</h2>
        <button disabled={!!loading || dbSearching} onClick={() => loadDatabases(dbSearch, true)}><RefreshCw size={15} className={dbSearching ? 'spin' : ''}/> Refresh</button>
      </div>
      <div className="website-search-bar">
        <Search size={16}/>
        <input
          value={dbSearch}
          onChange={e => setDbSearch(e.target.value)}
          placeholder="Search by database or user name"
          aria-label="Search databases"
        />
        {dbSearch && <button className="secondary-light icon-button" type="button" onClick={() => setDbSearch('')} aria-label="Clear database search" title="Clear search"><X size={15}/></button>}
      </div>
      <div className="form-row">
        <input value={newDatabase.db_name} onChange={e => setNewDatabase(prev => ({ ...prev, db_name: e.target.value }))} placeholder="database_name" />
        <input value={newDatabase.db_user} onChange={e => setNewDatabase(prev => ({ ...prev, db_user: e.target.value }))} placeholder="db_user (default = db_name)" />
        <input value={newDatabase.db_password} onChange={e => setNewDatabase(prev => ({ ...prev, db_password: e.target.value }))} placeholder="password (min 12 chars)" />
        <button className="mini secondary-light" title="Generate random password" onClick={() => setNewDatabase(prev => ({ ...prev, db_password: generateRandomPassword() }))}><Dices size={13}/></button>
        <button disabled={!!loading || !newDatabase.db_name.trim()} onClick={createDatabase}><Plus size={15}/> Create database</button>
      </div>
      {createdDbInfo && <div className="info-box db-created-box">
        <div className="db-created-head"><strong>Database created successfully</strong><button className="mini secondary-light" onClick={() => setCreatedDbInfo(null)}><X size={13}/></button></div>
        <div className="db-created-grid">
          <label>Database</label><span>{createdDbInfo.db_name} <button className="mini secondary-light" title={copiedField === 'db_name' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_name, 'db_name')}>{copiedField === 'db_name' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
          <label>User</label><span>{createdDbInfo.db_user} <button className="mini secondary-light" title={copiedField === 'db_user' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_user, 'db_user')}>{copiedField === 'db_user' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
          <label>Password</label><span><code>{createdDbInfo.db_password}</code> <button className="mini secondary-light" title={copiedField === 'db_password' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_password, 'db_password')}>{copiedField === 'db_password' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
        </div>
      </div>}
      {databases.length === 0 && !createdDbInfo && <EmptyState icon={Database} message={dbSearchActive ? 'No databases match this search.' : 'No databases found.'} />}
      <div className="table">
        {databases.map(db => {
          return <div className="row db-row" key={db.id}>
          <span><strong>{db.db_name}</strong></span>
          <span style={{color:'var(--text-muted)'}}>{db.db_user}</span>
          <button disabled={!!loading} onClick={() => openPhpMyAdmin(db.id)}>phpMyAdmin</button>
          <button disabled={!!loading} onClick={() => downloadDatabase(db.id, db.db_name)}><Download size={14}/> SQL</button>
          <button disabled={!!loading} onClick={() => changeDbPassword(db.id)}><KeyRound size={14}/> Password</button>
          <button className="danger" disabled={!!loading} onClick={() => deleteDatabase(db.id, db.db_name)}><Trash2 size={14}/></button>
        </div>})}
      </div>
      <p className="hint">Click phpMyAdmin to sign in directly. Token expires after 60s.</p>
    </section>;
  }

  function renderCron() {
    const sitePhpVersion = cronPhpInfo.php_version || currentSite?.php_version || '';
    const sitePhpBinary = cronPhpInfo.php_binary || (sitePhpVersion ? `/usr/bin/php${sitePhpVersion}` : 'php');
    const cronExamples = [
      ['php -q cron.php', 'Path is relative to public_html.'],
      ['php cron.php >/dev/null 2>&1', 'Discard output so cron does not try to mail it.'],
      ['php cron.php >> ../logs/cron.log 2>&1', 'Keep output in a log file inside this website.'],
      ['wp cron event run --due-now', 'WP-CLI, for WordPress sites.'],
    ];
    return <section className="section">
      <div className="section-title">
        <div><h2>Cron manager</h2></div>
        <button disabled={!selectedWebsiteId || !!loading} onClick={listCron}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="cron-form">
        <WebsiteSelect />
        <input value={cronSchedule} onChange={e => setCronSchedule(e.target.value)} placeholder="*/15 * * * *" />
        <input value={cronCommand} onChange={e => setCronCommand(e.target.value)} placeholder="php -q cron.php >/dev/null 2>&1" />
        <button disabled={!selectedWebsiteId || !!loading} onClick={addCron}><Plus size={14}/> Add cron</button>
      </div>
      {selectedWebsiteId && <p className="hint">Cron runs as <strong>{cronUser || currentSite?.linux_user || 'www-data'}</strong> for the selected website.</p>}
      {selectedWebsiteId && <div className="cron-help">
        <p>
          Write <code>php</code> and SNPanel rewrites it to <code>{sitePhpBinary}</code>
          {sitePhpVersion ? <> — the PHP {sitePhpVersion} CLI this website is set to</> : null}, so the job never
          runs on the server default version. Change the website's PHP version and its cron jobs follow.
        </p>
        <ul>
          {cronExamples.map(([example, note]) => <li key={example}>
            <button type="button" className="cron-example" onClick={() => setCronCommand(example)}>{example}</button>
            <small>{note}</small>
          </li>)}
        </ul>
        <p className="cron-help-note">
          Only PHP scripts inside <code>public_html</code> and the safe WP-CLI maintenance commands are allowed.
          A trailing <code>&gt;</code>, <code>&gt;&gt;</code>, <code>2&gt;</code> or <code>2&gt;&amp;1</code> may
          redirect to <code>/dev/null</code> or to a file inside this website.
        </p>
      </div>}
      <div className="cron-list">
        {selectedWebsiteId && cronItems.length === 0 && <EmptyState icon={Clock} message="No cron jobs found for this website." />}
        {cronItems.map(item => <div className="cron-item" key={`${item.index}-${item.line}`}>
          <span className="badge">#{item.index}</span>
          <span><strong>{item.schedule}</strong><small>{item.command || item.line}</small></span>
          <button className="mini danger" disabled={!!loading} onClick={() => deleteCron(item.index)}><Trash2 size={13}/></button>
        </div>)}
      </div>
    </section>;
  }

  function renderChmodDialog() {
    const targets = chmodTarget || [];
    if (targets.length === 0) return null;
    const bits = octalToPermissionBits(chmodMode);
    const onlyDirs = targets.every(item => item.is_dir);
    const hasFiles = targets.some(item => !item.is_dir);
    const worldWritable = !!(bits.other & 2);
    const setBit = (classKey, bitValue) => setChmodMode(permissionBitsToOctal({
      ...bits,
      [classKey]: bits[classKey] ^ bitValue,
    }));
    const title = targets.length === 1 ? targets[0].name : `${targets.length} selected items`;
    return <div className="chmod-backdrop" role="presentation" onClick={() => setChmodTarget(null)}>
      <div className="chmod-dialog" role="dialog" aria-modal="true" aria-label="Change permissions" onClick={e => e.stopPropagation()}>
        <div className="chmod-head">
          <div>
            <h3><Lock size={15}/> Permissions</h3>
            <p>{title}</p>
          </div>
          <button className="mini secondary-light" onClick={() => setChmodTarget(null)} aria-label="Close"><X size={14}/></button>
        </div>
        <table className="chmod-grid">
          <thead>
            <tr><th scope="col"></th>{PERMISSION_BITS.map(bit => <th scope="col" key={bit.key}>{bit.label}</th>)}</tr>
          </thead>
          <tbody>
            {PERMISSION_CLASSES.map(group => <tr key={group.key}>
              <th scope="row">{group.label}</th>
              {PERMISSION_BITS.map(bit => <td key={bit.key}>
                <input
                  type="checkbox"
                  aria-label={`${group.label} ${bit.label}`}
                  checked={!!(bits[group.key] & bit.value)}
                  onChange={() => setBit(group.key, bit.value)}
                />
              </td>)}
            </tr>)}
          </tbody>
        </table>
        <div className="chmod-value">
          <label>
            <span>Octal</span>
            <input value={chmodMode} inputMode="numeric" maxLength={4} onChange={e => setChmodMode(e.target.value.replace(/[^0-7]/g, '').slice(0, 4))} />
          </label>
          <code>{permissionSymbols(chmodMode)}</code>
        </div>
        <div className="chmod-presets">
          {(onlyDirs ? PERMISSION_PRESETS.dir : PERMISSION_PRESETS.file).map(([preset, label]) => <button
            key={preset}
            type="button"
            className={`mini ${chmodMode === preset ? '' : 'secondary-light'}`}
            onClick={() => setChmodMode(preset)}
          >{preset} <small>{label}</small></button>)}
        </div>
        {onlyDirs && <label className="chmod-setgid">
          <input
            type="checkbox"
            checked={bits.special === 2}
            onChange={() => setChmodMode(permissionBitsToOctal({ ...bits, special: bits.special === 2 ? 0 : 2 }))}
          />
          <span>Setgid — new files inside keep the folder's group. SNPanel sets this on site folders; leave it on unless you know otherwise.</span>
        </label>}
        {worldWritable && <p className="chmod-note warn">
          <AlertCircle size={13}/> World-writable: anyone with an account on the server can change
          {hasFiles ? ' these files' : ' what is inside these folders'}. Use 755 unless something really needs it.
        </p>}
        <p className="chmod-note">
          Any permission combination is allowed. The setuid and sticky bits are not — setgid on a folder is the
          only special bit the panel sets.
        </p>
        <div className="chmod-actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => setChmodTarget(null)}>Cancel</button>
          <button disabled={!!loading} onClick={applyChmod}><Check size={14}/> Apply {chmodMode}</button>
        </div>
      </div>
    </div>;
  }

  function renderFiles() {
    const allSelected = files.length > 0 && selectedFilePaths.length === files.length;
    const selectedArchiveFile = selectedFilePaths.length === 1
      ? files.find(item => item.path === selectedFilePaths[0] && isArchiveFile(item))
      : null;
    const activeFileApp = currentFileApp();
    const targetKey = fileTargetKey();
    const visibleFileJobs = fileJobs
      .filter(job => (job.target_key || `site:${job.website_id}`) === targetKey && job.status !== 'done')
      .slice(0, 4);
    const selectedChmodItems = files.filter(item => selectedFilePaths.includes(item.path));
    return <section className="section">
      {renderChmodDialog()}
      <div className="section-title">
        <div><h2>File manager</h2></div>
        <button disabled={!hasFileTarget() || !!loading} onClick={() => listFiles(fileListPath)}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="file-manager">
        <div className="file-panel">
          <div className="file-controls">
            <FileTargetSelect />
            {activeFileApp
              ? <div className="file-meta">
                <span>Application: <strong>{activeFileApp.name}</strong></span>
                <span>Root: <strong>{activeFileApp.directory}{fileListPath ? `/${fileListPath}` : ''}</strong></span>
                {currentUser && !isAdmin && <span>Storage: <strong>{storageUsageText(currentUser)}</strong></span>}
              </div>
              : currentSite && <div className="file-meta">
                <span>Website: <strong>{currentSite.domain}</strong></span>
                <span>Root: <strong>{currentSite.root_path}{fileListPath ? `/${fileListPath}` : ''}</strong></span>
                {currentUser && !isAdmin && <span>Storage: <strong>{storageUsageText(currentUser)}</strong></span>}
              </div>}
            <div className="path-pill breadcrumb-line">
              <button className="crumb" disabled={!hasFileTarget() || fileListPath === ''} onClick={() => listFiles('')}>root</button>
              {fileBreadcrumbs(fileListPath).map(crumb => <button className="crumb" key={crumb.path} onClick={() => listFiles(crumb.path)}>{crumb.label}</button>)}
            </div>
            <div className="file-toolbar">
              <button disabled={!hasFileTarget() || fileListPath === '' || !!loading} onClick={() => listFiles(parentFilePath(fileListPath))}>Up</button>
              <button disabled={!hasFileTarget() || !!loading} onClick={makeFileDirectory}><Plus size={14}/> Folder</button>
              <button disabled={!hasFileTarget() || !!loading} onClick={makeFile}><FileText size={14}/> File</button>
              <label className={`upload-button ${(!hasFileTarget() || !!loading) ? 'disabled' : ''}`}>
                <Upload size={14}/> Upload
                <input type="file" disabled={!hasFileTarget() || !!loading} onChange={e => { uploadSiteFile(e.target.files?.[0]); e.target.value = ''; }} />
              </label>
              <select value={archiveFormat} onChange={e => setArchiveFormat(e.target.value)} disabled={!hasFileTarget() || !!loading}>
                <option value="zip">zip</option>
                <option value="tar.gz">tar.gz</option>
              </select>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={copySelectedFiles}><Copy size={14}/> Copy</button>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={moveSelectedFiles}><MoveRight size={14}/> Move</button>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={archiveSelectedFiles}><Archive size={14}/> Archive</button>
              <button disabled={!selectedArchiveFile || !!loading} onClick={() => extractArchiveFile(selectedArchiveFile.path)}><ArchiveRestore size={14}/> Extract</button>
              <button disabled={selectedChmodItems.length === 0 || !!loading} onClick={() => openChmodDialog(selectedChmodItems)}><Lock size={14}/> Permissions</button>
              <button className="danger" disabled={selectedFilePaths.length === 0 || !!loading} onClick={deleteSelectedFiles}><Trash2 size={14}/> Delete</button>
            </div>
            {visibleFileJobs.length > 0 && <div className="file-job-list">
              {visibleFileJobs.map(job => <div className={`file-job ${job.status}`} key={job.job_id}>
                <Clock size={14}/>
                <span><strong>{job.archive_path?.split('/').pop() || 'Archive'}</strong> {job.status === 'error' ? 'failed' : job.status}</span>
                {job.error && <small>{job.error}</small>}
                <button className="file-job-dismiss" onClick={() => dismissFileJob(job.job_id)} aria-label="Dismiss"><X size={13}/></button>
              </div>)}
            </div>}
          </div>
          <div className="file-list-header">
            <label><input type="checkbox" checked={allSelected} onChange={toggleAllFiles} disabled={files.length === 0} /> Select</label>
            <span>{files.length} item(s)</span>
          </div>
          <div className="file-list">
            {files.length === 0 && <div className="empty-box">No files in this folder.</div>}
            {files.map(item => <div className={`file-item ${selectedFilePaths.includes(item.path) ? 'selected' : ''}`} key={item.path}>
              <input type="checkbox" checked={selectedFilePaths.includes(item.path)} onChange={() => toggleFileSelection(item.path)} />
              <button className="file-name" onClick={() => item.is_dir ? listFiles(item.path) : (isTextEditable(item) ? openFileEditorTab(item.path) : downloadFile(item.path))}>
                {item.is_dir ? <FolderOpen size={16}/> : <FileText size={16}/>} <strong>{item.name}</strong>
              </button>
              <button
                className="file-mode"
                type="button"
                disabled={!!loading}
                title={`Permissions ${item.mode || '---'} (${permissionSymbols(item.mode)}) - click to change`}
                onClick={() => openChmodDialog(item)}
              >{item.mode || '---'}</button>
              <span className="file-size">{item.is_dir ? 'Folder' : formatBytes(item.size)}</span>
              <div className="file-row-actions">
                {!item.is_dir && <button className="mini secondary-light" disabled={!!loading} onClick={() => downloadFile(item.path)}><Download size={13}/></button>}
                {isArchiveFile(item) && <button className="mini secondary-light" disabled={!!loading} onClick={() => extractArchiveFile(item.path)}><ArchiveRestore size={13}/> Extract</button>}
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openChmodDialog(item)}><Lock size={13}/> Perms</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => renameFileItem(item)}>Rename</button>
              </div>
            </div>)}
          </div>
        </div>
      </div>
    </section>;
  }

  function renderBackups() {
    const selectedBackupUser = users.find(user => String(user.id) === String(selectedBackupUserId));
    const userNameById = id => users.find(user => String(user.id) === String(id))?.username || `User #${id}`;
    const scheduleUserLabel = item => {
      if (item.all_users) return 'All users';
      const ids = (item.user_ids && item.user_ids.length > 0) ? item.user_ids : (item.user_id ? [item.user_id] : []);
      return ids.length ? ids.map(userNameById).join(', ') : 'No users';
    };
    const jobTitle = job => ({ site_backup: 'Website backup', user_backup: 'Full user backup', sftp_backup: 'SFTP backup' }[job.kind] || 'Backup task');
    const jobDetail = job => job.error || job.remote_file || job.backup_file || job.message || job.status;
    const backupTabs = isAdmin
      ? [
        ['website', 'Backup website', Globe],
        ['user', 'Backup user', Users],
        ['schedule', 'Scheduled backups', Clock],
        ['destination', 'Backup Destination', Network],
        ['da-import', 'DA Import', ArchiveRestore],
      ]
      : [['website', 'Backup website', Globe]];
    const activeBackupTab = backupTabs.some(([id]) => id === backupTab) ? backupTab : 'website';
    const visibleBackupJobs = backupJobs.filter(job => job.status !== 'done');

    return <section className="section backups-page">
      <h2>Backups</h2>
      <div className="segmented-control backup-tabs" role="tablist" aria-label="Backup sections">
        {backupTabs.map(([id, label, Icon]) => <button
          key={id}
          type="button"
          role="tab"
          aria-selected={activeBackupTab === id}
          className={activeBackupTab === id ? 'active' : ''}
          onClick={() => setBackupTab(id)}
        ><Icon size={14}/>{label}</button>)}
      </div>
      {visibleBackupJobs.length > 0 && <div className="backup-job-list">
        {visibleBackupJobs.map(job => <div className={`backup-job ${job.status}`} key={job.job_id}>
          <Clock size={14}/>
          <span><strong>{jobTitle(job)}</strong><small>{jobDetail(job)}</small></span>
          <span className={job.status === 'done' ? 'badge ok' : job.status === 'error' ? 'badge bad' : 'badge'}>{job.status}</span>
        </div>)}
      </div>}

      {activeBackupTab === 'website' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup website</h3><p className="hint">Backups include website source files and a database SQL export.</p></div>
        </div>
        <WebsiteSelect />
        <div className="actions backup-toolbar">
          <button disabled={!selectedWebsiteId || !!loading} onClick={createBackup}><Plus size={14}/> Create backup</button>
          <button disabled={!selectedWebsiteId || !!loading} onClick={refreshBackupArea}><RefreshCw size={14}/> Refresh</button>
          <label className="upload-button">
            <Upload size={14}/> Upload backup
            <input type="file" accept=".tar.gz,application/gzip" onChange={e => { uploadBackup(e.target.files?.[0]); e.target.value = ''; }} />
          </label>
        </div>
        {backups.length === 0 && selectedWebsiteId && <EmptyState icon={Archive} message="No backups found for this website." />}
        <div className="backup-list">
          {backups.map(file => <div className="backup-item" key={file}>
            <span>{file.split('/').pop()}</span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadBackup(file)}><Download size={14}/> Download</button>
              <button disabled={!!loading} onClick={() => restoreBackup(file)}><RotateCcw size={14}/> Restore</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteBackup(file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'user' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup user</h3><p className="hint">Includes the panel user, all owned websites, source files, database dumps, and restore metadata.</p></div>
          <button disabled={!!loading} onClick={refreshUserBackupArea}><RefreshCw size={14}/> Reload</button>
        </div>
        <div className="sftp-run-row user-backup-row backup-run-row">
          <select value={selectedBackupUserId} onChange={e => setSelectedBackupUserId(e.target.value)}>
            <option value="">Select user</option>
            {users.map(user => <option key={user.id} value={user.id}>{user.username}</option>)}
          </select>
          <select value={selectedSftpTargetId} onChange={e => setSelectedSftpTargetId(e.target.value)}>
            <option value="">Local only</option>
            {sftpTargets.map(target => <option key={target.id} value={target.id}>{target.name}</option>)}
          </select>
          <button disabled={!selectedBackupUserId || !!loading} onClick={createUserBackup}><Archive size={14}/> Create backup</button>
        </div>
        {selectedBackupUser && <p className="hint">Current user: <strong>{selectedBackupUser.username}</strong></p>}
        <div className="actions backup-subactions">
          <button disabled={!selectedBackupUserId || !!loading} onClick={() => listUserBackups()}><RefreshCw size={14}/> Refresh list</button>
        </div>
        {selectedBackupUserId && userBackups.length === 0 && <EmptyState icon={Archive} message="No user backups found." />}
        <div className="backup-list">
          {userBackups.map(file => <div className="backup-item" key={file}>
            <span>{file.split('/').pop()}</span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadUserBackup(file)}><Download size={14}/> Download</button>
              <button disabled={!!loading} onClick={() => restoreUserBackup(file)}><RotateCcw size={14}/> Restore user</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteUserBackup(file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>

        <div className="section-title restore-title backup-panel-heading backup-subtitle">
          <div><h3>Restore folder</h3><p className="hint">{restoreBackupDir || '/var/backups/snpanel/users/restore'}</p></div>
          <div className="actions">
            <button disabled={!!loading} onClick={loadRestoreBackups}><RefreshCw size={14}/> Refresh</button>
            <label className="upload-button">
              <Upload size={14}/> Upload backups
              <input type="file" multiple accept=".tar.gz,application/gzip" onChange={e => { uploadUserBackups(e.target.files); e.target.value = ''; }} />
            </label>
          </div>
        </div>
        <div className="backup-list">
          {restoreBackups.map(item => <div className="backup-item" key={item.backup_file}>
            <span>{item.filename || item.backup_file.split('/').pop()}<small>{item.valid ? `${item.source === 'opanel' ? 'opanel · ' : ''}${item.username || 'unknown user'} - ${item.websites || 0} website(s)` : (item.error || 'Invalid backup')}</small></span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadUserBackup(item.backup_file)}><Download size={14}/> Download</button>
              <button disabled={!!loading || !item.valid} onClick={() => restoreUserBackup(item.backup_file)}><RotateCcw size={14}/> Restore user</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteRestoreBackup(item.backup_file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>

      </div>}

      {isAdmin && activeBackupTab === 'schedule' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Scheduled backups</h3><p className="hint">Run full user backups automatically with optional off-server destination.</p></div>
          <button disabled={!!loading} onClick={refreshScheduledBackupArea}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="sftp-form schedule-form backup-schedule-form">
          <label className="schedule-toggle">
            <input type="checkbox" checked={!!newBackupSchedule.all_users} onChange={e => setNewBackupSchedule(prev => ({ ...prev, all_users: e.target.checked }))} />
            <span>All users</span>
          </label>
          <select multiple value={newBackupSchedule.user_ids || []} disabled={!!newBackupSchedule.all_users} onChange={e => setNewBackupSchedule(prev => ({ ...prev, user_ids: Array.from(e.target.selectedOptions, option => option.value) }))}>
            {users.map(user => <option key={user.id} value={String(user.id)}>{user.username}</option>)}
          </select>
          <input value={newBackupSchedule.schedule} onChange={e => setNewBackupSchedule(prev => ({ ...prev, schedule: e.target.value }))} placeholder="0 2 * * *" />
          <select value={newBackupSchedule.target_id} onChange={e => setNewBackupSchedule(prev => ({ ...prev, target_id: e.target.value }))}>
            <option value="">Local only</option>
            {sftpTargets.map(target => <option key={target.id} value={target.id}>{target.name}</option>)}
          </select>
          <button disabled={(!newBackupSchedule.all_users && (!newBackupSchedule.user_ids || newBackupSchedule.user_ids.length === 0)) || !!loading} onClick={createBackupSchedule}><Clock size={14}/> Schedule</button>
        </div>
        <div className="backup-list">
          {backupSchedules.map(item => {
            const scheduleTarget = sftpTargets.find(target => target.id === item.target_id);
            return <div className="backup-item" key={item.id}>
              <span>{scheduleUserLabel(item)} - {item.schedule}{scheduleTarget ? ` - ${scheduleTarget.name}` : ''}<small>{item.last_status}: {item.last_message || 'not run yet'}</small></span>
              <button className="danger" disabled={!!loading} onClick={() => deleteBackupSchedule(item.id)}><Trash2 size={14}/></button>
            </div>;
          })}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'destination' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup Destination</h3><p className="hint">Manage SFTP destinations used for off-server backup copies.</p></div>
          <button disabled={!!loading} onClick={loadSftpTargets}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="sftp-form sftp-target-form">
          <input value={newSftpTarget.name} onChange={e => setNewSftpTarget(prev => ({ ...prev, name: e.target.value }))} placeholder="Target name" />
          <input value={newSftpTarget.host} onChange={e => setNewSftpTarget(prev => ({ ...prev, host: e.target.value }))} placeholder="Host" />
          <input value={newSftpTarget.port} onChange={e => setNewSftpTarget(prev => ({ ...prev, port: e.target.value }))} placeholder="22" inputMode="numeric" />
          <input value={newSftpTarget.username} onChange={e => setNewSftpTarget(prev => ({ ...prev, username: e.target.value }))} placeholder="Username" />
          <input value={newSftpTarget.password} onChange={e => setNewSftpTarget(prev => ({ ...prev, password: e.target.value }))} placeholder="Password" type="password" />
          <input value={newSftpTarget.remote_path} onChange={e => setNewSftpTarget(prev => ({ ...prev, remote_path: e.target.value }))} placeholder="/backups/snpanel" />
          <textarea value={newSftpTarget.private_key} onChange={e => setNewSftpTarget(prev => ({ ...prev, private_key: e.target.value }))} placeholder="Private key (optional)" rows={4} />
          <button disabled={!!loading || !newSftpTarget.name || !newSftpTarget.host || !newSftpTarget.username || (!newSftpTarget.password && !newSftpTarget.private_key)} onClick={createSftpTarget}><Plus size={14}/> Save target</button>
        </div>
        {sftpTargets.length === 0 && <EmptyState icon={Network} message="No backup destinations found." />}
        <div className="backup-list">
          {sftpTargets.map(target => <div className="backup-item" key={target.id}>
            <span>{target.name} - {target.username}@{target.host}:{target.remote_path}</span>
            <button className="danger" disabled={!!loading} onClick={() => deleteSftpTarget(target.id)}><Trash2 size={14}/></button>
          </div>)}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'da-import' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>DirectAdmin Import</h3><p className="hint">Import websites, databases, and users from a DirectAdmin backup archive.</p></div>
          <button disabled={!!loading} onClick={() => listDaBackups()}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="da-toolbar">
          <label className="upload-button">
            <Upload size={14}/> Upload DA backup
            <input ref={daFileInputRef} type="file" accept=".tar.zst,.tzst,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,.tar" onChange={e => { uploadDaBackup(e.target.files?.[0]); e.target.value = ''; }} />
          </label>
          <label className="da-toggle">
            <input type="checkbox" checked={daReplaceExisting} onChange={e => setDaReplaceExisting(e.target.checked)} />
            Replace existing users/websites
          </label>
        </div>
        {daReplaceExisting && <p className="hint da-warn">
          Imports will delete any existing panel user, website, files and databases that share a name with the backup. Leave this off to have conflicting imports stop instead.
        </p>}
        {daBackups.length === 0 && <EmptyState icon={ArchiveRestore} message="No DirectAdmin backups uploaded. Upload a DA backup archive to get started." />}
        {daBackups.length > 0 && <>
          <div className="da-list-head">
            <label className="da-toggle">
              <input type="checkbox" checked={selectedDaBackups.length === daBackups.length && daBackups.length > 0} onChange={toggleSelectAllDaBackups} />
              Select all ({daBackups.length})
            </label>
            {selectedDaBackups.length > 0 && <div className="da-actions">
              <button disabled={!!loading} onClick={() => bulkImportDaBackups()} className="primary"><ArchiveRestore size={14}/> Restore selected ({selectedDaBackups.length})</button>
              <button disabled={!!loading} onClick={bulkDeleteDaBackups} className="danger"><Trash2 size={14}/> Delete selected ({selectedDaBackups.length})</button>
            </div>}
          </div>
          <div className="backup-list">
            {daBackups.map(file => <div className={`backup-item da-backup-row${selectedDaBackups.includes(file.path) ? ' selected' : ''}`} key={file.path}>
              <label className="da-backup-pick">
                <input type="checkbox" checked={selectedDaBackups.includes(file.path)} onChange={() => toggleDaBackupSelect(file.path)} />
                <span>{file.filename}<small>{(file.size / (1024 * 1024)).toFixed(1)} MB</small></span>
              </label>
              <div className="da-actions">
                <button disabled={!!loading} onClick={() => scanDaBackup(file.path)}><Search size={14}/> Scan</button>
                <button disabled={!!loading} onClick={() => importDaBackup(file.path)}><ArchiveRestore size={14}/> Import</button>
                <button className="danger" disabled={!!loading} onClick={() => deleteDaBackup(file.path)}><Trash2 size={14}/></button>
              </div>
            </div>)}
          </div>
        </>}

        {daScanResult && <div className="da-scan-result">
          <h4>Scan result: {daScanResult.filename}</h4>
          {daScanResult.errors?.length > 0 && <div className="error-list">
            {daScanResult.errors.map((err, i) => <p key={i} className="error-text">{err}</p>)}
          </div>}
          {daScanResult.users?.map((user, i) => <div key={i} className="da-user-block">
            <p className="da-user-head"><Users size={13}/> <strong>{user.username}</strong>{user.email && <small>{user.email}</small>}</p>
            {user.domains?.length > 0 && <div className="da-table-wrap">
              <table className="da-scan-table">
                <thead><tr><th>Domain</th><th>Type</th><th>Files</th><th>Database</th><th>SQL dump</th><th>Pointers</th></tr></thead>
                <tbody>
                  {user.domains.map((d, j) => <tr key={j}>
                    <td><Globe size={12}/> {d.domain}</td>
                    <td>{d.app_type}</td>
                    <td>{d.has_files ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                    <td>{d.db_name || <span className="da-muted">—</span>}</td>
                    <td>{d.has_sql_dump ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                    <td>{d.aliases?.length > 0 ? d.aliases.map(a => `${a.domain} (${a.mode})`).join(', ') : <span className="da-muted">—</span>}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>}
            {user.databases?.length > 0 && <div className="da-table-wrap">
              <p className="hint">Unassigned databases ({user.databases.length})</p>
              <table className="da-scan-table">
                <thead><tr><th>Database</th><th>SQL dump</th></tr></thead>
                <tbody>
                  {user.databases.map((db, j) => <tr key={j}>
                    <td><Database size={12}/> {db.db_name}</td>
                    <td>{db.has_sql_dump ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>}
          </div>)}
        </div>}

        {daImportJob && <div className={`backup-job da-job ${daImportJob.status}`}>
          <Clock size={14}/>
          <span><strong>DA Import</strong><small>{daImportJob.archive || ''}</small></span>
          <span className={daImportJob.status === 'completed' ? 'badge ok' : daImportJob.status === 'failed' ? 'badge bad' : 'badge'}>{daImportJob.status}</span>
        </div>}
        {daImportJob?.status === 'completed' && daImportJob.result?.summary && <div className="da-scan-result">
          <h4>Import summary</h4>
          {daImportJob.result.summary.map((item, i) => <div key={i} className="da-user-block">
            <p className="da-user-head"><strong>{item.username}</strong> <span className="badge ok">{item.imported_domains?.length || 0} domain(s)</span> <span className="badge">{item.databases?.length || 0} database(s)</span></p>
            {item.aliases?.length > 0 && <p className="hint">Pointers: {item.aliases.join(', ')}</p>}
            {item.ssl_enabled_domains?.length > 0 && <p className="hint">SSL enabled: {item.ssl_enabled_domains.join(', ')}</p>}
            {item.warnings?.length > 0 && <p className="hint da-warn">Warnings: {item.warnings.join('; ')}</p>}
          </div>)}
          {daImportJob.result.credentials && <details className="da-creds-details">
            <summary>Generated credentials (click to show)</summary>
            <pre className="da-credentials">{daImportJob.result.credentials.join('\n')}</pre>
          </details>}
        </div>}

        {daBulkImportJob && <div className={`backup-job da-job ${daBulkImportJob.status}`}>
          <Clock size={14}/>
          <span><strong>Bulk restore</strong><small>{daBulkImportJob.status === 'running' ? `Processing ${daBulkImportJob.current + 1}/${daBulkImportJob.total}: ${daBulkImportJob.current_archive}` : `${daBulkImportJob.total} backup(s)`}</small></span>
          <span className={daBulkImportJob.status === 'completed' ? 'badge ok' : 'badge'}>{daBulkImportJob.status === 'running' ? `${daBulkImportJob.current}/${daBulkImportJob.total}` : daBulkImportJob.status}</span>
        </div>}
        {daBulkImportJob?.status === 'completed' && daBulkImportJob.results && <div className="da-scan-result">
          <h4>Bulk restore results</h4>
          {daBulkImportJob.results.map((item, i) => <div key={i} className={`da-user-block ${item.status === 'completed' ? 'ok' : 'bad'}`}>
            <p className="da-user-head"><strong>{item.archive}</strong> <span className={item.status === 'completed' ? 'badge ok' : 'badge bad'}>{item.status}</span></p>
            {item.result?.summary?.map((s, j) => <p key={j} className="hint">{s.username}: {s.imported_domains?.length || 0} domain(s), {s.databases?.length || 0} db(s)</p>)}
            {item.result?.credentials && <details className="da-creds-details">
              <summary>Credentials</summary>
              <pre className="da-credentials">{item.result.credentials.join('\n')}</pre>
            </details>}
            {item.error && <p className="error-text">{item.error}</p>}
          </div>)}
        </div>}
      </div>}
    </section>;
  }

  function renderServices() {
    return <section className="section">
      <div className="section-title">
        <h2>Services Status</h2>
        <button disabled={!!loading} onClick={checkAllServices}><RefreshCw size={15}/> Refresh</button>
      </div>
      <div className="service-grid">
        {serviceNames.map(name => {
          const state = serviceStates[name];
          const text = `${state?.stdout || ''} ${state?.stderr || ''}`;
          const active = text.includes('active (running)');
          const inactive = text.includes('inactive') || text.includes('failed');
          return <div className="service-card" key={name}>
            <div><strong>{name}</strong><span className={active ? 'badge ok' : inactive ? 'badge bad' : 'badge'}>{active ? 'Running' : inactive ? 'Stopped' : '...'}</span></div>
            <small>Auto-refreshes every 10s</small>
            {isAdmin && <div className="service-actions">
              <button onClick={() => runServiceAction(name, 'start')}><Play size={13}/> Start</button>
              {!['snpanel-api', 'redis-server'].includes(name) && <button onClick={() => runServiceAction(name, 'stop')}><Square size={13}/> Stop</button>}
              <button onClick={() => runServiceAction(name, 'restart')}><RotateCcw size={13}/> Restart</button>
            </div>}
          </div>;
        })}
      </div>
    </section>;
  }

  function renderPhpConfig() {
    if (!isAdmin) return <section className="section"><h2>PHP config</h2><p className="hint">You do not have permission to edit PHP config.</p></section>;
    const notInstalled = sortPhpVersions(phpVersions.supported.filter(v => !phpVersions.installed.includes(v)));
    // The only thing worth an administrator's attention: settings Auto tune
    // would actually change. A row that already matches, or one pinned by the
    // form below (it always wins - PHP reads it last), is not a decision to
    // make, so it does not belong in a list someone has to read every time.
    const tuneChanges = (phpTune?.settings || []).filter(row => row.changes && !row.overridden_value);
    // Every pool on a server is sized from the same CPU/RAM/pool-count budget,
    // so they normally all carry identical numbers - a row per pool (this test
    // box alone has 49) is a wall of the same four numbers repeated. Collapse
    // to "N/N pools run X", and only list the ones that do not match: those are
    // the only ones worth an administrator's attention.
    const poolKey = p => `${p.max_children}|${p.idle_timeout}|${p.max_requests}|${p.request_terminate_timeout}`;
    const poolGroups = {};
    (phpTune?.pools || []).forEach(p => { (poolGroups[poolKey(p)] ||= []).push(p); });
    const [commonPools, ...restPoolGroups] = Object.values(poolGroups).sort((a, b) => b.length - a.length);
    const poolOutliers = restPoolGroups.flat();
    return <section className="section">
      <div className="section-title">
        <div><h2>PHP Configuration</h2></div>
      </div>
      <div className="user-create-card">
        <label><span>PHP version</span><select value={phpConfig.php_version} onChange={e => { const v = e.target.value; setPhpConfig(prev => ({ ...prev, php_version: v })); loadPhpConfig(v); loadPhpTune(v); }}>
          {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
        </select></label>
        <label><span>display_errors</span><select value={phpConfig.display_errors} onChange={e => setPhpConfig(prev => ({ ...prev, display_errors: e.target.value }))}>
          <option value="Off">Off (production)</option><option value="On">On (debug)</option>
        </select></label>
        <label><span>max_execution_time</span><input type="number" value={phpConfig.max_execution_time} onChange={e => setPhpConfig(prev => ({ ...prev, max_execution_time: e.target.value }))} /></label>
        <label><span>max_input_time</span><input type="number" value={phpConfig.max_input_time} onChange={e => setPhpConfig(prev => ({ ...prev, max_input_time: e.target.value }))} /></label>
        <label><span>max_input_vars</span><input type="number" value={phpConfig.max_input_vars} onChange={e => setPhpConfig(prev => ({ ...prev, max_input_vars: e.target.value }))} /></label>
        <label><span>memory_limit</span><input value={phpConfig.memory_limit} onChange={e => setPhpConfig(prev => ({ ...prev, memory_limit: e.target.value }))} placeholder="1024M" /></label>
        <label><span>post_max_size</span><input value={phpConfig.post_max_size} onChange={e => setPhpConfig(prev => ({ ...prev, post_max_size: e.target.value }))} placeholder="1024M" /></label>
        <label><span>upload_max_filesize</span><input value={phpConfig.upload_max_filesize} onChange={e => setPhpConfig(prev => ({ ...prev, upload_max_filesize: e.target.value }))} placeholder="1024M" /></label>
        <button className="secondary-light" disabled={!!loading} onClick={restorePhpDefaults}><RotateCcw size={14}/> Restore defaults</button>
        <button disabled={!!loading} onClick={updatePhpConfig}>Save</button>
        {phpTune && tuneChanges.length > 0 && <div className="php-tune-diff">
          <strong><AlertCircle size={14}/> Auto tune PHP {phpTune.php_version} sẽ đổi {tuneChanges.length} thông số</strong>
          <span>{tuneChanges.map(row => `${row.key} ${row.current || 'chưa đặt'} → ${row.value}`).join(', ')}.</span>
          <button className="mini" disabled={!!loading} onClick={applyPhpTune}>Auto tune PHP</button>
        </div>}
        {phpTune && tuneChanges.length === 0 && <div className="notice php-tune-diff">
          <Check size={14}/> PHP {phpTune.php_version} đã khớp khuyến nghị auto tune cho máy này ({phpTune.facts.cpu_count} CPU, {phpTune.facts.total_memory_mb} MB RAM).
        </div>}
      </div>
      {phpTune && <div className="php-tune" style={{ marginTop: 16 }}>
        <div className="php-tune-actions">
          <button disabled={!!loading} onClick={applyPhpTune}><Cpu size={14}/> Auto tune PHP</button>
          <button className="secondary-light" disabled={!!loading} onClick={toggleOpcache}>
            {phpTune.opcache_enabled
              ? <><Ban size={14}/> Tắt OPcache (PHP {phpTune.php_version})</>
              : <><Play size={14}/> Bật OPcache (PHP {phpTune.php_version})</>}
          </button>
        </div>
        {phpTuneApplied && <div className="notice php-tune-result">
          <strong><Check size={14}/> Đã tối ưu PHP {phpTune.php_version} xong.</strong>
        </div>}
        {commonPools && <p className="hint">
          Pool PHP-FPM: {commonPools.length}/{phpTune.pools.length} pool đang chạy pm.max_children={commonPools[0].max_children || '—'},
          idle {commonPools[0].idle_timeout || '—'}, tối đa {commonPools[0].max_requests || '—'} request/tiến trình.
          {poolOutliers.length > 0 && ` ${poolOutliers.length} pool khác đang chạy thông số khác:`}
        </p>}
        {poolOutliers.length > 0 && <ul className="php-tune-pool-outliers">
          {poolOutliers.map(p => <li key={p.pool}>
            <code>{p.pool}</code>
            <span>pm.max_children={p.max_children || '—'}, idle {p.idle_timeout || '—'}, tối đa {p.max_requests || '—'} request</span>
          </li>)}
        </ul>}
      </div>}
      {notInstalled.length > 0 && <div className="user-create-card" style={{ marginTop: 16 }}>
        <h3>Install PHP</h3>
        <div className="php-install-grid">
          {notInstalled.map(v => <button key={v} disabled={!!loading} onClick={() => installPhpVersion(v)}>+ PHP {v}</button>)}
        </div>
      </div>}
    </section>;
  }

  function renderFirewall() {
    if (!isAdmin) return <section className="section"><h2>Firewall</h2><p className="hint">No permission.</p></section>;
    const firewallText = firewallStatus?.stdout || firewallStatus?.stderr || 'Click Refresh to load status.';
    const blocklistText = firewallBlocklists?.stdout || firewallBlocklists?.stderr || 'No blocklist status loaded.';
    const blocklistUrls = parseFirewallBlocklistUrls(blocklistText);
    const allRules = firewallStatus?.rules || [];
    const userRules = allRules.filter(rule => !rule.protected);
    const panelRules = allRules.filter(rule => rule.protected);
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Firewall (iptables + ipset)</h2><p className="hint">SSH, the panel port and 80/443/465/587 are always kept open.</p></div>
        </div>
        <div className="actions">
          <button disabled={!!loading} onClick={loadFirewall}><RefreshCw size={14}/> Refresh</button>
          <button disabled={!!loading} onClick={enableFirewall}><Shield size={14}/> Enable</button>
          <button disabled={!!loading} onClick={disableFirewall}>Disable</button>
          <button disabled={!!loading} onClick={reloadFirewall}>Reload</button>
        </div>
        {panelRules.length > 0 && <p className="hint">Protected ports: {panelRules.map(rule => rule.to).join(', ')}</p>}
        {userRules.length > 0 && <div className="table firewall-rule-table">
          {userRules.map(rule => <div className="firewall-rule" key={rule.id}>
            <span>
              <strong>#{rule.id}</strong>{' '}
              <span className={rule.action === 'DENY' ? 'badge danger' : 'badge ok'}>{rule.action}</span>{' '}
              {rule.to} from {rule.from}
            </span>
            <div className="firewall-rule-actions">
              <button className="danger" disabled={!!loading} onClick={() => deleteFirewallRule(rule.id)}><Trash2 size={14}/> Delete</button>
            </div>
          </div>)}
        </div>}
        {userRules.length === 0 && <p className="hint">No custom rules yet. Only the protected ports are open.</p>}
        <div className="info-box firewall-status">
          <strong>Firewall status</strong>
          <pre>{firewallText}</pre>
          <div className="firewall-delete-inline">
            <label><span>Delete rule #</span><input value={firewallDeleteNumber} onChange={e => setFirewallDeleteNumber(e.target.value)} placeholder="12" inputMode="numeric" /></label>
            <button className="danger" disabled={!!loading || !firewallDeleteNumber} onClick={() => deleteFirewallRule()}>Delete</button>
          </div>
        </div>
      </section>
      <section className="section">
        <h2>Open port</h2>
        <div className="firewall-form">
          <label><span>Port</span><input value={firewallPort} onChange={e => setFirewallPort(e.target.value)} placeholder="80" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallProtocol} onChange={e => setFirewallProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button disabled={!!loading || !firewallPort} onClick={openFirewallPort}>Open port</button>
        </div>
      </section>
      <section className="section">
        <h2>Allow IP</h2>
        <div className="firewall-form">
          <label><span>IP / CIDR</span><input value={firewallAllowIp} onChange={e => setFirewallAllowIp(e.target.value)} placeholder="1.2.3.4" /></label>
          <label><span>Port (optional)</span><input value={firewallAllowPort} onChange={e => setFirewallAllowPort(e.target.value)} placeholder="22" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallAllowProtocol} onChange={e => setFirewallAllowProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button disabled={!!loading || !firewallAllowIp} onClick={allowFirewallIp}>Allow</button>
        </div>
      </section>
      <section className="section">
        <h2>Block IP</h2>
        <div className="firewall-form">
          <label><span>IP / CIDR</span><input value={firewallBlockIp} onChange={e => setFirewallBlockIp(e.target.value)} placeholder="5.6.7.8" /></label>
          <label><span>Port (optional)</span><input value={firewallBlockPort} onChange={e => setFirewallBlockPort(e.target.value)} placeholder="All ports" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallBlockProtocol} onChange={e => setFirewallBlockProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button className="danger" disabled={!!loading || !firewallBlockIp} onClick={blockFirewallIp}>Block</button>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>IP blocklist URLs</h2><p className="hint">TXT files are fetched daily at 01:00 into an ipset, so even million-entry lists cost one kernel lookup per packet.</p></div>
          <button disabled={!!loading} onClick={loadFirewallBlocklists}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="firewall-form firewall-blocklist-form">
          <label><span>TXT URL</span><input value={firewallBlocklistUrl} onChange={e => setFirewallBlocklistUrl(e.target.value)} placeholder="https://example.com/blocklist.txt" /></label>
          <button disabled={!!loading || !firewallBlocklistUrl.trim()} onClick={addFirewallBlocklistUrl}><Plus size={14}/> Add URL</button>
          <button className="secondary-light" disabled={!!loading} onClick={updateFirewallBlocklistsNow}><RefreshCw size={14}/> Update now</button>
        </div>
        {blocklistUrls.length > 0 && <div className="table firewall-blocklist-table">
          {blocklistUrls.map(url => <div className="firewall-rule" key={url}>
            <span>{url}</span>
            <div className="firewall-rule-actions"><button className="danger" disabled={!!loading} onClick={() => deleteFirewallBlocklistUrl(url)}><Trash2 size={14}/> Delete</button></div>
          </div>)}
        </div>}
        <div className="info-box firewall-status"><strong>IP blocklist status</strong><pre>{blocklistText}</pre></div>
      </section>
    </>;
  }

  function renderWaf() {
    const statusText = wafRules.status?.stdout || wafRules.status?.stderr || 'Click Refresh to load WAF status.';
    // The effective list, not the site's own: a site with nothing of its own
    // still enforces the global list, and reporting "No bots" for it was a lie.
    const rowFor = id => botBlocks?.websites?.find(w => w.website_id === id);
    const botCountFor = id => (rowFor(id)?.effective_blocked_bots || []).length;
    const ownCountFor = id => (rowFor(id)?.blocked_bots || []).length;
    return <>
      <section className="section">
        <div className="section-title">
          <div>
            <h2>WAF</h2>
            <p className="hint">{isAdmin
              ? 'Engine status and per-website protection. Open a website to configure its rules, flood limits and blocked bots.'
              : 'Protection for your websites. Open one to configure its rules and blocked bots.'}</p>
          </div>
          <button disabled={!!loading} onClick={() => { loadBotBlocks(); if (isAdmin) { loadWafRules(); loadCrs(); } }}><RefreshCw size={14}/> Refresh</button>
        </div>
        {isAdmin && <div className="info-box firewall-status"><strong>Status</strong><pre>{statusText}</pre></div>}
      </section>

      {isAdmin && <section className="section">
        <div className="section-title">
          <div>
            <h2>OWASP Core Rule Set</h2>
            <p className="hint">
              SNPanel's own rules block known bad paths. CRS inspects the payload - SQL injection, XSS,
              command injection - and scores each request instead of refusing on a single match.
              Off by default because CRS needs tuning against real traffic before it can be trusted to block.
            </p>
          </div>
          <button disabled={!!loading} onClick={loadCrs}><RefreshCw size={14}/> Check</button>
        </div>
        {!crs && <p className="hint">Click Check to read the current state.</p>}
        {crs && <>
          <div className="waf-overview-badges" style={{ marginBottom: 12 }}>
            <span className={crs.mode === 'block' ? 'badge ok' : 'badge'}>
              {crs.mode === 'off' ? 'Off' : (crs.mode === 'detect' ? 'Detect only' : 'Blocking')}
            </span>
            <span className={crs.installed ? 'badge ok' : 'badge'}>
              {crs.installed ? `${crs.rule_files} rule file(s) installed` : 'Not installed'}
            </span>
            <span className="badge">{crs.sites_opted_in ?? 0} site(s) opted in</span>
            <span className="badge">nginx now: {crs.nginx_pss_mb || 0} MB</span>
            <span className={(crs.ram_available_mb || 0) < 1024 ? 'badge danger' : 'badge'}>
              {crs.ram_available_mb || 0} MB RAM free
            </span>
          </div>
          <div className="info-box" style={{ marginBottom: 12 }}>
            <strong>Memory</strong>
            <p className="hint">
              Each site that loads CRS adds its own copy of the rule set, so the cost grows with the
              number opted in — roughly {crs.rss_mb_per_site || 50} MB each. "nginx now" above is measured on this
              server, not estimated, and it is the figure to act on; watch it and the free-RAM figure
              beside it as you opt sites in. Note that `ps` reports several times this, because it
              counts pages the nginx workers share once for each worker.
            </p>
          </div>
          <div className="segmented-control">
            {[['off', 'Off'], ['detect', 'Detect only'], ['block', 'Block']].map(([value, label]) => (
              <button
                key={value}
                className={crs.mode === value ? 'active' : ''}
                disabled={!!loading || crs.mode === value}
                onClick={() => saveCrsMode(value)}
              >{label}</button>
            ))}
          </div>
          <p className="hint" style={{ marginTop: 10 }}>
            {crs.mode === 'off' && 'Nothing from CRS is loaded. Payload attacks are not inspected.'}
            {crs.mode === 'detect' && 'Every CRS rule runs and nothing is refused. Each request that Block mode would have stopped is recorded in /var/log/nginx/snpanel-modsec-audit.log, with the rule IDs that scored it. Read that for a while, add exceptions per site, then switch to Block.'}
            {crs.mode === 'block' && 'Requests scoring above the threshold are refused on every site with the WAF on. Add SecRuleRemoveById <id> to a site’s custom rules to excuse it from one rule.'}
          </p>
          {crs.mode !== 'off' && crs.panel_mode !== crs.mode && (
            <p className="hint">Panel setting says "{crs.panel_mode}" but the server reports "{crs.mode}".</p>
          )}
          <p className="hint">
            This is the server-wide switch. Which sites load CRS is chosen per website below.
          </p>
        </>}
      </section>}

      <section className="section">
        <div className="section-title"><h2>Websites</h2></div>
        {websites.length === 0 && <EmptyState icon={Globe} message="No websites yet." />}
        <div className="table waf-overview-list">
          {websites.map(site => {
            const bots = botCountFor(site.id);
            const crsRow = (crs?.websites || []).find(w => w.website_id === site.id);
            const crsOn = !!crsRow?.crs_enabled;
            const crsLive = crsOn && site.waf_enabled && crs?.mode && crs.mode !== 'off';
            return <div className="waf-overview-row" key={site.id}>
              <span className="waf-overview-domain"><strong>{site.domain}</strong></span>
              <div className="waf-overview-badges">
                <span className={site.waf_enabled ? 'badge ok' : 'badge'}>{site.waf_enabled ? 'WAF on' : 'WAF off'}</span>
                <span
                  className={crsLive ? 'badge ok' : 'badge'}
                  title={crsOn && !crsLive ? 'Opted in, but CRS is off server-wide' : ''}
                >{crsOn ? (crsLive ? `CRS ${crs.mode}` : 'CRS pending') : 'CRS off'}</span>
                <span className={site.http_flood_enabled ? 'badge ok' : 'badge'}>{site.http_flood_enabled ? 'Flood on' : 'Flood off'}</span>
                <span
                  className={bots > 0 ? 'badge ok' : 'badge'}
                  title={ownCountFor(site.id) > 0 ? `${ownCountFor(site.id)} set on this site, the rest from the global list` : 'All from the global list'}
                >{bots > 0 ? `${bots} bot(s)` : 'No bots'}</span>
              </div>
              <button disabled={!!loading} onClick={() => openWafSite(site.id)}><SettingsIcon size={14}/> Configure</button>
            </div>;
          })}
        </div>
      </section>

      {isAdmin && <section className="section">
        <div className="section-title">
          <div>
            <h2>Global bad bots</h2>
            <p className="hint">
              Blocked on every website on this server. A site can add more of its own from its page.
              {globalBots.length > 0 ? ` Currently ${globalBots.length} bot(s).` : ' Nothing blocked globally yet.'}
            </p>
          </div>
          <button disabled={!!loading} onClick={() => setBulkBotOpen(open => !open)}>{bulkBotOpen ? 'Hide' : 'Edit'}</button>
        </div>

        {bulkBotOpen && <div className="global-bots">
          <div className="global-bots-add">
            <input
              value={newBotName}
              placeholder="Add one bot, e.g. Amazonbot"
              onChange={e => setNewBotName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { addGlobalBots(newBotName); setNewBotName(''); } }}
            />
            <button type="button" disabled={!newBotName.trim()} onClick={() => { addGlobalBots(newBotName); setNewBotName(''); }}>
              <Plus size={14}/> Add
            </button>
            <input
              className="global-bots-filter"
              value={globalBotFilter}
              placeholder="Filter the list"
              onChange={e => setGlobalBotFilter(e.target.value)}
            />
          </div>

          <div className="global-bots-list">
            {globalBots.length === 0 && <p className="hint">No bots yet. Add one above, or paste a list below.</p>}
            {globalBots
              .filter(name => !globalBotFilter.trim() || name.toLowerCase().includes(globalBotFilter.trim().toLowerCase()))
              .map(name => <span className="global-bot-chip" key={name}>
                <code>{name}</code>
                <button
                  type="button"
                  title={`Remove ${name}`}
                  onClick={() => setGlobalBots(prev => prev.filter(n => n !== name))}
                ><X size={12}/></button>
              </span>)}
          </div>

          <details className="global-bots-paste">
            <summary>Paste a list</summary>
            <textarea
              className="code-editor"
              rows={6}
              spellCheck={false}
              value={globalBotPaste}
              onChange={e => setGlobalBotPaste(e.target.value)}
              placeholder={'AhrefsBot\nSemrushBot\nMJ12bot'}
            />
            <button type="button" disabled={!globalBotPaste.trim()} onClick={() => { addGlobalBots(globalBotPaste); setGlobalBotPaste(''); }}>
              <Plus size={14}/> Add to list
            </button>
          </details>

          <div className="global-bots-actions">
            <button disabled={!!loading} onClick={() => saveGlobalBots(globalBots)}>
              <Shield size={14}/> Save and apply to all {websites.length} website(s)
            </button>
            <button
              className="secondary-light"
              disabled={!!loading}
              onClick={() => setGlobalBots(botBlocks?.global_blocked_bots || [])}
            >Reset</button>
            <span className="hint">
              {globalBots.length} bot(s)
              {botBlocks?.max_bots ? ` - max ${botBlocks.max_bots}` : ''}
              {JSON.stringify(globalBots) !== JSON.stringify(botBlocks?.global_blocked_bots || []) ? ' - unsaved changes' : ''}
            </span>
          </div>
        </div>}
      </section>}
    </>;
  }

  function renderWafSite() {
    const selectedSite = websites.find(site => String(site.id) === String(selectedWafWebsiteId));
    const groupedRules = (wafSiteConfig?.default_rules || wafRules.default_rule_definitions || []).reduce((groups, rule) => {
      const category = rule.category || 'General';
      groups[category] = groups[category] || [];
      groups[category].push(rule);
      return groups;
    }, {});
    const siteBotNames = siteBotText.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    const siteBotUnique = new Set(siteBotNames.map(s => s.toLowerCase()));
    return <>
      <section className="section">
        <div className="section-title waf-site-header">
          <div>
            <h2>{wafSiteConfig?.domain || selectedSite?.domain || 'Website'}</h2>
            <p className="hint">WAF rules, flood limits and blocked bots for this website.</p>
          </div>
          <div className="waf-site-header-actions">
            <select value={selectedWafWebsiteId} onChange={e => loadWebsiteWafConfig(e.target.value)}>
              {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
            <button className="secondary-light" onClick={() => navigateToPage('waf')}><ArrowLeft size={14}/> All websites</button>
          </div>
        </div>
        <div className="waf-site-toggles">
          <span className={selectedSite?.waf_enabled ? 'badge ok' : 'badge'}>{selectedSite?.waf_enabled ? 'WAF enabled' : 'WAF disabled'}</span>
          <button disabled={!selectedWafWebsiteId || !!loading} onClick={() => selectedSite && toggleWebsiteWaf(selectedSite)}>
            <Shield size={14}/> {selectedSite?.waf_enabled ? 'Disable WAF' : 'Enable WAF'}
          </button>
          <span className={wafSiteConfig?.crs_active ? 'badge ok' : 'badge'}>
            {wafSiteConfig?.crs_enabled
              ? (wafSiteConfig?.crs_mode === 'off' ? 'CRS on (server-wide: off)' : `CRS ${wafSiteConfig.crs_mode}`)
              : 'CRS off'}
          </span>
          <button
            disabled={!selectedWafWebsiteId || !!loading || !selectedSite?.waf_enabled}
            title={selectedSite?.waf_enabled ? '' : 'Enable the WAF first'}
            onClick={() => wafSiteConfig && toggleSiteCrs({
              website_id: wafSiteConfig.website_id,
              domain: wafSiteConfig.domain,
              crs_enabled: wafSiteConfig.crs_enabled,
            })}
          >
            <Shield size={14}/> {wafSiteConfig?.crs_enabled ? 'Disable CRS' : 'Enable CRS'}
          </button>
        </div>
        <p className="hint">
          The WAF blocks known bad paths. OWASP CRS adds payload inspection — SQL injection, XSS,
          command injection — for this site, at roughly {crs?.rss_mb_per_site || 50} MB of nginx memory.
          {wafSiteConfig?.crs_enabled && wafSiteConfig?.crs_mode === 'off'
            ? ' This site is opted in, but CRS is switched off server-wide on the WAF page, so nothing is loaded.'
            : ''}
          {wafSiteConfig?.crs_active
            ? ' Add SecRuleRemoveById <id> to the custom rules below to excuse this site from one CRS rule.'
            : ''}
        </p>
      </section>

      {!wafSiteConfig && websites.length === 0 && <section className="section"><EmptyState icon={Globe} message="No websites yet." /></section>}

      {wafSiteConfig && <section className="section bot-block-panel">
        <div className="section-title">
          <div>
            <h2>Blocked bots</h2>
            <p className="hint">One name per line, matched anywhere in User-Agent. Matched literally, so <code>bingbot/2.0</code> will not also match <code>bingbotX2Y0</code>. Blocked requests get 403 before WAF and rate limiting run.</p>
          </div>
        </div>
        <textarea
          className="code-editor"
          value={siteBotText}
          onChange={e => setSiteBotText(e.target.value)}
          rows={10}
          spellCheck={false}
          placeholder={'AhrefsBot\nSemrushBot\nMJ12bot'}
        />
        <p className="hint">
          {`${siteBotUnique.size} bot(s)`}
          {siteBotNames.length !== siteBotUnique.size ? ` (${siteBotNames.length - siteBotUnique.size} duplicate(s) will be dropped)` : ''}
          {botBlocks?.max_bots ? ` - max ${botBlocks.max_bots}` : ''}
        </p>
        <div className="actions">
          <button disabled={!!loading} onClick={saveSiteBots}><Shield size={14}/> Save blocked bots</button>
          <button className="secondary-light" disabled={!!loading || siteBotNames.length === 0} onClick={() => setSiteBotText('')}>Clear list</button>
        </div>
      </section>}

      {wafSiteConfig && <section className="section http-flood-panel">
        <div className="section-title">
          <h2>HTTP Flood</h2>
          <span className={httpFloodForm.http_flood_enabled ? 'badge ok' : 'badge'}>{httpFloodForm.http_flood_enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <label className="schedule-toggle http-flood-toggle">
          <input type="checkbox" checked={!!httpFloodForm.http_flood_enabled} onChange={e => setHttpFloodForm(prev => ({ ...prev, http_flood_enabled: e.target.checked }))} />
          Enabled
        </label>
        <div className="http-flood-grid">
          <label><span>Requests</span><input type="number" min="1" max="100000" value={httpFloodForm.access_limit_requests} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_requests: e.target.value }))} /></label>
          <label><span>Window (sec)</span><input type="number" min="1" max="3600" value={httpFloodForm.access_limit_window} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_window: e.target.value }))} /></label>
          <label><span>Burst</span><input type="number" min="0" max="100000" value={httpFloodForm.access_limit_burst} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_burst: e.target.value }))} /></label>
          <label><span>Connections/IP</span><input type="number" min="1" max="10000" value={httpFloodForm.connection_limit} onChange={e => setHttpFloodForm(prev => ({ ...prev, connection_limit: e.target.value }))} /></label>
          <button disabled={!!loading} onClick={saveWebsiteHttpFlood}><Shield size={14}/> Save HTTP Flood</button>
        </div>
      </section>}

      {wafSiteConfig && <section className="section waf-rules-grid">
        <div className="waf-rule-panel">
          <div className="section-title"><h2>Default rules</h2></div>
          <div className="waf-default-groups">
            {Object.entries(groupedRules).map(([category, rules]) => <div className="waf-rule-group" key={category}>
              <h3>{category}</h3>
              {rules.map(rule => <label className="waf-rule-toggle" key={rule.id}>
                <input type="checkbox" checked={!!rule.enabled} onChange={e => toggleWafDefaultRule(rule.id, e.target.checked)} />
                <span><strong>{rule.title}</strong><small>{rule.description}</small></span>
              </label>)}
            </div>)}
          </div>
        </div>
        <div className="waf-rule-panel">
          <div className="section-title"><h2>Custom rules</h2></div>
          <textarea
            className="code-editor"
            value={wafCustomRules}
            onChange={e => setWafCustomRules(e.target.value)}
            rows={14}
            spellCheck={false}
            placeholder="SecRule ..."
            readOnly={wafSiteConfig.may_edit_custom_rules === false}
          />
          <p className="hint">
            {wafSiteConfig.may_edit_custom_rules === false
              ? 'Custom rules are arbitrary ModSecurity directives, so only an administrator can change them. Ask your provider if you need a rule added or excluded.'
              : `Saved into ${wafSiteConfig.rules_file}`}
          </p>
          <div className="actions"><button disabled={!!loading} onClick={saveWebsiteWafRules}>Save website WAF rules</button></div>
        </div>
      </section>}
    </>;
  }

  function renderWafAccessLogs() {
    const rows = wafAccessLogs.items || [];
    const selectedSite = websites.find(site => String(site.id) === String(wafAccessLogFilters.websiteId));
    const entryLabel = wafAccessLogs.total >= 1000 ? `${(wafAccessLogs.total / 1000).toFixed(1)}k entries` : `${wafAccessLogs.total || 0} entries`;
    return <section className="section access-logs-section">
      <div className="section-title access-logs-title">
        <div><h2>Access Logs</h2><p className="hint">Protected Nginx traffic across all websites.</p></div>
        <div className="access-log-icon-actions">
          <button className="secondary-light icon-button" disabled={!!loading} onClick={() => loadWafAccessLogs(wafAccessLogFilters, true)} aria-label="Refresh access logs" title="Refresh access logs"><RefreshCw size={15}/></button>
          <button className="secondary-light icon-button" onClick={() => selectedSite && window.open(websiteUrl(selectedSite), '_blank', 'noopener,noreferrer')} disabled={!selectedSite} aria-label="Open website" title="Open website"><ExternalLink size={15}/></button>
        </div>
      </div>
      <div className="access-log-panel">
        <div className="access-log-toolbar">
          <div className="access-log-toolbar-label"><strong>Access Logs</strong><span>{entryLabel}</span></div>
          <button className="secondary-light" disabled={rows.length === 0} onClick={exportWafAccessLogs}><Download size={14}/> Export</button>
          <button className="danger light" disabled={!!loading || websites.length === 0} onClick={clearWafAccessLogs}><Trash2 size={14}/> Clear</button>
          <select value={wafAccessLogFilters.websiteId} onChange={e => updateWafAccessLogFilters({ websiteId: e.target.value }, true)}>
            <option value="">All websites</option>
            {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
          </select>
          <select value={wafAccessLogFilters.verdict} onChange={e => updateWafAccessLogFilters({ verdict: e.target.value }, true)}>
            <option value="all">All verdicts</option>
            <option value="block">Blocked</option>
            <option value="allow">Allowed</option>
            <option value="error">Errors</option>
          </select>
          <input value={wafAccessLogFilters.query} onChange={e => updateWafAccessLogFilters({ query: e.target.value })} onKeyDown={e => { if (e.key === 'Enter') applyWafAccessLogFilters(); }} placeholder="Filter logs" />
          <select value={wafAccessLogFilters.limit} onChange={e => updateWafAccessLogFilters({ limit: Number(e.target.value) }, true)}>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
            <option value={200}>200 / page</option>
            <option value={500}>500 / page</option>
          </select>
          <select value={wafAccessLogFilters.refresh} onChange={e => updateWafAccessLogFilters({ refresh: Number(e.target.value) })}>
            <option value={0}>Manual refresh</option>
            <option value={5}>Refresh 5s</option>
            <option value={10}>Refresh 10s</option>
            <option value={30}>Refresh 30s</option>
          </select>
          <button disabled={!!loading} onClick={applyWafAccessLogFilters}><Search size={14}/> Apply</button>
        </div>
        <div className="access-log-table-wrap">
          <table className="access-log-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Time</th>
                <th>Site</th>
                <th>Method</th>
                <th>Path</th>
                <th>IP</th>
                <th>Country</th>
                <th>Reason</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(item => <tr key={item.id}>
                <td data-label="Verdict"><span className={accessLogBadgeClass(item.verdict)}>{accessLogVerdictLabel(item.verdict)}</span></td>
                <td data-label="Time"><span className="access-log-time">{formatAccessLogTime(item.timestamp)}</span><small>{item.duration_ms || 0} ms</small></td>
                <td data-label="Site"><span className="access-log-site">{item.domain}</span></td>
                <td data-label="Method">{item.method || '-'}</td>
                <td data-label="Path"><code>{item.path || '-'}</code></td>
                <td data-label="IP"><span className="access-log-ip">{item.ip || '-'}</span></td>
                <td data-label="Country">{accessLogCountryLabel(item)}</td>
                <td data-label="Reason">{item.reason || '-'}</td>
                <td data-label="Status">{item.status || '-'}</td>
              </tr>)}
            </tbody>
          </table>
          {rows.length === 0 && <EmptyState icon={FileText} message="No access log entries match these filters." />}
        </div>
        {(wafAccessLogs.missing || []).length > 0 && <p className="hint">Missing log files: {wafAccessLogs.missing.join(', ')}</p>}
      </div>
    </section>;
  }

  function renderUpdates() {
    if (!isAdmin) return <section className="section"><h2>Updates</h2><p className="hint">No permission.</p></section>;
    const statusText = updatesStatus?.stdout || updatesStatus?.stderr || 'Click View logs to load update logs.';
    const panelUpdate = updatesStatus?.panel || {};
    const updateKnown = typeof panelUpdate.update_available === 'boolean';
    const updateAvailable = panelUpdate.update_available === true;
    const panelBadge = updateAvailable ? 'Update available' : updateKnown ? 'Up to date' : 'Unknown';
    const panelBadgeClass = updateAvailable ? 'badge bad' : updateKnown ? 'badge ok' : 'badge';
    const currentPanelVersion = panelUpdate.current_version || appVersion || 'unknown';
    const latestPanelVersion = panelUpdate.latest_version || 'unknown';
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Updates</h2><p className="hint">OS packages use apt; panel updates use <code>snpanel-update</code>.</p></div>
          <button className="secondary-light" disabled={!!loading} onClick={toggleUpdateLog}>{showUpdateLog ? <X size={14}/> : <FileText size={14}/>} {showUpdateLog ? 'Hide logs' : 'View logs'}</button>
        </div>
        <div className="info-box update-version-box">
          <div className="update-version-head"><strong>Panel release</strong><span className={panelBadgeClass}>{panelBadge}</span></div>
          <div className="update-version-grid">
            <span>Current <strong>v{currentPanelVersion}</strong></span>
            <span>Latest <strong>{latestPanelVersion === 'unknown' ? 'unknown' : `v${latestPanelVersion}`}</strong></span>
            <span>Checked <strong>{panelUpdate.last_checked_at || 'never'}</strong></span>
            <span>State file <strong>{panelUpdate.state_file || '/var/lib/snpanel/update-status.json'}</strong></span>
          </div>
          {panelUpdate.check_error && <p className="hint">Release check failed: {panelUpdate.check_error}</p>}
          {panelUpdate.last_update_status && <p className="hint">Last update: {panelUpdate.last_update_status}{panelUpdate.last_update_ref ? ` (${panelUpdate.last_update_ref})` : ''}{panelUpdate.last_update_finished_at ? ` at ${panelUpdate.last_update_finished_at}` : ''}</p>}
        </div>
        <div className="actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => loadUpdates(true)}><RefreshCw size={14}/> Check releases</button>
          <button disabled={!!loading || osUpdating} onClick={runOsUpdate}><RefreshCw size={14} className={osUpdating ? 'spin' : ''}/> {osUpdating ? 'Updating OS...' : 'Update OS now'}</button>
          <button disabled={!!loading || panelUpdating || !updateAvailable} onClick={runPanelUpdate}><RotateCcw size={14} className={panelUpdating ? 'spin' : ''}/> {panelUpdating ? 'Updating panel...' : 'Update panel now'}</button>
        </div>
        {showUpdateLog && <div className="info-box firewall-status update-log-box">
          <div className="update-log-head"><strong>Update logs</strong><button className="secondary-light" disabled={!!loading} onClick={() => loadUpdates(true)}><RefreshCw size={13}/> Refresh</button></div>
          <pre>{statusText}</pre>
        </div>}
        {(panelUpdating || (panelUpdate.progress_percent && panelUpdate.last_update_status && panelUpdate.last_update_status !== 'completed' && panelUpdate.last_update_status !== 'failed')) && (
          <div className="info-box firewall-status update-progress-box">
            <div className="update-progress-row">
              <span className={panelUpdate.last_update_status === 'failed' ? 'badge bad' : 'badge ok'}>
                {panelUpdating ? 'Running' : (panelUpdate.last_update_status === 'failed' ? 'Failed' : (panelUpdate.last_update_status || 'Idle'))}
              </span>
              <span className="update-progress-phase">{panelUpdate.progress_phase || ''}</span>
              <span className="update-progress-pct">{Number(panelUpdate.progress_percent) || 0}%</span>
            </div>
            <div className="progress-bar"><div className="progress-bar-fill" style={{ width: `${Number(panelUpdate.progress_percent) || 0}%` }} /></div>
            {panelUpdate.progress_message && <p className="hint update-progress-msg">{panelUpdate.progress_message}</p>}
            {panelUpdateLog.length > 0 && (
              <pre className="update-progress-log">{panelUpdateLog.join('\n')}</pre>
            )}
          </div>
        )}
      </section>
      <section className="section">
        <h2>Auto Update OS</h2>
        <div className="firewall-form updates-os-form">
          <label><span>Enabled</span><select value={osAutoUpdate.enabled ? 'on' : 'off'} onChange={e => setOsAutoUpdate(prev => ({ ...prev, enabled: e.target.value === 'on' }))}><option value="on">On</option><option value="off">Off</option></select></label>
          <label><span>Mode</span><select value={osAutoUpdate.mode} onChange={e => setOsAutoUpdate(prev => ({ ...prev, mode: e.target.value }))}><option value="security">Security</option><option value="all">All packages</option></select></label>
          <label><span>Auto reboot</span><select value={osAutoUpdate.auto_reboot ? 'on' : 'off'} onChange={e => setOsAutoUpdate(prev => ({ ...prev, auto_reboot: e.target.value === 'on' }))}><option value="off">Off</option><option value="on">On</option></select></label>
          <button disabled={!!loading} onClick={saveOsAutoUpdate}>Save OS auto update</button>
        </div>
      </section>
    </>;
  }

  function renderSecurity() {
    const enabled = Boolean(twoFactorStatus?.enabled || currentUser?.totp_enabled);
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Google Authenticator 2FA</h2><p className="hint">Current status: <strong>{enabled ? 'Enabled' : 'Disabled'}</strong></p></div>
          <button disabled={!!loading} onClick={loadTwoFactorStatus}><RefreshCw size={14}/> Refresh</button>
        </div>
        {!enabled && <div className="security-grid">
          <div className="info-box">
            <strong>Setup</strong>
            {twoFactorSetup?.qr_data_url ? <img className="qr-code" src={twoFactorSetup.qr_data_url} alt="2FA QR code" /> : <p className="hint">No setup code generated.</p>}
            {twoFactorSetup?.secret && <code className="secret-text">{twoFactorSetup.secret}</code>}
            <div className="actions">
              <button disabled={!!loading} onClick={setupTwoFactorAuth}><Shield size={14}/> Generate QR</button>
            </div>
          </div>
          <div className="info-box">
            <strong>Verify</strong>
            <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" />
            <button disabled={!!loading || !twoFactorSetup || !twoFactorCode} onClick={enableTwoFactorAuth}><Lock size={14}/> Enable 2FA</button>
          </div>
        </div>}
        {enabled && <div className="security-grid one">
          <div className="info-box">
            <strong>Disable 2FA</strong>
            <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" />
            <button className="danger" disabled={!!loading || !twoFactorCode} onClick={disableTwoFactorAuth}>Disable 2FA</button>
          </div>
        </div>}
      </section>

    </>;
  }

  function renderMalware() {
    if (!isAdmin) return <section className="section"><h2>Malware Scanner</h2><p className="hint">No permission.</p></section>;
    const mw = malwareScanStatus || {};
    const mwActive = Boolean(mw.active);
    const mwInstalled = Boolean(mw.installed);
    const mwEnabled = Boolean(mw.enabled);
    const activeScanJob = scanJob || scanResults || {};
    const scanRunning = ['queued', 'running'].includes(scanJob?.status);
    const scanJobTitle = job => job.scope === 'server'
      ? 'Toàn bộ VPS'
      : (job.domains && job.domains.length > 0)
        ? (job.domains.length === 1 ? job.domains[0] : `${job.domains.length} website`)
        : (job.scope === 'all' ? 'Tất cả website' : 'Lượt quét');
    const scanJobStamp = job => {
      const stamp = job.finished_at || job.updated_at || job.started_at || job.created_at || '';
      if (!stamp) return 'Chưa có thời gian';
      const date = new Date(stamp);
      return Number.isNaN(date.getTime()) ? stamp : new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Ho_Chi_Minh',
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
      }).format(date).replace(',', '');
    };
    const scanJobDetail = job => `${job.scanned || 0}/${job.total_files || job.scanned || 0} tệp, ${job.infected || 0} mối đe doạ, ${job.errors || 0} lỗi`;
    const scanJobMeta = job => `${scanJobStamp(job)} / ${scanJobDetail(job)}`;
    const scanJobBadgeClass = job => {
      if (job.status === 'done') return 'badge ok';
      if (job.status === 'infected') return 'badge danger';
      if (['error', 'interrupted'].includes(job.status)) return 'badge bad';
      return 'badge warn';
    };
    const scanStatusLabel = status => ({
      queued: 'Đang chờ', running: 'Đang chạy', done: 'Hoàn tất',
      infected: 'Phát hiện đe doạ', error: 'Lỗi', interrupted: 'Bị gián đoạn',
    }[status] || status || '—');
    const fmtStamp = s => {
      if (!s) return '';
      const d = new Date(s);
      return Number.isNaN(d.getTime()) ? s : new Intl.DateTimeFormat('vi-VN', {
        timeZone: 'Asia/Ho_Chi_Minh', hour12: false,
        day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
      }).format(d);
    };
    const scheduleDirty = ['websites', 'server'].some(n =>
      JSON.stringify(malwareSchedulesForm[n] || {}) !== JSON.stringify(malwareSchedules[n] || {}));
    const setSched = (name, patch) =>
      setMalwareSchedulesForm(p => ({ ...p, [name]: { ...p[name], ...patch } }));
    const renderScheduleRow = name => {
      const form = malwareSchedulesForm[name] || {};
      const saved = malwareSchedules[name] || {};
      // form.weekday/hour are UTC on the wire; show and edit them as VN time.
      const vn = utcScheduleToVn(form.weekday ?? 6, form.hour ?? 3);
      const setSchedVn = (patch) => {
        const merged = { weekday: patch.weekday ?? vn.weekday, hour: patch.hour ?? vn.hour };
        setSched(name, vnScheduleToUtc(merged.weekday, merged.hour));
      };
      return <div className={`malware-sched-row${form.enabled ? ' on' : ''}`} key={name}>
        <label className="malware-sched-toggle">
          <input type="checkbox" checked={!!form.enabled} onChange={e => setSched(name, { enabled: e.target.checked })} />
          <span>{MALWARE_SCHEDULE_LABELS[name]}</span>
        </label>
        <div className="malware-sched-when">
          <select value={vn.weekday} disabled={!form.enabled} aria-label="Thứ"
            onChange={e => setSchedVn({ weekday: Number(e.target.value) })}>
            {WEEKDAY_LABELS.map((l, i) => <option key={i} value={i}>{l}</option>)}
          </select>
          <select value={vn.hour} disabled={!form.enabled} aria-label="Giờ"
            onChange={e => setSchedVn({ hour: Number(e.target.value) })}>
            {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
          </select>
        </div>
        <div className="malware-sched-meta">
          {saved.enabled && saved.next_run_at && <span>Kế tiếp: <strong>{fmtStamp(saved.next_run_at)}</strong></span>}
          {saved.last_run_at && <span className={`badge ${saved.last_status === 'done' ? 'ok' : saved.last_status === 'infected' ? 'danger' : 'warn'}`}>
            {fmtStamp(saved.last_run_at)} · {scanStatusLabel(saved.last_status)}
          </span>}
        </div>
      </div>;
    };

    return <>
      <section className="section">
        <div className="section-title">
          <div>
            <h2>Malware Scanner</h2>
            <p className="hint">
              {mwActive ? <span className="badge ok">Đang bật</span>
                : mwEnabled && !mwInstalled ? <span className="badge warn">Đang cài đặt...</span>
                : mwInstalled && !mwEnabled ? <span className="badge">Đã cài · đang tắt</span>
                : <span className="badge">Chưa cài</span>}
              {mw.realtime_enabled && <span className={mw.monitor_running ? 'badge ok' : 'badge warn'} style={{marginLeft:6}}>
                Cấp 2 {mw.monitor_running ? 'đang chạy' : 'chưa chạy'}
              </span>}
            </p>
          </div>
          <button disabled={!!loading} onClick={loadMalwareScanStatus}><RefreshCw size={14}/> Refresh</button>
        </div>
        {mw.memory_warning && <div className="info-box malware-ram-warning">
          <strong><AlertCircle size={15}/> Cảnh báo RAM</strong>
          <p className="hint">{mw.memory_warning}</p>
        </div>}
        <div className="info-box">
          <p className="hint">{mw.detail || 'Đang kiểm tra...'}</p>
          {mw.memory_total_mb > 0 && <p className="hint">RAM máy chủ: <strong>{mw.memory_total_mb} MB</strong> (còn trống {mw.memory_available_mb} MB)</p>}
          {mw.lmd_installed && <p className="hint">Dữ liệu nhận diện mã độc: <strong>{mw.lmd_sig_version || '—'}</strong>{mw.lmd_updated_at ? ` (cập nhật ${mw.lmd_updated_at})` : ''}</p>}
          {!mwInstalled && <p className="hint" style={{marginTop:8}}>Khi bật, panel tự cài trình quét. Trình quét chỉ chạy trong lúc quét (RAM ~1.3GB), quét xong tự giải phóng — không chạy nền liên tục nên không tốn RAM lúc bình thường.</p>}
          <div className="actions" style={{marginTop:12}}>
            {!mwEnabled
              ? <button disabled={!!loading} onClick={() => toggleMalwareScan(true)}><Shield size={14}/> Bật trình quét</button>
              : <button className="danger" disabled={!!loading} onClick={() => toggleMalwareScan(false)}>Tắt trình quét</button>}
            {mwEnabled && !mw.lmd_installed && <button disabled={!!loading} onClick={installLmd}>Cài đặt trình quét</button>}
            {mw.lmd_installed && <button className="secondary" disabled={!!loading} onClick={updateMalwareSignatures}><RefreshCw size={13}/> Cập nhật chữ ký</button>}
          </div>
        </div>

        {mwInstalled && <div className="info-box malware-scan-panel">
          <div className="malware-scan-runner">
            <div className="malware-scan-head">
              <div>
                <strong>Cấp 1 — Quét theo lịch</strong>
                <p className="hint">Quét thư mục website (nhanh), quét toàn bộ VPS, hoặc quét tăng dần (chỉ những tệp mới sửa gần đây — chạy thủ công khi cần, không nằm trong lịch tự động).</p>
              </div>
              <button className="secondary" disabled={!!loading} onClick={loadMalwareScanJobs}><RefreshCw size={14}/> Lịch sử</button>
            </div>
            <div className="malware-scan-controls">
              <select value={scanTargetWebsiteId} onChange={e => { setScanTargetWebsiteId(e.target.value); setScanResults(null); setScanJob(null); }}>
                <option value="">-- Quét ngay: chọn mục tiêu --</option>
                <option value="all">Toàn bộ website</option>
                <option value="incremental">Quét tăng dần</option>
                <option value="server">Toàn bộ VPS</option>
                {websites.map(w => <option key={w.id} value={w.id}>{w.domain}</option>)}
              </select>
              {scanTargetWebsiteId === 'incremental' && <select value={incrementalDays} onChange={e => setIncrementalDays(Number(e.target.value))}>
                {[1, 2, 3, 7, 14].map(d => <option key={d} value={d}>{d} ngày</option>)}
              </select>}
              <button disabled={!!loading || scanRunning || !scanTargetWebsiteId} onClick={runMalwareScan}>
                {scanRunning || scanLoading ? <><RefreshCw size={14} className="spin"/> Đang quét...</> : <><Search size={14}/> Quét ngay</>}
              </button>
            </div>
          </div>
          <div className="malware-schedule">
            <div className="malware-scan-head">
              <div><strong>Lịch tự động</strong><p className="hint">Panel tự quét theo lịch, không cần ai bấm. Nên đặt vào giờ ít khách truy cập.</p></div>
              <button disabled={!!loading || !scheduleDirty} onClick={saveMalwareSchedule}><Clock size={14}/> Lưu lịch</button>
            </div>
            <div className="malware-sched-list">
              {['websites', 'server'].map(renderScheduleRow)}
            </div>
          </div>
          <div className="malware-realtime">
            <div className="malware-scan-head">
              <div>
                <strong>Cấp 2 — Bảo vệ thời gian thực</strong>
                <p className="hint">Theo dõi thư mục website liên tục, kiểm tra tệp mới theo từng đợt ngắn (~15 giây). Bắt được ngay tệp lạ upload qua SFTP/plugin, không phải chờ tới lần quét theo lịch kế tiếp như Cấp 1.</p>
              </div>
              <label className="switch-line">
                <input type="checkbox" checked={!!mw.realtime_enabled} disabled={!!loading}
                  onChange={e => toggleMalwareRealtime(e.target.checked)} />
                <span>{mw.realtime_enabled ? 'Đang bật' : 'Đang tắt'}</span>
              </label>
            </div>
          </div>
          {scanJobs.length > 0 && <div className="scan-history-wrap">
            <div className="scan-history-head">
              <strong>Lịch sử quét</strong>
              <span>{scanJobs.length} lượt</span>
            </div>
            <div className="scan-history-list">
              {scanJobs.slice(0, 8).map(job => <button
                key={job.job_id}
                className={`scan-history-item ${job.status}${activeScanJob.job_id === job.job_id ? ' active' : ''}`}
                onClick={() => showMalwareScanJob(job)}
                disabled={!!loading}
                type="button"
              >
                <Clock size={14}/>
                <span className="scan-history-main">
                  <strong>{scanJobTitle(job)}</strong>
                  <small>{scanJobMeta(job)}</small>
                </span>
                <span className={scanJobBadgeClass(job)}>{scanStatusLabel(job.status)}</span>
              </button>)}
            </div>
          </div>}
          {(scanJob || scanResults) && <div className="scan-status-panel">
            <div className="progress-bar">
              <div className="progress-bar-fill" style={{width: `${Number(activeScanJob.progress_percent) || 0}%`}} />
            </div>
            <div className="scan-status-summary">
              <span><strong>Tiến độ</strong>{Number(activeScanJob.progress_percent) || 0}%</span>
              <span><strong>Tệp đã quét</strong>{activeScanJob.scanned || 0}/{activeScanJob.total_files || activeScanJob.scanned || 0}</span>
              <span><strong>Mối đe doạ</strong>{activeScanJob.infected > 0
                ? <span className="badge danger">{activeScanJob.infected}</span>
                : <span className="badge ok">0</span>}
              </span>
              <span><strong>Lỗi</strong>{activeScanJob.errors || 0}</span>
            </div>
            {activeScanJob.message && <p className="hint">{activeScanJob.message}</p>}
            {activeScanJob.threats && activeScanJob.threats.length > 0 && <div className="scan-threat-list">
              <p className="hint">Tên hiển thị là họ mã độc do trình quét tự đặt (ví dụ php.base64...), không phải tên virus thông thường — không cần tra cứu tên này ở đâu khác.</p>
              {activeScanJob.threats.map((t, i) => <div key={i} className="scan-threat-item">
                <strong>{t.signature}</strong>
                <span>{t.domain ? `${t.domain}: ` : ''}{t.path}</span>
              </div>)}
            </div>}
            {activeScanJob.log && activeScanJob.log.length > 0 && <pre className="malware-scan-log">{activeScanJob.log.join('\n')}</pre>}
          </div>}
        </div>}
      </section>
    </>;
  }

  function renderPanelSettings() {
    if (!isAdmin) return <section className="section"><h2>Settings</h2><p className="hint">No permission.</p></section>;
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Panel settings</h2><p className="hint">Branding and hostname.</p></div>
          <button disabled={!!loading} onClick={loadPanelSettings}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="panel-settings-grid panel-settings-compact">
          <label><span>Panel name</span><input value={panelSettingsForm.app_name} onChange={e => setPanelSettingsForm(prev => ({ ...prev, app_name: e.target.value }))} placeholder="SNPanel" /></label>
          <label><span>Panel hostname</span><input value={panelSettingsForm.panel_hostname} onChange={e => setPanelSettingsForm(prev => ({ ...prev, panel_hostname: e.target.value }))} placeholder="panel.domain.com" /></label>
          <label className="check-line panel-ssl-status"><input type="checkbox" checked={!!panelSettingsForm.ssl_enabled} onChange={e => setPanelSettingsForm(prev => ({ ...prev, ssl_enabled: e.target.checked }))} /> Panel SSL</label>
          <button disabled={!!loading || !panelSettingsForm.app_name || !panelSettingsForm.panel_hostname} onClick={savePanelSettings}><SettingsIcon size={14}/> Save settings</button>
        </div>
        <div className="panel-net-strip">
          <div className="panel-net-row">
            <span className="panel-net-label">IPv4</span>
            <div className="panel-net-value">
              {panelSettings.server_ipv4?.length > 0
                ? panelSettings.server_ipv4.map(address => <span key={address} className="badge">{address}</span>)
                : <span className="hint">Không đọc được địa chỉ IPv4 của máy chủ.</span>}
            </div>
          </div>
          <div className="panel-net-row">
            <span className="panel-net-label">IPv6</span>
            <div className="panel-net-value">
              {panelSettings.ipv6?.addresses?.length > 0
                ? panelSettings.ipv6.addresses.map(address => <span key={address} className="badge">{address}</span>)
                : <span className="badge">Chưa có</span>}
              <span className={`badge ${panelSettings.ipv6?.enabled ? 'ok' : ''}`}>
                {panelSettings.ipv6?.enabled ? 'Đang bật' : 'Đang tắt'}
              </span>
            </div>
            {panelSettings.ipv6?.enabled
              ? <button className="secondary-light" disabled={!!loading} onClick={() => toggleIpv6(false)}>Tắt IPv6</button>
              : <button className="secondary-light" disabled={!!loading || !panelSettings.ipv6?.available} onClick={() => toggleIpv6(true)}>Bật IPv6</button>}
          </div>
          <span className="hint">{panelSettings.ipv6?.detail}</span>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>Admin account</h2></div>
        </div>
        <div className="panel-settings-grid admin-account-grid">
          <label><span>Email</span><input type="email" value={adminAccountForm.email} onChange={e => setAdminAccountForm(prev => ({ ...prev, email: e.target.value }))} placeholder="admin@domain.com" /></label>
          <label><span>Current password</span><input type="password" value={adminAccountForm.current_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, current_password: e.target.value }))} placeholder="Current password" autoComplete="current-password" /></label>
          <label><span>New password</span><input type="password" value={adminAccountForm.password} onChange={e => setAdminAccountForm(prev => ({ ...prev, password: e.target.value }))} placeholder="New password" autoComplete="new-password" /></label>
          <label><span>Confirm password</span><input type="password" value={adminAccountForm.confirm_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, confirm_password: e.target.value }))} placeholder="Repeat new password" autoComplete="new-password" /></label>
          <label><span>Authenticator code</span><input value={adminAccountForm.code} onChange={e => setAdminAccountForm(prev => ({ ...prev, code: e.target.value }))} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" /></label>
          <button disabled={!!loading || !adminAccountForm.email.trim() || (!!adminAccountForm.password && adminAccountForm.password !== adminAccountForm.confirm_password)} onClick={saveAdminAccount}><Lock size={14}/> Save account</button>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>Brand assets</h2><p className="hint">Upload PNG, JPG, WEBP, or ICO files up to 1 MB.</p></div>
        </div>
        <div className="brand-asset-grid">
          <div className="brand-asset-card">
            <div className="brand-preview">{renderBrandMark('settings-brand-mark')}</div>
            <label><span>Logo</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelLogoFile(e.target.files?.[0] || null)} /></label>
            <button disabled={!!loading || !panelLogoFile} onClick={() => uploadPanelAsset('logo')}><Upload size={14}/> Upload logo</button>
          </div>
          <div className="brand-asset-card">
            <div className="brand-preview favicon-preview">{panelSettings.favicon_url ? <img src={panelSettings.favicon_url} alt="" /> : <Image size={28}/>}</div>
            <label><span>Favicon</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelFaviconFile(e.target.files?.[0] || null)} /></label>
            <button disabled={!!loading || !panelFaviconFile} onClick={() => uploadPanelAsset('favicon')}><Upload size={14}/> Upload favicon</button>
          </div>
        </div>
      </section>
    </>;
  }

  function renderApiTokens() {
    if (!isAdmin) return <section className="section"><h2>API Tokens</h2><p className="hint">No permission.</p></section>;
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>API Tokens</h2><p className="hint">Create one token for WHMCS. Paste it into WHMCS Server → Access Hash.</p></div>
          <button disabled={!!loading} onClick={loadApiTokens}><RefreshCw size={14}/> Refresh</button>
        </div>
        {createdApiToken && <div className="user-create-card">
          <label><span>New token (copy now)</span><input id="created-api-token" readOnly value={createdApiToken} onFocus={e => e.target.select()} /></label>
          <button disabled={!!loading} onClick={copyApiToken}><Copy size={14}/> Copy token</button>
          <button className="secondary-light" onClick={() => setCreatedApiToken('')}>Hide</button>
        </div>}
        <div className="user-create-card">
          <label><span>Name</span><input value={newApiToken.name} onChange={e => setNewApiToken(prev => ({ ...prev, name: e.target.value }))} placeholder="WHMCS" /></label>
          <label><span>WHMCS server IP</span><input value={newApiToken.allowed_ips} onChange={e => setNewApiToken(prev => ({ ...prev, allowed_ips: e.target.value }))} placeholder="optional: 1.2.3.4 or 1.2.3.4, 5.6.7.8" /></label>
          <button disabled={!!loading || !newApiToken.name.trim()} onClick={createApiToken}><Plus size={14}/> Create token</button>
        </div>
        <p className="hint">Leave WHMCS server IP empty to allow all IPs. Multiple IPs: separate with comma.</p>
        <div className="package-list">
          {apiTokens.length === 0 && <EmptyState icon={KeyRound} message="No API tokens found." />}
          {apiTokens.map(token => <div className="package-row" key={token.id}>
            <div className="user-main"><strong>{token.name}</strong><small>{token.allowed_ips ? `Allowed IPs: ${token.allowed_ips}` : 'Allowed IPs: all'}</small></div>
            <span className="user-metric"><KeyRound size={13}/>{token.is_active ? 'Active' : 'Revoked'}</span>
            <span className="user-metric"><Clock size={13}/>{token.last_used_at ? new Date(token.last_used_at).toLocaleString() : 'Never used'}</span>
            <div className="row-actions">
              <button className="mini danger" disabled={!!loading || !token.is_active} onClick={() => revokeApiToken(token)}><Trash2 size={14}/> Revoke</button>
            </div>
          </div>)}
        </div>
      </section>
    </>;
  }

  function renderUsers() {
    if (!isAdmin) return <section className="section"><h2>Users</h2><p className="hint">No permission.</p></section>;
    const activeUserTab = userTab || 'list';
    const userTabButton = (key, Icon, label) => (
      <button
        type="button"
        className={activeUserTab === key ? 'active' : ''}
        role="tab"
        aria-selected={activeUserTab === key}
        aria-controls={`users-tab-${key}`}
        id={`users-tab-button-${key}`}
        onClick={() => setUserTab(key)}
      >
        <Icon size={14}/> {label}
      </button>
    );

    return <section className="section users-page">
      <div className="section-title">
        <div><h2>Panel users</h2><p className="hint">Manage users, packages, and domain ownership.</p></div>
      </div>
      <div className="segmented user-tabs" role="tablist" aria-label="Panel user sections">
        {userTabButton('list', Users, 'List user')}
        {userTabButton('packages', HardDrive, 'Package')}
        {userTabButton('add', Plus, 'Add User')}
      </div>

      {activeUserTab === 'list' && <div className="user-tab-panel" id="users-tab-list" role="tasnpanel" aria-labelledby="users-tab-button-list">
        <div className="section-title user-panel-title">
          <div><h2>Panel user list</h2><p className="hint">Current panel users and service limits.</p></div>
          <button disabled={!!loading} onClick={loadUsers}><RefreshCw size={14}/> Refresh</button>
        </div>
        {users.length === 0 && <EmptyState icon={Users} message="No users found." />}
        <div className="table">
          {users.map(user => <div className="row user-row" key={user.id}>
            <div className="user-main"><strong>{user.username}</strong><small>{user.email}</small></div>
            <div className="user-badges">
              <span className={user.is_active ? 'badge ok' : 'badge danger'}>{user.is_active ? 'Active' : 'Suspended'}</span>
              <span className="badge">{roleLabel(user.role)}</span>
              <span className="badge">{user.package_name || 'Custom'}</span>
              {user.totp_enabled && <span className="badge ok">2FA</span>}
            </div>
            <span className="user-metric"><HardDrive size={13}/>{storageUsageText(user)}</span>
            <div className="row-actions">
              <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingUser(user)}><Pencil size={14}/> Edit</button>
              <button className="mini secondary-light" disabled={!!loading} onClick={() => quickLoginUser(user)}><LogIn size={14}/> Login as</button>
              {user.totp_enabled && user.id !== currentUser?.id && <button className="mini secondary-light" disabled={!!loading} onClick={() => resetUserTwoFactor(user)}>Reset 2FA</button>}
              {user.id !== currentUser?.id && (user.is_active
                ? <button className="mini secondary-light" disabled={!!loading} onClick={() => suspendUser(user)}><Ban size={14}/> Suspend</button>
                : <button className="mini secondary-light" disabled={!!loading} onClick={() => unsuspendUser(user)}><Play size={14}/> Unsuspend</button>
              )}
              {user.id !== currentUser?.id && <button className="mini danger" disabled={!!loading} onClick={() => deletePanelUser(user)}><Trash2 size={14}/></button>}
            </div>
            {editingUser?.id === user.id && <div className="user-edit-panel">
              <div className="user-edit-heading">
                <div><strong>Edit {user.username}</strong><small>
                  {user.id === currentUser?.id ? 'Role is locked for the active admin session.' : 'Role changes sign the user out of existing sessions.'}
                  {editingUserForm.role === 'admin' ? ' Admin accounts bypass website and storage limits.' : ''}
                </small></div>
                <button className="user-edit-close secondary-light" onClick={cancelEditingUser} aria-label="Close user editor" title="Close user editor"><X size={16}/></button>
              </div>
              <div className="user-edit-grid">
                <label><span>Email</span><input type="email" value={editingUserForm.email} onChange={e => setEditingUserForm(prev => ({ ...prev, email: e.target.value }))} /></label>
                <label><span>Role</span><select value={editingUserForm.role} disabled={user.id === currentUser?.id} onChange={e => setEditingUserForm(prev => ({ ...prev, role: e.target.value }))}>
                  <option value="end_user">End user</option><option value="admin">Admin</option>
                </select></label>
                <label><span>Package</span><select value={editingUserForm.package_id} onChange={e => applyPackageToEditingUser(e.target.value)}>
                  <option value="">Custom limits</option>
                  {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                </select></label>
                <label><span>Website limit</span><input type="number" min="0" max="1000" disabled={!!editingUserForm.package_id} value={editingUserForm.website_limit} onChange={e => setEditingUserForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
                <label><span>Storage limit (MB)</span><input type="number" min="0" max="1048576" disabled={!!editingUserForm.package_id} value={editingUserForm.storage_limit_mb} onChange={e => setEditingUserForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
              </div>
              <div className="user-edit-section">
                <div className="user-edit-heading"><div><strong>Change password</strong><small>Minimum 12 characters. {user.id === currentUser?.id ? 'Requires current password + 2FA.' : 'Admin can set directly.'}</small></div></div>
                <div className="user-edit-grid">
                  <label><span>New password</span><input type="password" placeholder="Min 12 characters" value={editingUserForm.new_password} onChange={e => setEditingUserForm(prev => ({ ...prev, new_password: e.target.value }))} /></label>
                  <label><span>Confirm password</span><input type="password" placeholder="Repeat password" value={editingUserForm.confirm_password} onChange={e => setEditingUserForm(prev => ({ ...prev, confirm_password: e.target.value }))} /></label>
                </div>
                <div className="user-edit-actions">
                  <button disabled={!!loading || !editingUserForm.new_password || editingUserForm.new_password.length < 12} onClick={() => submitPasswordChange(user)}>Set password</button>
                </div>
              </div>
              <div className="user-edit-actions">
                <button className="secondary-light" onClick={cancelEditingUser}>Cancel</button>
                <button disabled={!!loading || !editingUserForm.email.trim()} onClick={updatePanelUser}><Save size={14}/> Save changes</button>
              </div>
            </div>}
          </div>)}
        </div>
        <div className="user-action-panel">
          <div><h3>Assign domain to user</h3><p className="hint">Move an existing domain under a selected panel user.</p></div>
          <div className="assign-row">
            <select value={assignWebsiteId} onChange={e => setAssignWebsiteId(e.target.value)}>
              <option value="">Select domain</option>
              {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
            <select value={assignUserId} onChange={e => setAssignUserId(e.target.value)}>
              <option value="">Select user</option>
              {users.map(user => <option key={user.id} value={user.id}>{user.username} ({roleLabel(user.role)})</option>)}
            </select>
            <button disabled={!assignWebsiteId || !assignUserId || !!loading} onClick={assignDomainToUser}>Assign</button>
          </div>
        </div>
      </div>}

      {activeUserTab === 'packages' && <div className="user-tab-panel" id="users-tab-packages" role="tasnpanel" aria-labelledby="users-tab-button-packages">
        <div className="section-title user-panel-title">
          <div><h2>Package</h2><p className="hint">Create, edit, delete, and review reusable user limits.</p></div>
          <button disabled={!!loading} onClick={loadPackages}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="user-create-card package-create-card">
          <label><span>Package name</span><input value={newPackage.name} onChange={e => setNewPackage(prev => ({ ...prev, name: e.target.value }))} placeholder="Starter" /></label>
          <label><span>Site limit</span><input type="number" min="0" max="1000" value={newPackage.website_limit} onChange={e => setNewPackage(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
          <label><span>Storage MB</span><input type="number" min="0" max="1048576" value={newPackage.storage_limit_mb} onChange={e => setNewPackage(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
          <button disabled={!!loading || !newPackage.name.trim()} onClick={createPackage}><Plus size={14}/> Create package</button>
        </div>
        <div className="package-list">
          {packages.length === 0 && <EmptyState icon={HardDrive} message="No packages found." />}
          {packages.map(item => <div className="package-row" key={item.id}>
            {String(editingPackageId) === String(item.id) ? <>
              <label><span>Name</span><input value={editingPackageForm.name} onChange={e => setEditingPackageForm(prev => ({ ...prev, name: e.target.value }))} /></label>
              <label><span>Site limit</span><input type="number" min="0" max="1000" value={editingPackageForm.website_limit} onChange={e => setEditingPackageForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
              <label><span>Storage MB</span><input type="number" min="0" max="1048576" value={editingPackageForm.storage_limit_mb} onChange={e => setEditingPackageForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
              <div className="row-actions">
                <button className="mini secondary-light" onClick={cancelEditingPackage}>Cancel</button>
                <button className="mini" disabled={!!loading || !editingPackageForm.name.trim()} onClick={() => updatePackage(item.id)}><Save size={14}/> Save</button>
              </div>
            </> : <>
              <div className="user-main"><strong>{item.name}</strong><small>{item.website_limit} sites - {item.storage_limit_mb} MB</small></div>
              <span className="user-metric"><Globe size={13}/>{item.website_limit} sites</span>
              <span className="user-metric"><HardDrive size={13}/>{item.storage_limit_mb} MB</span>
              <div className="row-actions">
                <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingPackage(item)}><Pencil size={14}/> Edit</button>
                <button className="mini danger" disabled={!!loading || users.some(user => user.package_id === item.id)} onClick={() => deletePackage(item)}><Trash2 size={14}/></button>
              </div>
            </>}
          </div>)}
        </div>
      </div>}

      {activeUserTab === 'add' && <div className="user-tab-panel" id="users-tab-add" role="tasnpanel" aria-labelledby="users-tab-button-add">
        <div className="section-title user-panel-title">
          <div><h2>Add User</h2><p className="hint">Panel username is also the Linux user. Login as a user before creating websites for that account.</p></div>
        </div>
        <div className="user-create-card">
          <label><span>Username</span><input value={newUser.username} onChange={e => setNewUser(prev => ({ ...prev, username: e.target.value.toLowerCase() }))} placeholder="johndoe" /></label>
          <label><span>Email</span><input value={newUser.email} onChange={e => setNewUser(prev => ({ ...prev, email: e.target.value }))} placeholder="user@domain.com" /></label>
          <label><span>Password</span><input value={newUser.password} onChange={e => setNewUser(prev => ({ ...prev, password: e.target.value }))} placeholder="Min 12 characters" type="password" /></label>
          <label><span>Role</span><select value={newUser.role} onChange={e => setNewUser(prev => ({ ...prev, role: e.target.value }))}>
            <option value="end_user">End user</option><option value="admin">Admin</option>
          </select></label>
          <label><span>Package</span><select value={newUser.package_id} onChange={e => applyPackageToNewUser(e.target.value)}>
            <option value="">Custom limits</option>
            {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select></label>
          <label><span>Site limit</span><input type="number" disabled={!!newUser.package_id} value={newUser.website_limit} onChange={e => setNewUser(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
          <label><span>Storage MB</span><input type="number" disabled={!!newUser.package_id} value={newUser.storage_limit_mb} onChange={e => setNewUser(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
          <button disabled={!!loading || !newUser.username || !newUser.password} onClick={createUser}><Plus size={14}/> Create user</button>
        </div>
      </div>}
    </section>;
  }

  function renderStandaloneEditor() {
    const editorLineCount = Math.max(1, String(fileContent || '').split('\n').length);
    const editorMode = editorLanguage(filePath);
    const siteLabel = currentSite?.domain || (selectedWebsiteId ? `Website #${selectedWebsiteId}` : 'Website');
    return <main className="standalone-editor-page">
      <header className="standalone-editor-top">
        <div className="standalone-editor-title">
          <strong>{filePath || 'No file selected'}</strong>
          <span>{siteLabel}</span>
        </div>
        <div className="standalone-editor-actions">
          <span className="editor-chip">{editorMode}</span>
          <span className="editor-chip">{editorLineCount} line(s)</span>
          <span className="editor-chip">Ln {editorCursor.line}, Col {editorCursor.column}</span>
          <button disabled={!selectedWebsiteId || !!loading} onClick={() => readFile(filePath)}><RefreshCw size={14}/> Reload</button>
          <button disabled={!selectedWebsiteId || !!loading} onClick={writeFile}>Save</button>
          <button disabled={!selectedWebsiteId || !filePath || !!loading} onClick={() => downloadFile(filePath)}><Download size={14}/></button>
          <ThemeToggle theme={theme} onToggle={toggleTheme}/>
          <button className="secondary-light" onClick={() => window.close()}><X size={14}/> Close</button>
        </div>
      </header>
      {loading && <div className="loading">{loading}</div>}
      {renderNotifications()}
      <section className="standalone-editor-body">
        <CodeEditor
          value={fileContent}
          mode={editorMode}
          disabled={!selectedWebsiteId}
          onChange={setFileContent}
          onCursorChange={setEditorCursor}
        />
      </section>
    </main>;
  }

  function renderPage() {
    if (page === 'websites') return renderWebsites();
    if (page === 'addons') return renderAddons();
    // Reachable by URL after the addon is removed, so it answers for itself
    // rather than rendering a page whose every request would be refused.
    if (page === 'applications') return appsFeatureEnabled ? renderApplications() : renderAddonMissing();
    if (page === 'ssl') return renderSsl();
    if (page === 'databases') return renderDatabases();
    if (page === 'cron') return renderCron();
    if (page === 'files') return renderFiles();
    if (page === 'backups') return renderBackups();
    if (page === 'security') return renderSecurity();
    if (page === 'php') return renderPhpConfig();
    if (page === 'firewall') return renderFirewall();
    if (page === 'waf') return renderWaf();
    if (page === 'waf-site') return renderWafSite();
    if (page === 'malware') return renderMalware();
    if (page === 'access-logs') return renderWafAccessLogs();
    if (page === 'updates') return renderUpdates();
    if (page === 'services') return renderServices();
    if (page === 'settings') return renderPanelSettings();
    if (page === 'api-tokens') return renderApiTokens();
    if (page === 'users') return renderUsers();
    return renderDashboard();
  }

  // Login screen
  if (bootstrapping) {
    return <main className="login-page">
      <section className="login-card">
        <div className="login-brand">{renderBrandMark('login-brand-mark')}<div><p className="eyebrow">{panelSettings.app_name || 'SNPanel'}</p><h1>Loading…</h1></div></div>
      </section>
    </main>;
  }

  if (!isAuthenticated) {
    return <main className="login-page">
      <section className="login-card">
        <div className="login-card-head">
          <div className="login-brand">
            {renderBrandMark('login-brand-mark')}
            <div>
              <p className="eyebrow">Server Management Panel</p>
              <h1>{panelSettings.app_name || 'SNPanel'}</h1>
              <p className="hint">Manage websites, databases, backups, SSL, and services.</p>
            </div>
          </div>
          <ThemeToggle theme={theme} onToggle={toggleTheme}/>
        </div>
        <div className="login-form">
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" autoComplete="username" />
          <input value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" type="password" autoComplete="current-password" onKeyDown={e => { if (e.key === 'Enter') login(); }} />
          {needsTwoFactor && <input value={otpCode} onChange={e => setOtpCode(e.target.value)} placeholder="Authentication code" inputMode="numeric" autoComplete="one-time-code" onKeyDown={e => { if (e.key === 'Enter') login(); }} />}
          <label className="login-remember">
            <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} />
            Keep me signed in for 30 days
          </label>
          <button disabled={!!loading || !username || !password} onClick={login}>{loading ? 'Logging in...' : 'Login'}</button>
        </div>
      </section>
      {renderNotifications()}
    </main>;
  }

  if (standaloneEditor) return renderStandaloneEditor();

  const ActiveIcon = activeNavItem?.[2] || Home;

  return <main className="app-shell">
    <section className="layout">
      {mobileMenuOpen && <div className="mobile-nav-backdrop" onClick={() => setMobileMenuOpen(false)} aria-hidden="true"></div>}
      <aside className={`sidebar ${mobileMenuOpen ? 'open' : ''}`} role="navigation" aria-label="Main navigation">
        <div className="sidebar-head">
          <div className="sidebar-brand">
            {renderBrandMark()}
            <div>
              <strong>{panelSettings.app_name || 'SNPanel'}</strong>
              <small>Server Panel</small>
            </div>
          </div>
          <button className="sidebar-close" onClick={() => setMobileMenuOpen(false)} aria-label="Close menu"><X size={18}/></button>
        </div>
        <nav className="sidebar-nav">
          {mainNavItems.map(([key, label, Icon]) => <button key={key} type="button" className={navPage === key ? 'active' : ''} onClick={() => navigateToPage(key)} aria-current={navPage === key ? 'page' : undefined}>
            <Icon size={17}/>{label}
          </button>)}
          <div className={`sidebar-nav-group ${settingsMenuOpen ? 'open' : ''}`}>
            <button className={`sidebar-group-toggle ${settingsIsActive ? 'active' : ''}`} onClick={() => setSettingsMenuOpen(open => !open)} aria-expanded={settingsMenuOpen} aria-controls="settings-submenu">
              <SettingsIcon size={17}/><span>Settings</span><ChevronDown className="sidebar-group-chevron" size={16}/>
            </button>
            {settingsMenuOpen && <div className="sidebar-subnav" id="settings-submenu">
              {settingsNavItems.map(([key, label, Icon]) => <button key={key} type="button" className={navPage === key ? 'active' : ''} onClick={() => navigateToPage(key)} aria-current={navPage === key ? 'page' : undefined}>
                <Icon size={16}/>{label}
              </button>)}
            </div>}
          </div>
        </nav>
        {appVersion && <div className="sidebar-version">v{appVersion}</div>}
      </aside>
      <div className="content">
        <section className="topbar">
          <button className="mobile-nav-toggle" onClick={() => setMobileMenuOpen(o => !o)} aria-expanded={mobileMenuOpen} aria-label="Toggle navigation">
            <Menu size={20}/><span><ActiveIcon size={17}/>{activeNavItem?.[1] || 'Menu'}</span>
          </button>
          <div className="page-title">
            <p className="eyebrow">Server Management Panel</p>
            <h1>{activeNavItem?.[1] || panelSettings.app_name || 'SNPanel'}</h1>
          </div>
          <div className="login logged-in">
            <div className="account-pill" title={accountLabel}><span>Logged in as</span><strong>{accountLabel}</strong></div>
            <div className="top-actions">
              <ThemeToggle theme={theme} onToggle={toggleTheme}/>
              <button className="secondary compact-btn" onClick={logout} aria-label="Logout" title="Logout"><LogOut size={15}/><span className="btn-label">Logout</span></button>
            </div>
          </div>
        </section>
        <div className="content-body">
          {renderPage()}
          {loading && <div className="loading"><span></span>{loading}</div>}
        </div>
      </div>
    </section>
    {renderNotifications()}
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
