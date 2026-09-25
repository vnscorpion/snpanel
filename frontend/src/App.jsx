import React, { Suspense, lazy, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { AlertCircle, Archive, Bot, Boxes, ChevronDown, Clock, Code2, Database, Download, FileText, FolderOpen, Globe, Home, KeyRound, Lock, LogOut, Menu, RefreshCw, Search, Server, Settings as SettingsIcon, Shield, ShieldBan, Users, X } from 'lucide-react';
import {
  API,
  DEFAULT_SERVICE_NAMES,
  EMPTY_SITE_APP_DRAFT,
  HTTP_FLOOD_DEFAULTS,
  MALWARE_SCHEDULES_DEFAULT,
  MALWARE_SCHEDULE_LABELS,
  NAV_PARENT_PAGE,
  NotificationToast,
  SETTINGS_PAGE_KEYS,
  ThemeToggle,
  WAF_ACCESS_LOG_DEFAULTS,
  csvCell,
  editorParamsFromLocation,
  formatApiError,
  isProxiedAppType,
  normalizeHttpFloodConfig,
  normalizeOctalMode,
  octalToPermissionBits,
  pageFromPathname,
  permissionBitsToOctal,
  routeForPage,
  sortPhpVersions,
  useTheme,
  websiteConfigForm,
} from './lib/panel.jsx';
import './style.css';
import './brand.css';
import './file-manager.css';
import './theme.css';
import { PanelContext } from './lib/panel-context.jsx';
import { LocaleProvider, LocaleSwitch, msg, useT, serverText } from './i18n/index.jsx';
import { createPasskey, getPasskeyAssertion, passkeysSupported } from './lib/webauthn.js';
// Loaded on demand. Every page but the Dashboard - the one each session lands
// on - and the code editor, which pulls in ace and is only ever shown in the
// standalone editor window.
const CodeEditor = lazy(() => import('./components/CodeEditor.jsx'));
import DashboardPage from './pages/Dashboard.jsx';
const AddonMissingPage = lazy(() => import('./pages/AddonMissing.jsx'));
const AddonsPage = lazy(() => import('./pages/Addons.jsx'));
const ApplicationsPage = lazy(() => import('./pages/Applications.jsx'));
const WebsitesPage = lazy(() => import('./pages/Websites.jsx'));
const SslPage = lazy(() => import('./pages/Ssl.jsx'));
const DatabasesPage = lazy(() => import('./pages/Databases.jsx'));
const CronPage = lazy(() => import('./pages/Cron.jsx'));
const FilesPage = lazy(() => import('./pages/Files.jsx'));
const BackupsPage = lazy(() => import('./pages/Backups.jsx'));
const ServicesPage = lazy(() => import('./pages/Services.jsx'));
const PhpConfigPage = lazy(() => import('./pages/PhpConfig.jsx'));
const FirewallPage = lazy(() => import('./pages/Firewall.jsx'));
const Fail2banPage = lazy(() => import('./pages/Fail2ban.jsx'));
const McpPage = lazy(() => import('./pages/Mcp.jsx'));
const WafPage = lazy(() => import('./pages/Waf.jsx'));
const WafSitePage = lazy(() => import('./pages/WafSite.jsx'));
const WafAccessLogsPage = lazy(() => import('./pages/WafAccessLogs.jsx'));
const UpdatesPage = lazy(() => import('./pages/Updates.jsx'));
const SecurityPage = lazy(() => import('./pages/Security.jsx'));
const MalwarePage = lazy(() => import('./pages/Malware.jsx'));
const PanelSettingsPage = lazy(() => import('./pages/PanelSettings.jsx'));
const UsersPage = lazy(() => import('./pages/Users.jsx'));

// What the loading line says while a service or an application is sent an
// action - a sentence per verb, so a translation need not splice one in.
const ACTION_LABELS = {
  start: msg('Starting {name}...'),
  stop: msg('Stopping {name}...'),
  restart: msg('Restarting {name}...'),
  reload: msg('Reloading {name}...'),
};

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
  // A passkey sign-in: '' none, 'waiting' on the authenticator, 'failed' when
  // it did not work and the authenticator code is asked for instead.
  const [passkeyStatus, setPasskeyStatus] = useState('');
  const passkeyAbort = useRef(null);
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
  const [newDatabase, setNewDatabase] = useState({ db_name: '', db_user: '', db_password: '', owner_id: '', website_id: '' });
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
  const [newBackupSchedule, setNewBackupSchedule] = useState({ user_ids: [], all_users: false, schedule: '0 2 * * *', destination: '', name_style: 'timestamp', retention: 7 });
  const [sftpTargets, setSftpTargets] = useState([]);
  const [selectedSftpTargetId, setSelectedSftpTargetId] = useState('');
  const [newSftpTarget, setNewSftpTarget] = useState({ name: '', host: '', port: 22, username: '', password: '', private_key: '', remote_path: '/backups/snpanel' });
  const [s3Targets, setS3Targets] = useState([]);
  // Where a full user backup goes: '' for this server only, 'sftp:<id>' or 's3:<id>'.
  const [userBackupDestination, setUserBackupDestination] = useState('');
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
  // The Firewall page's one form for adding a rule.
  const [firewallRule, setFirewallRule] = useState({ action: 'allow', ip: '', port: '', protocol: 'tcp' });
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
  const [passkeys, setPasskeys] = useState({ items: [], available: false, totp_enabled: false, limit: 10, loaded: false });
  const [malwareScanStatus, setMalwareScanStatus] = useState(null);
  const [fail2ban, setFail2ban] = useState(null);
  // The MCP addon: whether it is on and where, this account's tokens, and -
  // for an administrator on the Addons page - every account's.
  const [mcpInfo, setMcpInfo] = useState(null);
  const [mcpTokens, setMcpTokens] = useState([]);
  const [mcpAllTokens, setMcpAllTokens] = useState([]);
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
  const t = useT();
  // Which loadPanelSettings() call is the latest. See there.
  const panelSettingsRequest = useRef(0);
  // Which loadUsers() call is the latest: a storage figure fetched for an
  // older list must not land on a newer one.
  const usersRequest = useRef(0);
  const isAdmin = currentUser?.role === 'admin';
  const applicationAddon = addons.items.find(item => item.slug === 'application');
  const applicationAddonInstalled = !!applicationAddon?.installed;
  const fail2banAddonInstalled = !!addons.items.find(item => item.slug === 'fail2ban')?.installed;
  const mcpAddonInstalled = !!addons.items.find(item => item.slug === 'mcp')?.installed;
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

  function clearSession(message = t('Your session expired. Please log in again.')) {
    // Old localStorage token from a previous deploy: nuke it for safety.
    try { localStorage.removeItem('token'); } catch {}
    clearReadableSessionCookies();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setNeedsTwoFactor(false);
    passkeyAbort.current?.abort();
    setPasskeyStatus('');
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
    setS3Targets([]);
    setUserBackupDestination('');
    setMcpInfo(null);
    setMcpTokens([]);
    setMcpAllTokens([]);
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

  // A wrong current password or code, on a form that asks for one, is a 401
  // too - and it is not the session ending. The person is still signed in and
  // is told what they typed was wrong, rather than being signed out for it.
  const STEP_UP_REFUSALS = new Set(['Current password is incorrect', 'Invalid authentication code', 'Two-factor authentication code required']);

  function handleAuthExpired(status, detail = '') {
    if (status === 401 && STEP_UP_REFUSALS.has(detail)) return false;
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
      if (!res.ok && !silent) setError(formatApiError(data.detail, t('Request failed with status {status}', { status: res.status })));
      if (res.ok && data?.message && !silent) setNotice(data.message);
      return res.ok ? data : null;
    } catch (err) {
      setError(t('Cannot connect to the {app} API at {url}. Check snpanel-api and the panel port.', { app: panelSettings.app_name || 'SNPanel', url: API }));
      return null;
    } finally {
      if (label) setLoading('');
    }
  }

  // `options.otp` lets "try the passkey again" send no code whatever is typed.
  async function login(options = {}) {
    const otp = typeof options.otp === 'string' ? options.otp : otpCode;
    try {
      setError('');
      setLoading(t('Logging in...'));
      const body = new URLSearchParams({ username, password });
      if (needsTwoFactor || otp) body.set('otp', otp);
      if (rememberMe) body.set('remember', 'true');
      const res = await fetch(`${API}/auth/login`, {
        method: 'POST',
        body,
        credentials: 'include',
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.requires_2fa) {
        setNeedsTwoFactor(true);
        // A passkey registered at this address is tried first; the code is
        // asked for when it does not work. Not awaited: the person may take
        // a while, and nothing else should wait on them.
        if (data.passkey && passkeysSupported()) {
          signInWithPasskey(data.passkey);
        } else {
          setPasskeyStatus('');
          setNotice(t('Enter your authentication code.'));
        }
      } else if (res.ok && data.access_token) {
        // Don't keep the token anywhere: the HttpOnly cookie just got set by
        // the response. JS code MUST NOT touch the JWT.
        setIsAuthenticated(true);
        setNeedsTwoFactor(false);
        setPasskeyStatus('');
        setOtpCode('');
        setNotice(t('Login successful.'));
        await loadCurrentUser();
      } else {
        setError(formatApiError(data.detail, t('Login failed with status {status}', { status: res.status })));
      }
    } catch (err) {
      setError(t('Cannot connect to the {app} API at {url}. Check snpanel-api and the panel port.', { app: panelSettings.app_name || 'SNPanel', url: API }));
    } finally {
      setLoading('');
    }
  }

  // The passkey half of the second step, from the ticket and options the
  // password step returned. When it does not work - no authenticator to
  // hand, the prompt cancelled, the signature refused - the page falls back
  // to the authenticator code.
  async function signInWithPasskey(offer) {
    passkeyAbort.current?.abort();
    const controller = new AbortController();
    passkeyAbort.current = controller;
    setPasskeyStatus('waiting');
    try {
      const credential = await getPasskeyAssertion(offer.publicKey, controller.signal);
      const res = await fetch(`${API}/auth/login/passkey`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket: offer.ticket, credential }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.access_token) {
        setIsAuthenticated(true);
        setNeedsTwoFactor(false);
        setPasskeyStatus('');
        setOtpCode('');
        setNotice(t('Login successful.'));
        await loadCurrentUser();
        return;
      }
    } catch {
      // The person chose the code instead: nothing went wrong.
      if (controller.signal.aborted) {
        setPasskeyStatus('');
        return;
      }
    } finally {
      if (passkeyAbort.current === controller) passkeyAbort.current = null;
    }
    setPasskeyStatus('failed');
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
    clearSession(t('Logged out.'));
  }

  async function loadCurrentUser({ clearOnUnauthorized = true } = {}) {
    try {
      const res = await fetch(`${API}/auth/session`, { credentials: 'include' });
      if (!res.ok) {
        if (res.status === 401) {
          if (clearOnUnauthorized) clearSession(t('Session expired.'));
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
        if (clearOnUnauthorized) clearSession(t('Session expired.'));
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
    // Only the latest call may write. Opening /settings with a live session
    // starts two: the public one from mount, before the session is known,
    // and the authenticated one once it is. The public answer has an empty
    // hostname and `ssl_enabled: false`, and if it lands second it
    // overwrites the form - so the admin sees the panel's IP and SSL off,
    // and "Save settings" would make both true. Measured: a Playwright run
    // against a busy server caught the form in exactly that state.
    const request = ++panelSettingsRequest.current;
    try {
      const res = await fetch(`${API}${path}`, { credentials: 'include' });
      if (!res.ok) return null;
      const data = await res.json();
      if (request !== panelSettingsRequest.current) return data;
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
      }, t('Saving panel settings...'));
      if (!nameData) return;
      const sslData = await request('/panel-settings/ssl', {
        method: 'POST',
        body: JSON.stringify({ panel_hostname: hostname, panel_port: port }),
      }, t('Installing panel SSL...'));
      if (sslData) {
        setPanelSettings(sslData);
        setPanelSettingsForm(formFromPanelSettings(sslData));
        setNotice(sslData.message || t('Panel SSL installed. The panel may restart in a moment.'));
      }
      return;
    }

    const payload = hasSsl && !wantsSsl
      ? { app_name: panelSettingsForm.app_name, panel_url: `http://${hostname}:${port}` }
      : { app_name: panelSettingsForm.app_name, panel_hostname: hostname };
    const data = await request('/panel-settings', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }, t('Saving panel settings...'));
    if (data) {
      setPanelSettings(data);
      setPanelSettingsForm(formFromPanelSettings(data));
      setNotice(hasSsl && !wantsSsl ? t('Panel SSL disabled. The panel remains reachable by IP and port over HTTP.') : t('Panel settings updated.'));
    }
  }

  async function saveAdminAccount() {
    const email = String(adminAccountForm.email || '').trim();
    const password = String(adminAccountForm.password || '');
    const confirmPassword = String(adminAccountForm.confirm_password || '');
    const currentPassword = String(adminAccountForm.current_password || '');
    const code = String(adminAccountForm.code || '').trim();

    if (!email) {
      setError(t('Email is required.'));
      return;
    }
    if (password && password.length < 12) {
      setError(t('Password must be at least 12 characters.'));
      return;
    }
    if (password && password !== confirmPassword) {
      setError(t('Passwords do not match.'));
      return;
    }

    const payload = { email };
    if (password) {
      if (!currentPassword) {
        setError(t('Current password is required to change password.'));
        return;
      }
      payload.password = password;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        if (!code) {
          setError(t('Authentication code is required.'));
          return;
        }
        payload.code = code;
      }
    }

    const data = await request('/panel-settings/admin-account', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }, t('Saving admin account...'));
    if (!data) return;
    if (data.password_changed) {
      clearSession(t('Password changed. Please log in again.'));
      return;
    }
    setAdminAccountForm(prev => ({ ...prev, current_password: '', password: '', confirm_password: '', code: '' }));
    await loadCurrentUser({ clearOnUnauthorized: false });
    setNotice(data.message || t('Admin account updated.'));
  }

  async function uploadPanelAsset(kind) {
    const file = kind === 'logo' ? panelLogoFile : panelFaviconFile;
    if (!file) return;
    const body = new FormData();
    body.append('file', file);
    const data = await request(`/panel-settings/${kind}`, { method: 'POST', body }, t('Uploading {kind}...', { kind }));
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
            account_suspended: t('This account is suspended. Contact the administrator.'),
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
    const data = await request(`/websites${suffix}`, {}, showLoading ? t('Loading websites...') : '');
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
    const data = await request(`/databases${suffix}`, {}, showLoading ? t('Loading databases...') : '');
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
    if (!newApiToken.name.trim()) { setError(t('Token name is required.')); return; }
    const data = await request('/provisioning/v1/tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: newApiToken.name.trim(),
        scopes: 'provisioning:read,provisioning:write',
        allowed_ips: newApiToken.allowed_ips.trim(),
      }),
    }, t('Creating the API token...'));
    if (data) {
      setCreatedApiToken(data.token || '');
      setNotice(t('API token created. Copy it now: it will not be shown again.'));
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
      setNotice(t('API token copied. Paste it into the WHMCS server’s Access Hash field.'));
    } catch {
      const input = document.getElementById('created-api-token');
      input?.focus();
      input?.select();
      setError(t('Could not copy. The token is selected: press Ctrl+C.'));
    }
  }

  async function revokeApiToken(token) {
    if (!confirm(t('Revoke the API token {name}? Anything using it, such as WHMCS, will stop working.', { name: token.name }))) return;
    const data = await request(`/provisioning/v1/tokens/${token.id}`, { method: 'DELETE' }, t('Revoking {name}...', { name: token.name }));
    if (data) {
      setNotice(t('Revoked the API token {name}.', { name: token.name }));
      await loadApiTokens();
    }
  }

  // The list at once, without the storage walk (`?usage=0`) that kept it
  // waiting on every account's files; then, on the Users page, each user's
  // figure from `/users/{id}/usage`, four at a time, filled in as it comes.
  async function loadUsers() {
    const call = ++usersRequest.current;
    const data = await request('/users?usage=0');
    if (!data || call !== usersRequest.current) return;
    setUsers(data);
    if (!selectedBackupUserId && data[0]) setSelectedBackupUserId(String(data[0].id));
    setNewBackupSchedule(prev => (!prev.all_users && (!prev.user_ids || prev.user_ids.length === 0) && data[0]) ? ({ ...prev, user_ids: [String(data[0].id)] }) : prev);
    if (page === 'users') loadUserUsage(data.map(user => user.id), call);
  }

  async function loadUserUsage(ids, call) {
    const queue = [...ids];
    const next = async () => {
      while (queue.length > 0) {
        const id = queue.shift();
        const figure = await request(`/users/${id}/usage`, { silent: true });
        if (call !== usersRequest.current) return;
        if (figure) setUsers(prev => prev.map(user => (user.id === id ? { ...user, ...figure } : user)));
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, queue.length) }, next));
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
    const data = await request('/users', { method: 'POST', body: JSON.stringify(payload) }, t('Creating user...'));
    if (data) {
      setNotice(t('Created user {name}', { name: data.username }));
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
    if (!editingUserForm.email.trim()) { setError(t('Email is required.')); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError(t('Website limit must be between 0 and 1000.'));
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError(t('Storage limit must be between 0 and 1048576 MB.'));
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
    }, t('Updating {name}...', { name: editingUser.username }));
    if (data) {
      setNotice(t('Updated user {name}.', { name: data.username }));
      if (data.id === currentUser?.id) setCurrentUser(prev => ({ ...prev, ...data }));
      cancelEditingUser();
      await loadUsers();
    }
  }

  async function submitPasswordChange(user) {
    if (!user) return;
    const pw = editingUserForm.new_password;
    if (pw.length < 12) { setError(t('Password must be at least 12 characters.')); return; }
    if (pw !== editingUserForm.confirm_password) { setError(t('Passwords do not match.')); return; }
    const payload = { password: pw };
    if (user.id === currentUser?.id) {
      const currentPassword = prompt(t('Enter your current password to confirm this change:'));
      if (!currentPassword) return;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        const code = prompt(t('Enter the 6-digit code from your authenticator:'));
        if (!code) return;
        payload.code = code.trim();
      }
    }
    const data = await request(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify(payload) }, t('Changing password for {name}...', { name: user.username }));
    if (data?.message) {
      setNotice(data.message);
      setEditingUserForm(prev => ({ ...prev, new_password: '', confirm_password: '' }));
    }
  }

  async function createPackage() {
    const websiteLimit = Number(newPackage.website_limit);
    const storageLimitMb = Number(newPackage.storage_limit_mb);
    if (!newPackage.name.trim()) { setError(t('Package name is required.')); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError(t('Website limit must be between 0 and 1000.'));
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError(t('Storage limit must be between 0 and 1048576 MB.'));
      return;
    }
    const data = await request('/packages', {
      method: 'POST',
      body: JSON.stringify({ name: newPackage.name.trim(), website_limit: websiteLimit, storage_limit_mb: storageLimitMb }),
    }, t('Creating package...'));
    if (data) {
      setNotice(t('Created package {name}.', { name: data.name }));
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
    if (!editingPackageForm.name.trim()) { setError(t('Package name is required.')); return; }
    if (!Number.isInteger(websiteLimit) || websiteLimit < 0 || websiteLimit > 1000) {
      setError(t('Website limit must be between 0 and 1000.'));
      return;
    }
    if (!Number.isInteger(storageLimitMb) || storageLimitMb < 0 || storageLimitMb > 1024 * 1024) {
      setError(t('Storage limit must be between 0 and 1048576 MB.'));
      return;
    }
    const data = await request(`/packages/${packageId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: editingPackageForm.name.trim(), website_limit: websiteLimit, storage_limit_mb: storageLimitMb }),
    }, t('Updating package...'));
    if (data) {
      setNotice(t('Updated package {name}.', { name: data.name }));
      cancelEditingPackage();
      await loadPackages();
      await loadUsers();
    }
  }

  async function deletePackage(item) {
    if (!confirm(t('Delete package {name}?', { name: item.name }))) return;
    const data = await request(`/packages/${item.id}`, { method: 'DELETE' }, t('Deleting {name}...', { name: item.name }));
    if (data) {
      setNotice(t('Deleted package {name}.', { name: item.name }));
      if (String(editingPackageId) === String(item.id)) cancelEditingPackage();
      await loadPackages();
    }
  }

  async function changeUserPassword(user) {
    const password = prompt(t('Enter a new password for {name} (minimum 12 characters):', { name: user.username }));
    if (!password) return;
    if (password.length < 12) { setError(t('Password must be at least 12 characters.')); return; }
    const payload = { password };
    if (user.id === currentUser?.id) {
      const currentPassword = prompt(t('Enter your current password to confirm this change:'));
      if (!currentPassword) return;
      payload.current_password = currentPassword;
      if (currentUser?.totp_enabled) {
        const code = prompt(t('Enter the 6-digit code from your authenticator:'));
        if (!code) return;
        payload.code = code.trim();
      }
    }
    const data = await request(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify(payload) }, t('Changing password for {name}...', { name: user.username }));
    if (data?.message) setNotice(data.message);
  }

  async function deletePanelUser(user) {
    if (!user || user.id === currentUser?.id) return;
    if (!confirm(t('Delete panel user {name} and permanently delete all owned websites, files, databases, SSL certificates, and Linux user data?', { name: user.username }))) return;
    const data = await request(`/users/${user.id}`, { method: 'DELETE' }, t('Deleting user {name}...', { name: user.username }));
    if (data) {
      const count = data.deleted_websites?.length || 0;
      setNotice(count ? t('Deleted user {name} and {count} website(s)', { name: user.username, count }) : t('Deleted user {name}', { name: user.username }));
      await loadUsers();
      await refreshAll();
    }
  }

  async function suspendUser(user) {
    if (!user || user.id === currentUser?.id) return;
    const siteCount = websites.filter(w => w.owner_id === user.id).length;
    if (!confirm(t('Suspend user {name}? This will block login, disable all {siteCount} website(s), lock SFTP, and kill active sessions.', { name: user.username, siteCount }))) return;
    const data = await request(`/users/${user.id}/suspend`, { method: 'POST' }, t('Suspending user {name}...', { name: user.username }));
    if (data) {
      await loadUsers();
      await refreshAll();
    }
  }

  async function unsuspendUser(user) {
    if (!user || user.id === currentUser?.id) return;
    if (!confirm(t('Unsuspend user {name}? This will restore login, websites, and SFTP access.', { name: user.username }))) return;
    const data = await request(`/users/${user.id}/unsuspend`, { method: 'POST' }, t('Unsuspending user {name}...', { name: user.username }));
    if (data) {
      await loadUsers();
      await refreshAll();
    }
  }

  async function quickLoginUser(user) {
    if (!user) return;
    const suspendedNote = user.is_active ? '' : ` ${t('This user is SUSPENDED — websites and SFTP are disabled.')}`;
    if (!confirm(`${t('Log in as {name}?', { name: user.username })}${suspendedNote}`)) return;
    // Impersonation re-prompts TOTP when the calling admin has 2FA enabled.
    // Try without the code first; if the backend says one is required, ask
    // and resend. Sending the OTP via FormData keeps it out of the URL.
    let body;
    if (currentUser?.totp_enabled) {
      const code = prompt(t('Enter the 6-digit code from your authenticator to confirm logging in as {name}:', { name: user.username }));
      if (!code) return;
      body = new URLSearchParams({ otp: code.trim() });
    }
    const data = await request(
      `/auth/impersonate/${user.id}`,
      body
        ? { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        : { method: 'POST' },
      t('Logging in as {name}...', { name: user.username }),
    );
    // Handle case where backend says 2FA is required (e.g., stale user object).
    if (data?.requires_2fa) {
      const code = prompt(t('Enter the 6-digit code from your authenticator to confirm logging in as {name}:', { name: user.username }));
      if (!code) return;
      const retryBody = new URLSearchParams({ otp: code.trim() });
      const retryData = await request(
        `/auth/impersonate/${user.id}`,
        { method: 'POST', body: retryBody, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
        t('Logging in as {name}...', { name: user.username }),
      );
      if (retryData?.access_token) {
        setNotice(t('Logged in as {name}.', { name: user.username }));
        await loadCurrentUser();
        navigateToPage('websites');
        await refreshAll();
      }
      return;
    }
    if (data?.access_token) {
      setNotice(t('Logged in as {name}.', { name: user.username }));
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
    const currentPassword = prompt(t('Enter your current password to set up the authenticator app:'));
    if (!currentPassword) return;
    const payload = { current_password: currentPassword };
    if (currentUser?.totp_enabled) {
      const code = prompt(t('Enter the six-digit code from your authenticator app:'));
      if (!code) return;
      payload.code = code.trim();
    }
    const data = await request('/auth/2fa/setup', { method: 'POST', body: JSON.stringify(payload) }, t('Preparing the authenticator app...'));
    if (data) {
      setTwoFactorSetup(data);
      setTwoFactorStatus({ enabled: false });
    }
  }

  async function enableTwoFactorAuth() {
    const data = await request('/auth/2fa/enable', { method: 'POST', body: JSON.stringify({ code: twoFactorCode }) }, t('Turning on two-step verification...'));
    if (data) {
      setTwoFactorStatus(data);
      setTwoFactorSetup(null);
      setTwoFactorCode('');
      await loadCurrentUser();
      await loadPasskeys();
      setNotice(t('Two-step verification is on.'));
    }
  }

  async function disableTwoFactorAuth() {
    const currentPassword = prompt(t('Enter your current password to turn off two-step verification:'));
    if (!currentPassword) return;
    const data = await request(
      '/auth/2fa/disable',
      { method: 'POST', body: JSON.stringify({ current_password: currentPassword, code: twoFactorCode }) },
      t('Turning off two-step verification...'),
    );
    if (data) {
      setTwoFactorStatus(data);
      setTwoFactorCode('');
      await loadCurrentUser();
      await loadPasskeys();
      setNotice(t('Two-step verification is off. Your passkeys were removed with it.'));
    }
  }

  async function loadPasskeys() {
    const data = await request('/auth/passkeys', { silent: true });
    if (data) setPasskeys({ ...data, loaded: true });
  }

  // A current authenticator code, then the device's own prompt. Returns
  // whether a passkey was added.
  async function addPasskey(name, code) {
    const options = await request('/auth/passkeys/register/options', { method: 'POST', body: JSON.stringify({ code }) }, t('Preparing the passkey...'));
    if (!options) return false;
    let credential;
    try {
      credential = await createPasskey(options.publicKey);
    } catch (err) {
      setError(err?.name === 'InvalidStateError'
        ? t('This device already has a passkey for this account.')
        : t('No passkey was created. The device prompt was closed or not available.'));
      return false;
    }
    const data = await request('/auth/passkeys/register', { method: 'POST', body: JSON.stringify({ name, credential }) }, t('Saving the passkey...'));
    if (!data) return false;
    setNotice(t('Passkey added.'));
    await loadPasskeys();
    return true;
  }

  async function removePasskey(item) {
    if (!confirm(t('Remove the passkey {name}? You can still sign in with the authenticator app.', { name: item.name }))) return;
    const data = await request(`/auth/passkeys/${item.id}`, { method: 'DELETE' }, t('Removing the passkey...'));
    if (data) {
      setNotice(t('Passkey removed.'));
      await loadPasskeys();
    }
  }

  async function resetUserTwoFactor(user) {
    if (!confirm(t('Reset 2FA for {name}?', { name: user.username }))) return;
    const data = await request(`/users/${user.id}/2fa/reset`, { method: 'POST' }, t('Resetting 2FA for {name}...', { name: user.username }));
    if (data?.message) { setNotice(data.message); await loadUsers(); }
  }

  async function loadMalwareScanStatus() {
    const data = await request('/malware/status', {}, t('Loading scanner status...'));
    if (data) setMalwareScanStatus(data);
  }

  async function toggleIpv6(enable) {
    const ipv6 = panelSettings.ipv6 || {};
    if (enable && !ipv6.available) {
      setError(ipv6.detail || t('This server has no IPv6 address, so this cannot be turned on.'));
      return;
    }
    if (!confirm(enable
      ? t('Turn on IPv6 for every website and the panel?\n\nSNPanel adds listen [::] to every website\'s nginx configuration, checks it with nginx -t and undoes the change if that fails. The panel will restart.')
      : t('Turn off IPv6?\n\nWebsites and the panel will only accept IPv4 connections. Visitors reaching a domain over IPv6 through an AAAA record will not get in.'))) return;
    const data = await request('/panel-settings/ipv6', {
      method: 'POST',
      body: JSON.stringify({ enabled: enable }),
    }, enable ? t('Turning on IPv6...') : t('Turning off IPv6...'));
    if (data) {
      setPanelSettings(data);
      setNotice(data.message || (enable ? t('IPv6 is on.') : t('IPv6 is off.')));
    }
  }

  async function toggleMalwareScan(enable) {
    if (enable && !malwareScanStatus?.installed) {
      if (!confirm(t('The scanner is not installed on this server. The panel will install it now, which takes a minute or two. Continue?'))) return;
    }
    const data = await request('/malware/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled: enable }),
    }, enable ? t('Turning on the scanner...') : t('Turning off the scanner...'));
    if (data) {
      setPanelSettings(data);
      setNotice(data.message || (enable ? t('The scanner is on.') : t('The scanner is off.')));
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
      if (!confirm(`${serverText(malwareScanStatus.memory_warning)}\n\n${t('Schedule the whole-server scan anyway?')}`)) return;
    }
    const body = {};
    for (const name of ['websites', 'server']) {
      const e = f[name] || {};
      body[name] = { enabled: !!e.enabled, weekday: Number(e.weekday ?? 6), hour: Number(e.hour ?? 3) };
    }
    const data = await request('/malware/schedule', { method: 'PUT', body: JSON.stringify(body) }, t('Saving the scan schedule...'));
    if (data) {
      setMalwareSchedules(data);
      setMalwareSchedulesForm(data);
      const on = ['websites', 'server'].filter(n => data[n]?.enabled).map(n => t(MALWARE_SCHEDULE_LABELS[n]));
      setNotice(on.length ? t('Schedule saved: {list}.', { list: on.join(', ') }) : t('Every scan schedule is off.'));
    }
  }

  async function toggleMalwareRealtime(enabled) {
    if (enabled && !confirm(t('Turn on real-time protection? The panel will watch website folders and scan new files as they appear. If it is not installed yet, the panel installs it first (1-3 minutes).'))) return;
    const data = await request('/malware/realtime', { method: 'POST', body: JSON.stringify({ enabled }) },
      enabled ? t('Turning on real-time protection...') : t('Turning off...'));
    if (data) { setMalwareScanStatus(data); setNotice(enabled ? t('Real-time protection (level 2) is on.') : t('Real-time protection is off.')); }
  }

  // Uploads through the File Manager, and the ClamAV daemon with them.
  async function toggleUploadScan(enabled) {
    const status = malwareScanStatus || {};
    if (enabled && status.enabled && !status.clamd_installed
      && !confirm(t('Scanning uploads uses the ClamAV daemon, which is not installed. The panel will install it now; it keeps about a gigabyte of memory in use. Continue?'))) return;
    const data = await request('/malware/upload-scan', { method: 'POST', body: JSON.stringify({ enabled }) },
      enabled ? t('Turning on upload scanning...') : t('Turning off upload scanning...'));
    if (data) {
      setMalwareScanStatus(data);
      setNotice(!enabled
        ? t('Uploads are no longer scanned, and the ClamAV daemon is stopped to free its memory. Scheduled and real-time scans are unchanged.')
        : !data.enabled
          ? t('Uploads will be scanned once the malware scanner is on.')
          : data.clamd_running
            ? t('Uploads are scanned. The ClamAV daemon is running.')
            : data.clamd_installed
              ? t('Starting the ClamAV daemon, which takes a minute while it loads its signatures. Until then, uploads are checked with clamscan.')
              : t('Installing the ClamAV daemon in the background (a few minutes). Until it runs, uploads are checked with clamscan.'));
    }
  }

  async function installLmd() {
    const data = await request('/malware/lmd/install', { method: 'POST' }, t('Installing...'));
    if (data) { setMalwareScanStatus(data); setNotice(t('Installing the scanner in the background (1-3 minutes). Press Refresh to see the result.')); }
  }

  async function updateMalwareSignatures() {
    const data = await request('/malware/lmd/update-sigs', { method: 'POST' }, t('Updating signatures...'));
    if (data) { setMalwareScanStatus(data); setNotice(data.message || t('Signatures updated.')); }
  }

  async function runMalwareScan() {
    if (!scanTargetWebsiteId) return;
    if (scanTargetWebsiteId === 'server' && malwareScanStatus?.memory_warning) {
      if (!confirm(`${serverText(malwareScanStatus.memory_warning)}\n\n${t('Scan the whole server anyway?')}`)) return;
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
      }, t('Starting the scan...'));
      if (data) {
        setScanJob(data);
        await loadMalwareScanJobs();
        setNotice(t('Scan started.'));
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
        setNotice(t('{count} threat(s) found.', { count: data.infected }));
      } else if (['error', 'interrupted'].includes(data.status)) {
        setError(data.error || data.message || t('The scan failed.'));
      } else {
        setNotice(t('Scan finished: {count} file(s) checked, no threats found.', { count: data.scanned || 0 }));
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
    const data = await request('/malware/start-daemon', { method: 'POST' }, t('Starting ClamAV daemon...'));
    if (data) {
      setNotice(data.message || t('ClamAV daemon started.'));
      await loadMalwareScanStatus();
    }
  }

  async function assignDomainToUser() {
    if (!assignWebsiteId || !assignUserId) return;
    const data = await request(`/websites/${assignWebsiteId}`, { method: 'PATCH', body: JSON.stringify({ owner_id: Number(assignUserId) }) }, t('Assigning domain to user...'));
    if (data) { setNotice(t('Assigned domain {domain} to user ID {id}', { domain: data.domain, id: assignUserId })); await refreshAll(); }
  }

  async function createWordPress() {
    const cleanDomain = domain.trim().toLowerCase();
    const cleanAdminEmail = adminEmail.trim();
    if (!cleanDomain) { setError(t('Please enter a domain name.')); return; }
    const installWp = siteType === 'wordpress' && installWordPress;
    if (siteType === 'application' && !createSiteAppId) {
      setError(t('Pick which application this website should serve.'));
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
      // A blank field gets a random password, shown once in the notice below -
      // never a fixed default, which would be one guessable login on every site.
      body.admin_password = wpAdminPassword || generateRandomPassword();
    }
    const data = await request('/websites', { method: 'POST', body: JSON.stringify(body) },
      installWp ? t('Creating WordPress website...') : t('Creating website...'));
    if (data) {
      if (installWp) {
        setNotice(t('Created WordPress site: {url}\nAdmin: {user} | Password: {password}', { url: `https://${cleanDomain}`, user: wpAdminUser, password: body.admin_password }));
      } else if (siteType === 'application') {
        setNotice(t('Created {domain}, serving the selected application.', { domain: cleanDomain }));
        setCreateSiteAppId('');
      } else {
        setNotice(t('Created site {domain}. Upload your files to public_html/ folder.', { domain: cleanDomain }));
      }
      if (createSslMode !== 'none') await applyCreateSsl(data.id, cleanDomain);
      refreshAll();
    }
  }

  async function deleteWebsite(id) {
    if (!confirm(t('Delete this website including files, vhost, database, and its SSL certificate?'))) return;
    const data = await request(`/websites/${id}?delete_files=true&delete_database=true`, { method: 'DELETE' }, t('Deleting website...'));
    if (data) refreshAll();
  }

  async function enableSsl(id) {
    const data = await request(`/websites/${id}/ssl`, { method: 'POST' }, t('Installing Let\'s Encrypt SSL...'));
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
        t('Issuing wildcard certificate via Cloudflare...'));
      if (data) {
        setCreateSslToken('');
        setNotice(t('Created {domain}. Wildcard SSL active — *.{source} covers it.', { domain: siteDomain, source: data.ssl_source_domain }));
      }
      return;
    }
    if (createSslMode === 'shared') {
      const sources = await request(`/websites/${id}/ssl/sources`, { silent: true });
      const list = Array.isArray(sources) ? sources : [];
      if (!list.length) {
        setError(t('Created {domain}, but no existing certificate covers it. Enable SSL from the SSL page.', { domain: siteDomain }));
        return;
      }
      // Prefer a wildcard cert, then the longest-matching source domain.
      const pick = [...list].sort((a, b) =>
        (b.wildcard - a.wildcard) || (b.domain.length - a.domain.length))[0];
      const data = await request(`/websites/${id}/ssl/shared`,
        { method: 'POST', body: JSON.stringify({ source_domain: pick.domain }) },
        t('Using {domain}\'s certificate...', { domain: pick.domain }));
      if (data) setNotice(t('Created {domain}, now serving {source}\'s certificate.', { domain: siteDomain, source: pick.domain }));
      return;
    }
    if (createSslMode === 'manual') {
      // Manual SSL needs the cert and key pasted in; send the operator to the
      // SSL page for this site to finish it there.
      setSelectedWebsiteId(String(id));
      setNotice(t('Created {domain}. Open the Manual tab on the SSL page to paste its certificate.', { domain: siteDomain }));
      navigateToPage('ssl');
    }
  }

  async function addWebsiteAlias(site) {
    const cleanAlias = String(aliasDrafts[site.id] || '').trim().toLowerCase();
    const aliasMode = aliasModes[site.id] || 'alias';
    if (!cleanAlias) { setError(t('Enter a domain.')); return; }
    const data = await request(`/websites/${site.id}/aliases`, {
      method: 'POST',
      body: JSON.stringify({ domain: cleanAlias, mode: aliasMode }),
    }, t('Adding {kind} {domain}...', { kind: aliasMode === 'redirect' ? 'redirect' : 'alias', domain: cleanAlias }));
    if (data) {
      const label = aliasMode === 'redirect' ? 'redirect' : 'alias';
      // Adding a domain only wires it into Nginx - same split DirectAdmin
      // uses. Getting it a certificate is the separate, explicit step on the
      // SSL page (Install / Renew SSL there already asks for every alias and
      // redirect), so nothing SSL-related is attempted or claimed here.
      setNotice(site.ssl_mode === 'letsencrypt' && !data.ssl_enabled
        ? t('Added {kind} {domain}. To give it a certificate, open the SSL page and press "Install / Renew SSL".', { kind: label, domain: cleanAlias })
        : t('Added {kind} {domain}.', { kind: label, domain: cleanAlias }));
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
    if (!confirm(t('Remove {kind} {domain} from {site}?', { kind: label, domain: alias.domain, site: site.domain }))) return;
    const data = await request(`/websites/${site.id}/aliases/${alias.id}`, { method: 'DELETE' }, t('Removing {kind} {domain}...', { kind: label, domain: alias.domain }));
    if (data) {
      setNotice(t('Removed {kind} {domain}.', { kind: label, domain: alias.domain }));
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
      setError(t('Certificate and private key are required.'));
      return;
    }
    const form = new FormData();
    if (manualSslFiles.certificate) form.append('certificate', manualSslFiles.certificate);
    else form.append('certificate_text', manualSslForm.certificate);
    if (manualSslFiles.private_key) form.append('private_key', manualSslFiles.private_key);
    else form.append('private_key_text', manualSslForm.private_key);
    if (manualSslFiles.ca_bundle) form.append('ca_bundle', manualSslFiles.ca_bundle);
    else if (manualSslForm.ca_bundle.trim()) form.append('ca_bundle_text', manualSslForm.ca_bundle);
    const data = await request(`/websites/${selectedWebsiteId}/ssl/manual`, { method: 'POST', body: form }, t('Installing manual SSL...'));
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
    else if (!cfZone.has_token) { setError(t('Paste a Cloudflare API token (Zone.DNS Edit).')); return; }
    const data = await request(`/websites/${selectedWebsiteId}/ssl/wildcard`,
      { method: 'POST', body: JSON.stringify(body) }, t('Issuing wildcard certificate via Cloudflare...'));
    if (data) {
      setWildcardToken('');
      setNotice(t('Wildcard SSL active — *.{source} covers this site.', { source: data.ssl_source_domain }));
      refreshAll();
    }
  }

  async function installSharedSsl() {
    if (!selectedWebsiteId || !sharedSource) return;
    const data = await request(`/websites/${selectedWebsiteId}/ssl/shared`,
      { method: 'POST', body: JSON.stringify({ source_domain: sharedSource }) },
      t('Using {domain}\'s certificate...', { domain: sharedSource }));
    if (data) {
      setNotice(t('Now serving {domain}\'s certificate.', { domain: sharedSource }));
      refreshAll();
    }
  }

  async function openNginxCustom(site) {
    setWordpressInstaller(null);
    setLogViewer(null);
    setTerminalViewer(null);
    setWebsiteSettingsForm(websiteConfigForm(site));
    const data = await request(`/websites/${site.id}/nginx-custom`, {}, t('Loading Custom Nginx...'));
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
    const uninstallQuestion = slug === 'mcp'
      ? t('Uninstall the MCP addon?\n\nAssistants can no longer reach the panel. Their tokens are kept and work again if you reinstall; revoke them on the Addons page to remove them.')
      : slug === 'fail2ban'
      ? t('Uninstall the Fail2ban addon?\n\nFail2ban is stopped, and every address it banned can connect again. Its settings are kept, and reinstalling puts them back.')
      : t('Uninstall the {name} addon?\n\nRunning applications will be stopped. Their folders, volumes and panel data are kept, and reinstalling picks up where they left off.', { name: label });
    if (!install && !confirm(uninstallQuestion)) return;
    const data = await request(`/addons/${slug}/${install ? 'install' : 'uninstall'}`, { method: 'POST' },
      install ? t('Installing {name}...', { name: label }) : t('Uninstalling {name}...', { name: label }));
    if (data) {
      setNotice(install
        ? `${t('{name} installed.', { name: label })} ${data.next_step ? serverText(data.next_step) : ''}`.trim()
        : `${t('{name} uninstalled.', { name: label })}${data.stopped?.length ? ` ${t('{count} application(s) stopped.', { count: data.stopped.length })}` : ''}`);
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
    }, t('Checking the compose file...'));
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
    const data = await request(`/site-apps/${app.id}`, { method: 'PUT', body: JSON.stringify(patch) }, t('Saving configuration...'));
    if (data) {
      setSiteAppEdit(null);
      setSiteAppEditPlan(null);
      setNotice(t('Saved {name}.', { name: data.name }));
      await loadSiteApps();
    }
  }

  async function loadSiteRuntimes() {
    const data = await request('/site-runtimes/status', { silent: true });
    if (data) setSiteRuntimes(data);
  }

  async function deploySiteApp(app) {
    const data = await request(`/site-apps/${app.id}/deploy`, { method: 'POST' }, t('Deploying {name}...', { name: app.name }));
    if (data) {
      setNotice(data.running ? t('{name} is running on port {port}.', { name: app.name, port: app.port }) : t('{name} was deployed but is not running — check the log.', { name: app.name }));
      // What it downloaded and installed, which is otherwise invisible.
      if (data.output) setSiteAppLog({ name: `${app.name} deploy`, log: data.output });
      await loadSiteApps();
    }
  }

  async function controlSiteApp(app, action) {
    const data = await request(`/site-apps/${app.id}/control`, { method: 'POST', body: JSON.stringify({ action }) }, t(ACTION_LABELS[action] || '{action} {name}...', { action, name: app.name }));
    if (data) {
      setNotice(data.running ? t('{name} is running.', { name: app.name }) : t('{name} is stopped.', { name: app.name }));
      await loadSiteApps();
    }
  }

  async function openSiteAppLog(app) {
    const data = await request(`/site-apps/${app.id}/logs?lines=300`, {}, t('Loading the {name} log...', { name: app.name }));
    if (data) setSiteAppLog({ name: app.name, log: data.log || t('No output yet.') });
  }

  async function installDockerEngine() {
    const data = await request('/site-runtimes/docker-install', { method: 'POST' }, t('Installing Docker, this takes a few minutes...'));
    if (data) {
      setNotice(data.message || t('Docker is ready.'));
      await loadSiteRuntimes();
    }
  }

  async function pruneDocker() {
    const data = await request('/site-runtimes/docker-prune', { method: 'POST' }, t('Removing unused Docker layers...'));
    if (data) {
      setNotice(data.message || t('Cleaned up.'));
      if (data.output) setSiteAppLog({ name: 'docker prune', log: data.output });
      await loadSiteRuntimes();
    }
  }

  async function installNodeMajor(major) {
    const data = await request('/site-runtimes/node-install', { method: 'POST', body: JSON.stringify({ major }) }, t('Installing Node {major}...', { major }));
    if (data) {
      setNotice(data.message || t('Node {major} is ready.', { major }));
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
    const data = await request('/site-apps', { method: 'POST', body: JSON.stringify(body) }, t('Creating application...'));
    if (data) {
      setNotice(t('Application {name} created. Upload your files to {directory} and press Deploy.', { name: data.name, directory: data.directory }));
      setSiteAppDraft(EMPTY_SITE_APP_DRAFT);
      setComposePlan(null);
      await loadSiteApps();
    }
  }

  async function updateSiteApp(app, patch, label = t('Updating application...')) {
    const data = await request(`/site-apps/${app.id}`, { method: 'PUT', body: JSON.stringify(patch) }, label);
    if (data) {
      setNotice(t('Updated {name}.', { name: data.name }));
      await loadSiteApps();
    }
  }

  async function deleteSiteApp(app) {
    if (!confirm(t('Delete application {name}? Its files stay on disk; only the runtime is removed.', { name: app.name }))) return;
    const data = await request(`/site-apps/${app.id}`, { method: 'DELETE' }, t('Deleting application...'));
    if (data) {
      setNotice(t('Deleted {name}.', { name: app.name }));
      await loadSiteApps();
    }
  }

  async function suggestSiteAppPort() {
    const data = await request('/site-apps/suggest-port', { silent: true });
    if (data?.port) setSiteAppDraft(prev => ({ ...prev, port: String(data.port) }));
  }

  async function viewFullNginxConfig() {
    if (!nginxCustomEditing) return;
    const data = await request(`/websites/${nginxCustomEditing.id}/nginx-config`, {}, t('Loading full Nginx config...'));
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
    }, t('Applying Custom Nginx and reloading...'));
    if (data) {
      setNotice(t('Updated Custom Nginx for {domain}', { domain: nginxCustomEditing.domain }));
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
        setError(t('Install an application first, on the Applications page.'));
        return;
      }
      if (!websiteSettingsForm.app_id) {
        setError(t('Pick which application this website should serve.'));
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
    }, t('Saving the settings of {domain}...', { domain: nginxCustomEditing.domain }));
    if (data) {
      setNotice(t('Updated settings for {domain}.', { domain: nginxCustomEditing.domain }));
      setWebsiteSettingsForm(websiteConfigForm(data));
      setNginxCustomEditing(prev => prev ? ({ ...prev, site: data }) : prev);
      await refreshAll();
    }
  }

  async function resetNginxDefault() {
    if (!nginxCustomEditing) return;
    if (!confirm(t('Clear Custom Nginx for {domain}?', { domain: nginxCustomEditing.domain }))) return;
    const data = await request(`/websites/${nginxCustomEditing.id}/nginx-custom`, {
      method: 'PUT',
      body: JSON.stringify({ nginx_custom: '' }),
    }, t('Clearing Custom Nginx...'));
    if (data) {
      setNotice(t('Cleared Custom Nginx for {domain}.', { domain: nginxCustomEditing.domain }));
      setNginxCustomEditing(null);
      await refreshAll();
    }
  }

  async function loadWebsiteLog(siteOrId = logViewer?.id, kind = logViewer?.kind || 'access', lines = logViewer?.lines || 200, domainLabel = logViewer?.domain || '') {
    const websiteId = typeof siteOrId === 'object' ? siteOrId.id : siteOrId;
    const domainName = typeof siteOrId === 'object' ? siteOrId.domain : domainLabel;
    if (!websiteId) return;
    const data = await request(`/websites/${websiteId}/logs?kind=${encodeURIComponent(kind)}&lines=${encodeURIComponent(lines)}`, {}, t('Loading the {kind} log...', { kind }));
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
      setError(t('Please fill all WordPress admin fields.'));
      return;
    }
    if (adminPasswordValue.length < 10) {
      setError(t('WordPress admin password must be at least 10 characters.'));
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
    }, t('Installing WordPress for {domain}...', { domain: wordpressInstaller.domain }));
    if (data) {
      setNotice(t('Installed WordPress: {url}\nAdmin: {user} | Password: {password}', { url: `https://${wordpressInstaller.domain}`, user: adminUser, password: adminPasswordValue }));
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
    }, t('Updating WordPress {part}...', { part: label }));
    if (data?.returncode && data.returncode !== 0) {
      setError(data.stderr || data.stdout || t('WordPress {part} update failed.', { part: label }));
      return;
    }
    if (data) {
      setNotice(t('Updated WordPress {part} for {domain}.', { part: label, domain: site.domain }));
    }
  }

  async function updateWordPressAll(site) {
    if (!site) return;
    setLoading(t('Updating WordPress...'));
    for (const action of ['core', 'plugins', 'themes']) {
      const data = await request('/maintenance/wordpress', {
        method: 'POST',
        body: JSON.stringify({ website_id: site.id, action }),
      });
      if (data?.returncode && data.returncode !== 0) {
        setError(data.stderr || data.stdout || t('WordPress {part} update failed.', { part: action }));
        setLoading('');
        return;
      }
    }
    setLoading('');
    setNotice(t('Updated WordPress core, plugins, and themes for {domain}.', { domain: site.domain }));
  }

  async function toggleWebsiteWaf(site) {
    const next = !site.waf_enabled;
    const data = await request(`/websites/${site.id}/waf`, {
      method: 'PATCH',
      body: JSON.stringify({ waf_enabled: next }),
    }, next ? t('Turning on the WAF for {domain}...', { domain: site.domain }) : t('Turning off the WAF for {domain}...', { domain: site.domain }));
    if (data) {
      setNotice(next ? t('The WAF is on for {domain}.', { domain: site.domain }) : t('The WAF is off for {domain}.', { domain: site.domain }));
      await refreshAll();
      if (String(selectedWafWebsiteId) === String(site.id)) await loadWebsiteWafConfig(site.id, false);
    }
  }

  async function fixWordPressPermissions(id) {
    const data = await request(`/maintenance/wordpress/${id}/fix-permissions`, { method: 'POST' }, t('Fixing permissions...'));
    if (data?.message) setNotice(data.message);
  }

  async function fixNginxSecurity(id) {
    const data = await request(`/websites/${id}/fix-nginx-security`, { method: 'POST' }, t('Rewriting Nginx security template...'));
    if (data?.message) setNotice(data.message);
  }

  async function changeDbPassword(id) {
    const newPass = prompt(t('A new password for the database, at least 12 characters:'));
    if (!newPass) return;
    await request(`/databases/${id}/password`, { method: 'POST', body: JSON.stringify({ password: newPass }) }, t('Changing the database password...'));
  }

  async function deleteDatabase(id, dbName) {
    if (!confirm(t('Delete the database {name}? This cannot be undone.', { name: dbName }))) return;
    const data = await request(`/databases/${id}`, { method: 'DELETE' }, t('Deleting the database...'));
    if (data) {
      setNotice(t('The database {name} is deleted.', { name: dbName }));
      await refreshAll();
    }
  }

  // Not in the Python: whose a database is - which decides whose backup it
  // is in - and which of their sites it is on.
  async function setDatabaseOwner(db, ownerId, websiteId) {
    const data = await request(`/databases/${db.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ owner_id: Number(ownerId), website_id: websiteId ? Number(websiteId) : null }),
    }, t('Moving {name}...', { name: db.db_name }));
    if (data) {
      setNotice(t('{name} now belongs to {owner}.', { name: db.db_name, owner: data.owner || '' }));
      await loadDatabases(dbSearch);
    }
    return !!data;
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
    if (!dbName) { setError(t('Type a name for the database.')); return; }
    if (!validDbName.test(dbName)) { setError(t('A database name is letters, digits and underscores only.')); return; }
    if (dbUser && !validDbName.test(dbUser)) { setError(t('A database user is letters, digits and underscores only.')); return; }
    if (dbPass && dbPass.length < 12) { setError(t('The password must be at least 12 characters.')); return; }
    if (dbPass && /[^\x20-\x7E]/.test(dbPass)) { setError(t('The password can only use plain ASCII characters.')); return; }
    const body = {
      db_name: dbName,
      db_user: dbUser || null,
      db_password: dbPass || null,
      // Not in the Python: an administrator may make it for somebody else,
      // and put it on one of their sites.
      ...(isAdmin && newDatabase.owner_id ? { owner_id: Number(newDatabase.owner_id) } : {}),
      website_id: newDatabase.website_id ? Number(newDatabase.website_id) : null,
    };
    const data = await request('/databases', { method: 'POST', body: JSON.stringify(body) }, t('Creating the database...'));
    if (data) {
      setCreatedDbInfo({ db_name: data.db_name, db_user: data.db_user, db_password: data.db_password });
      setNewDatabase({ db_name: '', db_user: '', db_password: '', owner_id: newDatabase.owner_id, website_id: '' });
      await refreshAll();
    }
  }

  async function addCron() {
    const data = await request('/maintenance/cron', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId), schedule: cronSchedule, command: cronCommand }) }, t('Adding cron job...'));
    if (data) {
      if (data.cron_user) setCronUser(data.cron_user);
      setNotice(data.cron_user ? t('Cron job added, running as {user}.', { user: data.cron_user }) : t('Cron job added.'));
      await listCron();
    }
  }

  async function listCron() {
    if (!selectedWebsiteId) return;
    const data = await request(`/maintenance/cron/${selectedWebsiteId}`, {}, t('Loading cron jobs...'));
    if (data?.items) setCronItems(data.items);
    if (data?.cron_user) setCronUser(data.cron_user);
    if (data?.php_binary) setCronPhpInfo({ php_binary: data.php_binary, php_version: data.php_version || '' });
  }

  async function deleteCron(index) {
    if (!confirm(t('Delete cron #{index}?', { index }))) return;
    index = Number(index);
    if (Number.isNaN(index)) return;
    const data = await request('/maintenance/cron', { method: 'DELETE', body: JSON.stringify({ website_id: Number(selectedWebsiteId), index }) }, t('Deleting cron job...'));
    if (data) {
      if (data.cron_user) setCronUser(data.cron_user);
      setNotice(t('Cron job deleted.'));
      await listCron();
    }
  }

  async function listFiles(path = fileListPath) {
    if (!hasFileTarget()) return;
    const data = await request(`${fileTargetBase()}?path=${encodeURIComponent(path)}`, {}, t('Loading file list...'));
    if (data?.items) { setFiles(data.items); setFileListPath(path); setFileUploadDir(path || ''); setSelectedFilePaths([]); }
  }

  async function readFile(pathOverride = filePath) {
    const targetPath = pathOverride || filePath;
    if (!hasFileTarget() || !targetPath) return;
    if (pathOverride) setFilePath(pathOverride);
    const data = await request(`${fileTargetBase()}/read?path=${encodeURIComponent(targetPath)}`, {}, t('Reading file...'));
    if (data?.content !== undefined) {
      setFileContent(data.content);
      setEditorCursor({ line: 1, column: 1 });
    }
  }

  async function writeFile() {
    const data = await request('/maintenance/files/write', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: filePath, content: fileContent }) }, t('Saving file...'));
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function downloadFile(path) {
    if (!hasFileTarget() || !path) return;
    try {
      setError(''); setLoading(t('Downloading file...'));
      const res = await fetch(`${API}${fileTargetBase()}/download?path=${encodeURIComponent(path)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Download failed.'))); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = path.split('/').pop() || 'download';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
    } catch (err) { setError(t('File download failed.')); }
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
    const name = prompt(t('Folder name:'));
    if (!name) return;
    const data = await request('/maintenance/files/mkdir', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: fileListPath || '', name }) }, t('Creating folder...'));
    if (data) await listFiles(fileListPath);
  }

  async function makeFile() {
    if (!hasFileTarget()) return;
    const name = prompt(t('File name:'), 'new-file.txt');
    if (!name) return;
    const data = await request('/maintenance/files/create', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: fileListPath || '', name }) }, t('Creating file...'));
    if (data) {
      await listFiles(fileListPath);
      const newPath = [fileListPath, name].filter(Boolean).join('/');
      openFileEditorTab(newPath);
    }
  }

  async function renameFileItem(item) {
    if (!item) return;
    const newName = prompt(t('New name:'), item.name);
    if (!newName || newName === item.name) return;
    const data = await request('/maintenance/files/rename', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), path: item.path, new_name: newName }) }, t('Renaming...'));
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
    if (!/^[0-7]{3,4}$/.test(mode)) { setError(t('Mode must be octal, for example 644 or 755.')); return; }
    for (const item of targets) {
      const data = await request('/maintenance/files/chmod', {
        method: 'POST',
        body: JSON.stringify({ ...fileTargetBody(), path: item.path, mode }),
      }, t('Setting permissions on {name}...', { name: item.name }));
      // request() already surfaced the reason; stop so the dialog keeps the mode.
      if (!data) return;
    }
    setChmodTarget(null);
    setNotice(t('Permissions set to {mode} on {count} item(s).', { mode, count: targets.length }));
    await listFiles(fileListPath);
  }

  async function deleteSelectedFiles() {
    if (selectedFilePaths.length === 0) return;
    if (!confirm(t('Delete {count} selected item(s)?', { count: selectedFilePaths.length }))) return;
    const data = await request('/maintenance/files/delete', { method: 'POST', body: JSON.stringify({ ...fileTargetBody(), paths: selectedFilePaths }) }, t('Deleting selected files...'));
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function transferFileItems(action, paths) {
    if (!hasFileTarget() || !paths?.length) return;
        const destination = prompt(action === 'copy' ? t('Copy to folder:') : t('Move to folder:'), fileListPath || 'public_html');
    if (destination === null) return;
    const targetPath = destination.trim() || fileListPath || 'public_html';
    const data = await request(`/maintenance/files/${action}`, {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), paths, destination_path: targetPath }),
    }, action === 'copy' ? t('Copying files...') : t('Moving files...'));
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
    const outputName = prompt(t('Archive file name:'), `archive-${Date.now()}.${ext}`);
    if (!outputName) return;
    const data = await request('/maintenance/files/archive', {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), base_path: fileListPath || '', paths: selectedFilePaths, output_name: outputName, format: archiveFormat }),
    }, t('Creating archive...'));
    if (data) { await listFiles(fileListPath); await loadCurrentUser(); }
  }

  async function extractArchiveFile(path) {
    if (!hasFileTarget() || !path) return;
    const destination = prompt(t('Extract to folder:'), fileListPath || '.');
    if (destination === null) return;
    const targetPath = destination.trim() || fileListPath || '.';
    const data = await request('/maintenance/files/extract', {
      method: 'POST',
      body: JSON.stringify({ ...fileTargetBody(), archive_path: path, destination_path: targetPath }),
    }, t('Starting extraction...'));
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
          setNotice(data.message || t('Extraction completed'));
          await listFiles(data.destination_path || fileListPath);
          await loadCurrentUser();
          continue;
        }
        upsertFileJob(data);
        if (data.status === 'error') {
          setError(formatApiError(data.error, t('Extraction failed')));
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
    if (!hasFileTarget()) { setError(t('Please select a website or application first.')); return; }
    const uploadDir = fileUploadDir.trim();
    const form = new FormData();
    form.append('file', file);
    try {
      setError('');
      setLoading(t('Uploading file...'));
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
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Upload failed.'))); return; }
      setNotice(uploadDir ? t('Uploaded {name} to {folder}.', { name: file.name, folder: uploadDir }) : t('Uploaded {name} to the site root.', { name: file.name }));
      if (String(fileListPath || '') === uploadDir) await listFiles(uploadDir);
      await loadCurrentUser();
    } catch (err) { setError(t('File upload failed.')); }
    finally { setLoading(''); }
  }

  async function createBackup() {
    const data = await request('/maintenance/backup', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId) }) }, t('Queueing backup...'));
    if (data?.job_id) { setNotice(t('Backup queued. It will keep running on the server.')); await loadBackupJobs(); }
    else if (data?.backup_file) { setNotice(t('Created backup: {file}', { file: data.backup_file })); await listBackups(); }
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
    await loadS3Targets();
    await loadBackupSchedules();
    await loadBackupJobs();
  }

  async function listUserBackups(userId = selectedBackupUserId) {
    if (!userId) return;
    const data = await request(`/maintenance/user-backups/${userId}`);
    if (data?.items) setUserBackups(data.items);
  }

  // A destination picker's value as the API's two ids: an SFTP target or an S3 one.
  function destinationIds(value) {
    const [kind, id] = String(value || '').split(':');
    return {
      target_id: kind === 'sftp' ? Number(id) : null,
      s3_target_id: kind === 's3' ? Number(id) : null,
    };
  }

  async function createUserBackup() {
    if (!selectedBackupUserId) return;
    const body = {
      user_id: Number(selectedBackupUserId),
      ...destinationIds(userBackupDestination),
    };
    const data = await request('/maintenance/user-backup', { method: 'POST', body: JSON.stringify(body) }, t('Queueing full user backup...'));
    if (data?.job_id) { setNotice(t('Full user backup queued. It will keep running on the server.')); await loadBackupJobs(); }
    else if (data?.backup_file) {
      setNotice(data.remote_file ? t('Full user backup uploaded: {file}', { file: data.remote_file }) : t('Created full user backup: {file}', { file: data.backup_file }));
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
      ...destinationIds(newBackupSchedule.destination),
      name_style: newBackupSchedule.name_style || 'timestamp',
      retention: Number(newBackupSchedule.retention || 7),
      is_active: true,
    };
    const data = await request('/maintenance/backup-schedules', { method: 'POST', body: JSON.stringify(body) }, t('Saving backup schedule...'));
    if (data) {
      setNotice(t('Backup schedule saved.'));
      await loadBackupSchedules();
    }
  }

  async function deleteBackupSchedule(id) {
    if (!confirm(t('Delete this backup schedule?'))) return;
    const data = await request(`/maintenance/backup-schedules/${id}`, { method: 'DELETE' }, t('Deleting backup schedule...'));
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
    const data = await request('/maintenance/sftp-targets', { method: 'POST', body: JSON.stringify(body) }, t('Saving SFTP target...'));
    if (data) {
      setNotice(t('Saved SFTP target {name}', { name: data.name }));
      setNewSftpTarget({ name: '', host: '', port: 22, username: '', password: '', private_key: '', remote_path: '/backups/snpanel' });
      await loadSftpTargets();
    }
  }

  async function deleteSftpTarget(id) {
    if (!confirm(t('Delete this SFTP target?'))) return;
    const data = await request(`/maintenance/sftp-targets/${id}`, { method: 'DELETE' }, t('Deleting SFTP target...'));
    if (data) await loadSftpTargets();
  }

  async function loadS3Targets() {
    const data = await request('/maintenance/s3-targets');
    if (data) setS3Targets(data);
  }

  // Creates one when `id` is null. The saved destination, or null.
  async function saveS3Target(id, body) {
    const data = await request(
      id ? `/maintenance/s3-targets/${id}` : '/maintenance/s3-targets',
      { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) },
      t('Saving S3 destination...'),
    );
    if (data) {
      setNotice(t('Saved S3 destination {name}.', { name: data.name }));
      await loadS3Targets();
    }
    return data;
  }

  async function deleteS3Target(id) {
    if (!confirm(t('Delete this S3 destination?'))) return;
    const data = await request(`/maintenance/s3-targets/${id}`, { method: 'DELETE' }, t('Deleting S3 destination...'));
    if (data) await loadS3Targets();
  }

  // Writes a small file to the bucket and removes it again.
  async function testS3Target(target) {
    const data = await request(`/maintenance/s3-targets/${target.id}/test`, { method: 'POST' }, t('Testing S3 destination...'));
    if (data) {
      setNotice(data.removed
        ? t('{name} accepts backups.', { name: target.name })
        : t('{name} accepts backups. The key may not delete, so the test file is still in the bucket.', { name: target.name }));
    }
    return data;
  }

  async function createSftpBackup() {
    if (!selectedWebsiteId || !selectedSftpTargetId) return;
    const data = await request('/maintenance/backup-sftp', {
      method: 'POST',
      body: JSON.stringify({ website_id: Number(selectedWebsiteId), target_id: Number(selectedSftpTargetId) }),
    }, t('Queueing SFTP backup...'));
    if (data?.job_id) {
      setNotice(t('SFTP backup queued. It will keep running on the server.'));
      await loadBackupJobs();
    } else if (data?.remote_file) {
      setNotice(t('SFTP backup uploaded: {file}', { file: data.remote_file }));
      await listBackups();
    }
  }

  async function restoreBackup(file) {
    if (!confirm(t('Restore this backup to the current website?\n{file}', { file }))) return;
    await request('/maintenance/restore', { method: 'POST', body: JSON.stringify({ website_id: Number(selectedWebsiteId), backup_file: file }) }, t('Restoring backup...'));
  }

  async function downloadBackup(file) {
    if (!selectedWebsiteId) return;
    try {
      setError(''); setLoading(t('Downloading backup...'));
      const res = await fetch(`${API}/maintenance/backups/${selectedWebsiteId}/download?backup_file=${encodeURIComponent(file)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Download failed.'))); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = file.split('/').pop() || 'backup.tar.gz';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice(t('Backup downloaded.'));
    } catch (err) { setError(t('Backup download failed.')); }
    finally { setLoading(''); }
  }

  async function downloadUserBackup(file) {
    try {
      setError(''); setLoading(t('Downloading full user backup...'));
      const res = await fetch(`${API}/maintenance/user-backups-download?backup_file=${encodeURIComponent(file)}`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Download failed.'))); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = file.split('/').pop() || 'user-backup.tar.gz';
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice(t('Full user backup downloaded.'));
    } catch (err) { setError(t('Full user backup download failed.')); }
    finally { setLoading(''); }
  }

  async function restoreUserBackup(file) {
    if (!confirm(t('Restore this full user backup? Missing panel user and websites will be created.\n{file}', { file }))) return;
    const data = await request('/maintenance/user-restore', { method: 'POST', body: JSON.stringify({ backup_file: file }) }, t('Restoring full user backup...'));
    if (data) {
      setNotice(t('Restored user {name}. Websites: {count}', { name: data.username, count: data.websites?.length || 0 }));
      await refreshAll();
      await loadUsers();
      await listUserBackups();
      await loadRestoreBackups();
    }
  }

  async function deleteUserBackup(file) {
    if (!confirm(t('Delete this full user backup?\n{file}', { file }))) return;
    const data = await request(`/maintenance/user-backups?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, t('Deleting full user backup...'));
    if (data) {
      await listUserBackups();
      await loadRestoreBackups();
    }
  }

  async function deleteRestoreBackup(file) {
    if (!confirm(t('Delete this restore backup?\n{file}', { file }))) return;
    const data = await request(`/maintenance/user-restore-backups?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, t('Deleting restore backup...'));
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
      setError(''); setLoading(t('Uploading full user backups...'));
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
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Upload failed.'))); return; }
      setNotice(t('Uploaded {count} full user backup file(s).', { count: data.items?.length || selectedFiles.length }));
      await loadRestoreBackups();
      await listUserBackups();
    } catch (err) { setError(t('Full user backup upload failed.')); }
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
      setError(''); setLoading(t('Uploading DA backup...'));
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/maintenance/da-import/upload`, {
        method: 'POST', credentials: 'include', headers, body: form,
      });
      const text = await res.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text || `HTTP ${res.status}` }; }
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Upload failed.'))); return; }
      setNotice(t('Uploaded: {file}', { file: data.filename }));
      await listDaBackups();
    } catch (err) { setError(t('DA backup upload failed.')); }
    finally { setLoading(''); }
  }

  async function scanDaBackup(archivePath) {
    setDaScanResult(null);
    const data = await request('/maintenance/da-import/scan', { method: 'POST', body: JSON.stringify({ archive_path: archivePath }) }, t('Scanning DA backup...'));
    if (data) setDaScanResult(data);
  }

  async function importDaBackup(archivePath, force = daReplaceExisting) {
    const message = force
      ? t('Import and REPLACE? Any existing panel user, website, files and databases with the same names are deleted first.')
      : t('Import this DirectAdmin backup? This will create users, websites, databases, and nginx configs.');
    if (!confirm(message)) return;
    setDaImportJob(null);
    const data = await request('/maintenance/da-import/import', { method: 'POST', body: JSON.stringify({ archive_path: archivePath, force }) }, t('Starting DA import...'));
    if (data?.job_id) {
      setNotice(t('DA import started. Polling for result...'));
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
      if (data.status === 'completed') { setNotice(t('DA import completed successfully!')); await listDaBackups(); return; }
      if (data.status === 'failed') { setError(t('DA import failed: {error}', { error: data.error || t('Unknown error') })); return; }
      attempts++;
    }
  }

  async function deleteDaBackup(archivePath) {
    if (!confirm(t('Delete this DA backup file?'))) return;
    const data = await request('/maintenance/da-import/backups', { method: 'DELETE', body: JSON.stringify({ archive_path: archivePath }) }, t('Deleting DA backup...'));
    if (data) { setNotice(t('Deleted: {file}', { file: data.deleted })); setDaScanResult(null); await listDaBackups(); }
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
      ? t('Restore and REPLACE {count} backup(s)? Existing users, websites, files and databases with the same names are deleted first.', { count: selectedDaBackups.length })
      : t('Restore {count} backup(s)? This will create users, websites, databases, and nginx configs for each.', { count: selectedDaBackups.length });
    if (!confirm(message)) return;
    setDaBulkImportJob(null);
    setDaImportJob(null);
    setDaScanResult(null);
    const data = await request('/maintenance/da-import/bulk-import', { method: 'POST', body: JSON.stringify({ archive_paths: selectedDaBackups, force }) }, t('Starting bulk restore...'));
    if (data?.job_id) {
      setNotice(t('Bulk restore started: {count} backup(s). Processing sequentially...', { count: data.total }));
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
        setNotice(t('Bulk restore done: {ok} succeeded, {fail} failed.', { ok, fail }));
        await listDaBackups();
        return;
      }
      attempts++;
    }
  }

  async function bulkDeleteDaBackups() {
    if (selectedDaBackups.length === 0) return;
    if (!confirm(t('Delete {count} selected backup file(s)?', { count: selectedDaBackups.length }))) return;
    for (const path of selectedDaBackups) {
      await request('/maintenance/da-import/backups', { method: 'DELETE', body: JSON.stringify({ archive_path: path }) }, t('Deleting...'));
    }
    setNotice(t('Deleted {count} backup(s).', { count: selectedDaBackups.length }));
    setSelectedDaBackups([]);
    setDaScanResult(null);
    await listDaBackups();
  }

  async function openPhpMyAdmin(databaseId) {
    try {
      setError(''); setLoading(t('Opening phpMyAdmin...'));
      const csrfToken = readCookie('snpanel_csrf');
      const headers = csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
      const res = await fetch(`${API}/databases/${databaseId}/phpmyadmin-sso`, {
        method: 'POST',
        credentials: 'include',
        headers,
      });
      const data = await res.json().catch(() => ({}));
      if (handleAuthExpired(res.status, data.detail)) return;
      if (!res.ok || !data.url) { setError(formatApiError(data.detail, t('Cannot open phpMyAdmin.'))); return; }
      window.open(data.url, '_blank', 'noopener,noreferrer');
    } catch (err) { setError(t('Cannot open phpMyAdmin.')); }
    finally { setLoading(''); }
  }

  async function downloadDatabase(databaseId, databaseName) {
    try {
      setError(''); setLoading(t('Downloading the database...'));
      const res = await fetch(`${API}/databases/${databaseId}/download`, { credentials: 'include' });
      if (!res.ok) { const data = await res.json().catch(() => ({})); if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Download failed.'))); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `${databaseName || 'database'}.sql`;
      document.body.appendChild(link); link.click(); link.remove();
      URL.revokeObjectURL(url);
      setNotice(t('The database SQL is downloaded.'));
    } catch (err) { setError(t('The database download failed.')); }
    finally { setLoading(''); }
  }

  async function deleteBackup(file) {
    if (!confirm(t('Delete this backup?\n{file}', { file }))) return;
    const data = await request(`/maintenance/backups/${selectedWebsiteId}?backup_file=${encodeURIComponent(file)}`, { method: 'DELETE' }, t('Deleting backup...'));
    if (data) await listBackups();
  }

  async function uploadBackup(file) {
    if (!file || !selectedWebsiteId) return;
    const form = new FormData();
    form.append('file', file);
    try {
      setError(''); setLoading(t('Uploading backup...'));
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
      if (!res.ok) { if (handleAuthExpired(res.status, data.detail)) return; setError(formatApiError(data.detail, t('Upload failed.'))); return; }
      if (data.backup_file) { setNotice(t('Uploaded backup: {file}', { file: data.backup_file })); await listBackups(); }
    } catch (err) { setError(t('Upload backup failed.')); }
    finally { setLoading(''); }
  }

  async function checkService(name) {
    const data = await request('/services/action', { method: 'POST', body: JSON.stringify({ name, action: 'status' }) });
    setServiceStates(prev => ({ ...prev, [name]: data || { stdout: '', stderr: error || t('Cannot check'), returncode: 1 } }));
    return data;
  }

  async function loadServiceNames() {
    const data = await request('/services/list');
    const names = data?.services?.length ? data.services : serviceNames;
    setServiceNames(names);
    return names;
  }

  async function checkAllServices() {
    setLoading(t('Checking services...'));
    const names = await loadServiceNames();
    for (const name of names) { await checkService(name); }
    setLoading('');
  }

  async function runServiceAction(name, action) {
    await request('/services/action', { method: 'POST', body: JSON.stringify({ name, action }) }, t(ACTION_LABELS[action] || '{action} {name}...', { action, name }));
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
    }, next ? t('Turning on OPcache for PHP {version}...', { version }) : t('Turning off OPcache for PHP {version}...', { version }));
    if (data) {
      setNotice(data.message || t('OPcache changed.'));
      await loadPhpTune(version);
    }
  }

  async function applyPhpTune() {
    const version = phpTune?.php_version || phpConfig.php_version;
    const data = await request('/maintenance/php-tune', {
      method: 'POST',
      body: JSON.stringify({ php_version: version }),
    }, t('Tuning PHP for this server...'));
    if (data) {
      if (data.plan) setPhpTune(data.plan);
      setPhpTuneApplied(true);
      await loadPhpConfig(version);
    }
  }

  async function loadPhpConfig(version = phpConfig.php_version) {
    const data = await request(`/maintenance/php-config?php_version=${encodeURIComponent(version)}`, {}, t('Loading PHP config...'));
    if (data) setPhpConfig(prev => ({ ...prev, ...data, php_version: version }));
  }

  async function updatePhpConfig() {
    const data = await request('/maintenance/php-config', {
      method: 'POST',
      body: JSON.stringify({ ...phpConfig, max_execution_time: Number(phpConfig.max_execution_time), max_input_time: Number(phpConfig.max_input_time), max_input_vars: Number(phpConfig.max_input_vars) }),
    }, t('Updating PHP config...'));
    if (data?.target) { setNotice(t('Updated PHP config: {target}', { target: data.target })); await loadPhpConfig(phpConfig.php_version); }
  }

  async function restorePhpDefaults() {
    if (!confirm(t('Restore default PHP {version} values?', { version: phpConfig.php_version }))) return;
    const data = await request('/maintenance/php-config/defaults', {
      method: 'POST',
      body: JSON.stringify({ php_version: phpConfig.php_version }),
    }, t('Restoring PHP defaults...'));
    if (data?.values) {
      setPhpConfig(prev => ({ ...prev, ...data.values }));
      setNotice(t('Restored PHP {version} defaults.', { version: phpConfig.php_version }));
    }
  }

  async function loadPhpVersions() {
    const data = await request('/maintenance/php-versions', {}, t('Loading PHP versions...'));
    if (data) setPhpVersions({
      installed: sortPhpVersions(data.installed || []),
      supported: sortPhpVersions(data.supported || []),
    });
  }

  async function installPhpVersion(version) {
    if (!confirm(t('Install PHP {version}? This will install php{version}-fpm via apt.', { version }))) return;
    const data = await request(`/maintenance/php-versions/${version}/install`, { method: 'POST' }, t('Installing PHP {version}...', { version }));
    if (data) { setNotice(t('PHP {version} installed successfully.', { version })); await loadPhpVersions(); await loadServiceNames(); }
  }

  async function loadFirewall() {
    const data = await request('/firewall/status', {}, t('Loading firewall...'));
    if (data) setFirewallStatus(data);
  }

  // The Fail2ban addon's page: every answer is the whole page again.
  async function loadFail2ban() {
    const data = await request('/fail2ban', {}, t('Loading Fail2ban...'));
    if (data) setFail2ban(data);
  }

  async function saveFail2banSettings(settings) {
    const data = await request('/fail2ban/settings', { method: 'PUT', body: JSON.stringify(settings) }, t('Saving Fail2ban settings...'));
    if (data) { setFail2ban(data); setNotice(t('Fail2ban settings saved.')); }
    return !!data;
  }

  async function fail2banBan(jail, address) {
    const data = await request('/fail2ban/ban', { method: 'POST', body: JSON.stringify({ jail, address }) }, t('Banning {address}...', { address }));
    if (data) { setFail2ban(data); setNotice(t('{address} is banned.', { address })); }
    return !!data;
  }

  async function loadMcp() {
    const info = await request('/mcp/info', { silent: true });
    if (info) setMcpInfo(info);
    const data = await request('/mcp/tokens', { silent: true });
    if (data?.items) setMcpTokens(data.items);
  }

  async function loadAllMcpTokens() {
    const data = await request('/mcp/tokens?all=true', { silent: true });
    if (data?.items) setMcpAllTokens(data.items);
  }

  // The answer carries the token itself, this once.
  async function createMcpToken(body) {
    const data = await request('/mcp/tokens', { method: 'POST', body: JSON.stringify(body) }, t('Creating the token...'));
    if (data) await loadMcp();
    return data;
  }

  async function revokeMcpToken(token, everyones = false) {
    if (!confirm(t('Revoke the token {name}? An assistant using it loses access at once.', { name: token.name }))) return;
    const data = await request(`/mcp/tokens/${token.id}`, { method: 'DELETE' }, t('Revoking the token...'));
    if (data) {
      setNotice(t('Token {name} revoked.', { name: token.name }));
      if (everyones) await loadAllMcpTokens();
      else await loadMcp();
    }
  }

  async function revokeAllMcpTokens() {
    if (!confirm(t('Revoke every MCP token on this panel? Every assistant loses access at once.'))) return;
    const data = await request('/mcp/tokens?all=true', { method: 'DELETE' }, t('Revoking every token...'));
    if (data) {
      setNotice(t('{count} token(s) revoked.', { count: data.revoked }));
      await loadAllMcpTokens();
    }
  }

  async function fail2banUnban(address) {
    const data = await request('/fail2ban/unban', { method: 'POST', body: JSON.stringify({ address }) }, t('Letting {address} back in...', { address }));
    if (data) { setFail2ban(data); setNotice(t('{address} can connect again.', { address })); }
  }

  // A user's SFTP login - see components/SftpAccess.jsx.
  async function loadSftpAccess(userId) {
    return await request(`/users/${userId}/sftp`);
  }

  async function switchSftpAccess(user, enabled, choice = {}) {
    if (!enabled && !confirm(t('Turn SFTP off for {name}?\n\nThey can no longer sign in over SFTP. Turning it on again sets a new password.', { name: user.username }))) return null;
    const data = await request(`/users/${user.id}/sftp`, { method: 'PUT', body: JSON.stringify({ enabled, ...choice }) },
      enabled ? t('Turning SFTP on...') : t('Turning SFTP off...'));
    if (data) {
      setNotice(enabled ? t('SFTP is on for {name}.', { name: user.username }) : t('SFTP is off for {name}.', { name: user.username }));
      if (page === 'users') loadUsers();
    }
    return data;
  }

  async function setSftpPassword(user, body) {
    const data = await request(`/users/${user.id}/sftp/password`, { method: 'POST', body: JSON.stringify(body) }, t('Setting the SFTP password...'));
    if (data) {
      setNotice(t('The SFTP password is set.'));
      if (page === 'users') loadUsers();
    }
    return data;
  }

  async function runFirewallAction(path, options = {}, label = t('Updating firewall...')) {
    const data = await request(path, options, label);
    if (data) { setNotice((data.stdout || data.stderr || t('Firewall updated.')).trim()); await loadFirewall(); }
    return !!data;
  }

  async function enableFirewall() {
    if (!confirm(t('Turn the firewall on now? SSH, the panel port and the web and mail ports stay open.'))) return;
    await runFirewallAction('/firewall/enable', { method: 'POST' }, t('Turning the firewall on...'));
  }
  async function disableFirewall() {
    if (!confirm(t('Turn the firewall off? Every port on this server will be reachable.'))) return;
    await runFirewallAction('/firewall/disable', { method: 'POST' }, t('Turning the firewall off...'));
  }
  async function reloadFirewall() { await runFirewallAction('/firewall/reload', { method: 'POST' }, t('Reloading the firewall rules...')); }

  // One form for what were three - open a port, allow an address, block an
  // address - sent to whichever endpoint its fields call for. Blocking needs
  // an address: the helper refuses to deny a port to everyone.
  async function addFirewallRule() {
    const ip = firewallRule.ip.trim();
    const port = firewallRule.port.trim();
    const { action, protocol } = firewallRule;
    let done = false;
    if (action === 'block') {
      if (!ip) return;
      if (!confirm(t('Block {address}?', { address: port ? `${ip} (${port}/${protocol})` : ip }))) return;
      done = await runFirewallAction('/firewall/block-ip', { method: 'POST', body: JSON.stringify({ ip, port: port || null, protocol }) }, t('Blocking...'));
    } else if (ip) {
      done = await runFirewallAction('/firewall/allow-ip', { method: 'POST', body: JSON.stringify({ ip, port: port || null, protocol }) }, t('Allowing...'));
    } else if (port) {
      done = await runFirewallAction('/firewall/allow-port', { method: 'POST', body: JSON.stringify({ port, protocol }) }, t('Opening the port...'));
    }
    if (done) setFirewallRule(prev => ({ ...prev, ip: '', port: '' }));
  }

  async function deleteFirewallRule(number) {
    if (!confirm(t('Delete firewall rule #{number}?', { number }))) return;
    await runFirewallAction(`/firewall/rules/${encodeURIComponent(number)}`, { method: 'DELETE' }, t('Deleting the rule...'));
  }

  async function loadFirewallBlocklists() {
    const data = await request('/firewall/blocklists', {}, t('Loading IP blocklists...'));
    if (data) setFirewallBlocklists(data);
  }

  async function addFirewallBlocklistUrl() {
    const url = firewallBlocklistUrl.trim();
    if (!url) return;
    const data = await request('/firewall/blocklists', { method: 'POST', body: JSON.stringify({ url }) }, t('Adding the blocklist...'));
    if (data) {
      setNotice((data.stdout || data.stderr || t('Blocklist added.')).trim());
      setFirewallBlocklistUrl('');
      await loadFirewallBlocklists();
    }
  }

  async function deleteFirewallBlocklistUrl(url) {
    if (!confirm(t('Remove the blocklist {url}?', { url }))) return;
    const data = await request('/firewall/blocklists/delete', { method: 'POST', body: JSON.stringify({ url }) }, t('Removing the blocklist...'));
    if (data) {
      setNotice((data.stdout || data.stderr || t('Blocklist removed.')).trim());
      await loadFirewallBlocklists();
    }
  }

  async function updateFirewallBlocklistsNow() {
    const data = await request('/firewall/blocklists/update', { method: 'POST' }, t('Updating the blocklists...'));
    if (data) {
      setNotice((data.stdout || data.stderr || t('Blocklists updated.')).trim());
      await loadFirewall();
      await loadFirewallBlocklists();
    }
  }

  async function loadWafRules() {
    const data = await request('/waf/rules', {}, t('Loading WAF rules...'));
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
    const data = await request(`/waf/websites/${websiteId}`, {}, showLoading ? t('Loading website WAF...') : '');
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
    }, t('Saving blocked bots...'));
    if (data) {
      setSiteBotText((data.blocked_bots || []).join('\n'));
      setNotice(data.message || t('Blocked bots saved.'));
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
    const data = await request('/waf/bots', {}, t('Loading blocked bots...'));
    if (data) {
      setBotBlocks(data);
      setGlobalBots(data.global_blocked_bots || []);
    }
  }

  async function saveGlobalBots(nextList) {
    const data = await request('/waf/bots/global', {
      method: 'PUT',
      body: JSON.stringify({ blocked_bots: nextList.join('\n') }),
    }, t('Saving global bad bots...'));
    if (data) {
      setGlobalBots(data.global_blocked_bots || []);
      setNotice(data.failed?.length
        ? `${serverText(data.message)} ${t('Failed: {list}', { list: data.failed.map(f => `${f.domain} (${serverText(f.error)})`).join('; ') })}`
        : (data.message || t('Global bad bots saved.')));
      await loadBotBlocks();
    }
  }

  async function loadCrs() {
    const data = await request('/waf/crs', { silent: true });
    if (data) setCrs(data);
  }

  async function saveCrsMode(mode) {
    if (mode === 'block' && !confirm(t('Switch OWASP CRS to blocking?\n\nEvery website with the WAF on will start refusing requests that score above the threshold. Run detect mode first and read the logs, or a legitimate request somebody depends on may be the one it stops.'))) return;
    const data = await request('/waf/crs', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }, t('Switching OWASP CRS to {mode}...', { mode }));
    if (data) await loadCrs();
  }

  async function toggleSiteCrs(row) {
    const turningOn = !row.crs_enabled;
    if (turningOn && !confirm(t('Load OWASP CRS on {domain}?\n\nThis adds roughly {mb} MB to nginx for this site. Check the measured figure on this page afterwards rather than trusting the estimate.', { domain: row.domain, mb: crs?.rss_mb_per_site || 50 }))) return;
    const data = await request(`/waf/websites/${row.website_id}/crs`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: turningOn }),
    }, turningOn ? t('Loading OWASP CRS on {domain}...', { domain: row.domain }) : t('Unloading OWASP CRS from {domain}...', { domain: row.domain }));
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
    }, t('Saving website WAF rules...'));
    if (data) {
      setWafSiteConfig(data);
      setWafCustomRules(data.custom_rules || '');
      setNotice(data.message || t('Website WAF rules saved.'));
      await refreshAll();
    }
  }

  async function saveWebsiteHttpFlood() {
    if (!selectedWafWebsiteId || !wafSiteConfig) return;
    const config = normalizeHttpFloodConfig(httpFloodForm);
    const data = await request(`/websites/${selectedWafWebsiteId}/http-flood`, {
      method: 'PATCH',
      body: JSON.stringify({ http_flood_enabled: !!httpFloodForm.http_flood_enabled, ...config }),
    }, t('Saving HTTP Flood settings...'));
    if (data) {
      setNotice(t('HTTP Flood settings saved for {domain}.', { domain: data.domain }));
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
    const data = await request(`/waf/access-logs?${params.toString()}`, {}, showLoading ? t('Loading access logs...') : '');
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
    if (!confirm(t('Clear access logs for {label}?', { label }))) return;
    const params = new URLSearchParams();
    if (wafAccessLogFilters.websiteId) params.set('website_id', wafAccessLogFilters.websiteId);
    const suffix = params.toString() ? `?${params.toString()}` : '';
    const data = await request(`/waf/access-logs${suffix}`, { method: 'DELETE' }, t('Clearing access logs...'));
    if (data) {
      setNotice(data.message || t('Access logs cleared.'));
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
    const data = await request(`/updates/status${force ? '?refresh=true' : ''}`, {}, t('Loading update status...'));
    if (data) setUpdatesStatus(data);
  }

  async function toggleUpdateLog() {
    if (!showUpdateLog && !updatesStatus) await loadUpdates();
    setShowUpdateLog(prev => !prev);
  }

  async function runOsUpdate() {
    if (!confirm(t('Run apt-get update && apt-get upgrade now?'))) return;
    setOsUpdating(true);
    const data = await request('/updates/os/run', { method: 'POST' }, t('Updating OS packages...'));
    setOsUpdating(false);
    if (data) { setNotice((data.stdout || data.stderr || t('OS update completed.')).trim()); if (showUpdateLog) await loadUpdates(); }
  }

  async function saveOsAutoUpdate() {
    const data = await request('/updates/os/auto', { method: 'POST', body: JSON.stringify(osAutoUpdate) }, t('Saving OS auto update...'));
    if (data) { setNotice((data.stdout || data.stderr || t('OS auto update saved.')).trim()); if (showUpdateLog) await loadUpdates(); }
  }

  async function runPanelUpdate() {
    if (!confirm(t('Update SNPanel from GitHub now? The API may restart and this page will reload when done.'))) return;
    setPanelUpdating(true);
    setShowUpdateLog(true);
    setPanelUpdateLog([]);
    const data = await request('/updates/panel/run', { method: 'POST' }, t('Updating SNPanel...'));
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
          setNotice(t('Panel update completed. Reloading to apply the new version...'));
          setTimeout(() => { window.location.reload(); }, 2000);
        } else if (st.last_update_status === 'failed') {
          setNotice((st.progress_message || st.last_update_message || t('Panel update failed.')).trim());
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

  // The owners an administrator can pick from.
  useEffect(() => {
    if (isAuthenticated && page === 'databases' && isAdmin) loadUsers();
  }, [isAuthenticated, page, isAdmin]);

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

  // Asked once the addon list says it is installed: before that the API
  // answers 409, and the page explains the missing addon itself.
  useEffect(() => {
    if (isAuthenticated && page === 'fail2ban' && isAdmin && fail2banAddonInstalled) loadFail2ban();
  }, [isAuthenticated, page, isAdmin, fail2banAddonInstalled]);

  useEffect(() => {
    if (isAuthenticated && page === 'mcp') loadMcp();
  }, [isAuthenticated, page, mcpAddonInstalled]);

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
      loadPasskeys();
      if (!websites.length) refreshAll();
    }
    if (isAuthenticated && ['settings', 'api-tokens'].includes(page)) {
      loadPanelSettings();
      if (currentUser?.role === 'admin') loadApiTokens();
    }
    if (isAuthenticated && page === 'backups' && currentUser?.role === 'admin') { loadUsers(); loadSftpTargets(); loadS3Targets(); loadBackupSchedules(); loadRestoreBackups(); }
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
    return role === 'admin' ? t('Admin') : t('End user');
  }

  const mainNavItems = [
    ['dashboard', t('Dashboard'), Home],
    ['websites', t('Websites'), Globe],
    ...(appsFeatureEnabled ? [['applications', t('Applications'), Server]] : []),
    ['ssl', t('SSL'), Lock],
    ['databases', t('Database'), Database],
    ['cron', t('Cron'), Clock],
    ['files', t('File manager'), FolderOpen],
    ['backups', t('Backups'), Archive],
    ...(isAdmin ? [['users', t('Panel users'), Users]] : []),
  ];

  const settingsNavItems = [
    ...(isAdmin ? [['settings', t('Panel settings'), SettingsIcon]] : []),
    ['security', t('Account security'), Shield],
    // An administrator sees it to install the addon from; anyone else once
    // the addon is on.
    ...((isAdmin || mcpAddonInstalled) ? [['mcp', t('AI assistants (MCP)'), Bot]] : []),
    ...(isAdmin ? [['php', t('PHP config'), Code2]] : []),
    ...(isAdmin ? [['firewall', t('Firewall'), Shield]] : []),
    ...(isAdmin && fail2banAddonInstalled ? [['fail2ban', t('Fail2ban'), ShieldBan]] : []),
    ['waf', t('WAF'), Shield],
    ...(isAdmin ? [['malware', t('Malware Scanner'), Search]] : []),
    ...(isAdmin ? [['access-logs', t('Access Logs'), FileText]] : []),
    ...(isAdmin ? [['updates', t('Updates'), RefreshCw]] : []),
    ...(isAdmin ? [['addons', t('Addons'), Boxes]] : []),
    ['services', t('Services Status'), Server],
  ];

  const navItems = [...mainNavItems, ...settingsNavItems];
  const navPage = NAV_PARENT_PAGE[page] || page;
  const activeNavItem = navItems.find(([key]) => key === navPage) || navItems[0];
  const settingsIsActive = SETTINGS_PAGE_KEYS.includes(page);

  function renderNotifications() {
    const errorMessage = formatApiError(error, '').trim();
    const noticeMessage = formatApiError(notice, '').trim();
    if (!errorMessage && !noticeMessage) return null;
    return <div className="app-toast-stack" aria-label={t('Notifications')}>
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
      <option value="">{t('-- Select website or application --')}</option>
      {websites.map(site => <option key={`site-${site.id}`} value={site.id}>{site.domain}</option>)}
      {siteApps.items.map(app => <option key={`app-${app.id}`} value={`app:${app.id}`}>{t('App: {name}', { name: app.name })}</option>)}
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
      <option value="">{t('-- Select website --')}</option>
      {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
    </select>;
  }

  function EmptyState({ icon: Icon = AlertCircle, message = t('No data yet') }) {
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





























  function renderStandaloneEditor() {
    const editorLineCount = Math.max(1, String(fileContent || '').split('\n').length);
    const editorMode = editorLanguage(filePath);
    const siteLabel = currentSite?.domain || (selectedWebsiteId ? t('Website #{id}', { id: selectedWebsiteId }) : t('Website'));
    return <main className="standalone-editor-page">
      <header className="standalone-editor-top">
        <div className="standalone-editor-title">
          <strong>{filePath || t('No file selected')}</strong>
          <span>{siteLabel}</span>
        </div>
        <div className="standalone-editor-actions">
          <span className="editor-chip">{editorMode}</span>
          <span className="editor-chip">{t('{count} line(s)', { count: editorLineCount })}</span>
          <span className="editor-chip">{t('Ln {line}, Col {column}', { line: editorCursor.line, column: editorCursor.column })}</span>
          <button disabled={!selectedWebsiteId || !!loading} onClick={() => readFile(filePath)}><RefreshCw size={14}/> {t('Reload')}</button>
          <button disabled={!selectedWebsiteId || !!loading} onClick={writeFile}>{t('Save')}</button>
          <button disabled={!selectedWebsiteId || !filePath || !!loading} onClick={() => downloadFile(filePath)}><Download size={14}/></button>
          <ThemeToggle theme={theme} onToggle={toggleTheme}/>
          <button className="secondary-light" onClick={() => window.close()}><X size={14}/> {t('Close')}</button>
        </div>
      </header>
      {loading && <div className="loading">{loading}</div>}
      {renderNotifications()}
      <section className="standalone-editor-body">
        <Suspense fallback={<div className="loading">{t('Loading editor…')}</div>}>
          <CodeEditor
            value={fileContent}
            mode={editorMode}
            disabled={!selectedWebsiteId}
            onChange={setFileContent}
            onCursorChange={setEditorCursor}
          />
        </Suspense>
      </section>
    </main>;
  }

  // Everything the pages read from App. A function rather than an object so
  // it is evaluated where the pages are rendered, after every value in it has
  // been initialised.
  function panelContext() {
    return {
      EmptyState,
      FileTargetSelect,
      ResourceCard,
      WebsiteSelect,
      addCron,
      addFirewallBlocklistUrl,
      addFirewallRule,
      addGlobalBots,
      addPasskey,
      addWebsiteAlias,
      addons,
      adminAccountForm,
      adminEmail,
      aliasDrafts,
      aliasModes,
      apiTokens,
      appVersion,
      applicationAddonInstalled,
      applyChmod,
      applyPackageToEditingUser,
      applyPackageToNewUser,
      applyPhpTune,
      applyWafAccessLogFilters,
      appsFeatureEnabled,
      archiveFormat,
      archiveSelectedFiles,
      assignDomainToUser,
      assignUserId,
      assignWebsiteId,
      backupJobs,
      backupSchedules,
      backupTab,
      backups,
      botBlocks,
      bulkBotOpen,
      bulkDeleteDaBackups,
      bulkImportDaBackups,
      cancelEditingPackage,
      cancelEditingUser,
      cfZone,
      changeDbPassword,
      checkAllServices,
      checkComposeFile,
      checkSiteAppEdit,
      chmodMode,
      chmodTarget,
      clearWafAccessLogs,
      composePlan,
      controlSiteApp,
      copiedField,
      copyApiToken,
      copySelectedFiles,
      createApiToken,
      createBackup,
      createBackupSchedule,
      createDatabase,
      createPackage,
      createSftpTarget,
      createSiteApp,
      createSiteAppId,
      createSslMode,
      createSslToken,
      createUser,
      createUserBackup,
      createWordPress,
      createdApiToken,
      createdDbInfo,
      cronCommand,
      cronItems,
      cronPhpInfo,
      cronSchedule,
      cronUser,
      crs,
      currentFileApp,
      currentSite,
      currentUser,
      daBackups,
      daBulkImportJob,
      daFileInputRef,
      daImportJob,
      daReplaceExisting,
      daScanResult,
      databases,
      dbSearch,
      dbSearching,
      deleteBackup,
      deleteBackupSchedule,
      deleteCron,
      deleteDaBackup,
      deleteDatabase,
      deleteFirewallBlocklistUrl,
      deleteFirewallRule,
      deletePackage,
      deletePanelUser,
      deleteRestoreBackup,
      deleteSelectedFiles,
      deleteS3Target,
      deleteSftpTarget,
      deleteSiteApp,
      deleteUserBackup,
      deleteWebsite,
      deleteWebsiteAlias,
      deploySiteApp,
      disableFirewall,
      disableTwoFactorAuth,
      dismissFileJob,
      domain,
      downloadBackup,
      downloadDatabase,
      downloadFile,
      downloadUserBackup,
      editingPackageForm,
      editingPackageId,
      editingUser,
      editingUserForm,
      enableFirewall,
      enableSsl,
      enableTwoFactorAuth,
      exportWafAccessLogs,
      extractArchiveFile,
      fail2ban,
      fail2banBan,
      fail2banUnban,
      createMcpToken,
      loadAllMcpTokens,
      loadMcp,
      mcpAllTokens,
      mcpInfo,
      mcpTokens,
      revokeAllMcpTokens,
      revokeMcpToken,
      fileBreadcrumbs,
      fileJobs,
      fileListPath,
      fileTargetKey,
      files,
      firewallBlocklistUrl,
      firewallBlocklists,
      firewallRule,
      firewallStatus,
      formatBytes,
      formatPercent,
      generateRandomPassword,
      globalBotFilter,
      globalBotPaste,
      globalBots,
      hasFileTarget,
      httpFloodForm,
      importDaBackup,
      incrementalDays,
      installDockerEngine,
      installLmd,
      installManualSsl,
      installNodeMajor,
      installPhpVersion,
      installSharedSsl,
      installWildcardSsl,
      installWordPress,
      installWordPressOnSite,
      isAdmin,
      isArchiveFile,
      isTextEditable,
      listCron,
      listDaBackups,
      listFiles,
      listUserBackups,
      loadAddons,
      loadApiTokens,
      loadBotBlocks,
      loadCrs,
      loadDatabases,
      loadFail2ban,
      loadFirewall,
      loadFirewallBlocklists,
      loadMalwareScanJobs,
      loadMalwareScanStatus,
      loadPackages,
      loadPanelSettings,
      loadPasskeys,
      loadPhpConfig,
      loadPhpTune,
      loadRestoreBackups,
      loadSftpAccess,
      loadS3Targets,
      loadSftpTargets,
      loadSiteApps,
      loadSiteRuntimes,
      loadTwoFactorStatus,
      loadUpdates,
      loadUsers,
      loadWafAccessLogs,
      loadWafRules,
      loadWebsiteList,
      loadWebsiteLog,
      loadWebsiteWafConfig,
      loading,
      logViewer,
      makeFile,
      makeFileDirectory,
      malwareScanStatus,
      malwareSchedules,
      malwareSchedulesForm,
      manualSslFiles,
      manualSslForm,
      moveSelectedFiles,
      navItems,
      navigateToPage,
      newApiToken,
      newBackupSchedule,
      newBotName,
      newDatabase,
      newPackage,
      newSftpTarget,
      newUser,
      nginxCustomEditing,
      openAppFileManager,
      openChmodDialog,
      openFileEditorTab,
      openNginxCustom,
      openPhpMyAdmin,
      openSiteAppEdit,
      openSiteAppLog,
      openWafSite,
      openWebsiteFileManager,
      openWebsiteLogs,
      openWebsiteTerminal,
      openWordPressInstaller,
      osAutoUpdate,
      osUpdating,
      packages,
      page,
      panelFaviconFile,
      panelLogoFile,
      panelSettings,
      panelSettingsForm,
      panelUpdateLog,
      panelUpdating,
      parentFilePath,
      passkeys,
      phpConfig,
      phpTune,
      phpTuneApplied,
      phpVersion,
      phpVersions,
      pruneDocker,
      quickLoginUser,
      refreshBackupArea,
      refreshScheduledBackupArea,
      refreshUserBackupArea,
      reloadFirewall,
      removePasskey,
      renameFileItem,
      renderBrandMark,
      resetNginxDefault,
      resetUserTwoFactor,
      resourceUsage,
      restoreBackup,
      restoreBackupDir,
      restoreBackups,
      restorePhpDefaults,
      restoreUserBackup,
      revokeApiToken,
      roleLabel,
      runMalwareScan,
      runOsUpdate,
      runPanelUpdate,
      runServiceAction,
      saveAdminAccount,
      saveCrsMode,
      saveFail2banSettings,
      saveGlobalBots,
      saveMalwareSchedule,
      saveNginxCustom,
      saveOsAutoUpdate,
      savePanelSettings,
      saveSiteAppEdit,
      saveSiteBots,
      saveWebsiteHttpFlood,
      saveWebsiteSettings,
      saveWebsiteWafRules,
      scanDaBackup,
      scanJob,
      scanJobs,
      scanLoading,
      scanResults,
      scanTargetWebsiteId,
      selectedBackupUserId,
      selectedDaBackups,
      selectedFilePaths,
      selectedSftpTargetId,
      selectedWafWebsiteId,
      selectedWebsiteId,
      serviceNames,
      serviceStates,
      setAddonInstalled,
      setAdminAccountForm,
      setAdminEmail,
      setAliasDrafts,
      setAliasModes,
      setArchiveFormat,
      setAssignUserId,
      setAssignWebsiteId,
      setBackupTab,
      setBulkBotOpen,
      setChmodMode,
      setChmodTarget,
      setComposePlan,
      setCopiedField,
      setCreateSiteAppId,
      setCreateSslMode,
      setCreateSslToken,
      setCreatedApiToken,
      setCreatedDbInfo,
      setCronCommand,
      setCronSchedule,
      setDaReplaceExisting,
      setDatabaseOwner,
      setDbSearch,
      setDomain,
      setEditingPackageForm,
      setEditingUserForm,
      setError,
      setFirewallBlocklistUrl,
      setFirewallRule,
      setGlobalBotFilter,
      setGlobalBotPaste,
      setGlobalBots,
      setHttpFloodForm,
      setIncrementalDays,
      setInstallWordPress,
      setLogViewer,
      setMalwareSchedulesForm,
      setManualSslFiles,
      setManualSslForm,
      setNewApiToken,
      setNewBackupSchedule,
      setNewBotName,
      setNewDatabase,
      setNewPackage,
      setNewSftpTarget,
      setNewUser,
      setNginxCustomEditing,
      setOsAutoUpdate,
      setPanelFaviconFile,
      setPanelLogoFile,
      setPanelSettingsForm,
      setPhpConfig,
      setPhpVersion,
      setScanJob,
      setScanResults,
      setScanTargetWebsiteId,
      setSelectedBackupUserId,
      setSelectedSftpTargetId,
      setSftpPassword,
      setSharedSource,
      setSiteAppDraft,
      setSiteAppEdit,
      setSiteAppEditPlan,
      setSiteAppLog,
      setSiteBotText,
      setSiteType,
      setSslMode,
      setTerminalViewer,
      setTwoFactorCode,
      setUserTab,
      setWafCustomRules,
      setWebsiteSearch,
      setWebsiteSettingsForm,
      setWildcardToken,
      setWordpressInstaller,
      setWpAdminPassword,
      setWpAdminUser,
      setupTwoFactorAuth,
      s3Targets,
      saveS3Target,
      setUserBackupDestination,
      sftpTargets,
      testS3Target,
      userBackupDestination,
      sharedSource,
      showMalwareScanJob,
      showUpdateLog,
      siteAppDraft,
      siteAppEdit,
      siteAppEditPlan,
      siteAppLog,
      siteApps,
      siteBotText,
      siteRuntimes,
      siteType,
      sslMode,
      sslSources,
      startEditingPackage,
      startEditingUser,
      storageLimitBytes,
      storageUsageText,
      submitPasswordChange,
      suggestSiteAppPort,
      suspendUser,
      switchSftpAccess,
      terminalViewer,
      toggleAllFiles,
      toggleDaBackupSelect,
      toggleFileSelection,
      toggleIpv6,
      toggleMalwareRealtime,
      toggleMalwareScan,
      toggleOpcache,
      toggleSelectAllDaBackups,
      toggleSiteCrs,
      toggleUpdateLog,
      toggleUploadScan,
      toggleWafDefaultRule,
      toggleWebsiteWaf,
      twoFactorCode,
      twoFactorSetup,
      twoFactorStatus,
      unsuspendUser,
      updateFirewallBlocklistsNow,
      updateMalwareSignatures,
      updatePackage,
      updatePanelUser,
      updatePhpConfig,
      updateSiteApp,
      updateWafAccessLogFilters,
      updateWordPressAll,
      updatesStatus,
      uploadBackup,
      uploadDaBackup,
      uploadPanelAsset,
      uploadSiteFile,
      uploadUserBackups,
      userBackups,
      userTab,
      users,
      viewFullNginxConfig,
      wafAccessLogFilters,
      wafAccessLogs,
      wafCustomRules,
      wafRules,
      wafSiteConfig,
      websiteList,
      websiteSearch,
      websiteSearching,
      websiteSettingsForm,
      websiteUrl,
      websites,
      wildcardToken,
      wordpressInstaller,
      wpAdminPassword,
      wpAdminUser,
    };
  }

  function renderPage() {
    if (page === 'websites') return <WebsitesPage />;
    if (page === 'addons') return <AddonsPage />;
    // Reachable by URL after the addon is removed, so it answers for itself
    // rather than rendering a page whose every request would be refused.
    if (page === 'applications') return appsFeatureEnabled ? <ApplicationsPage /> : <AddonMissingPage />;
    if (page === 'ssl') return <SslPage />;
    if (page === 'databases') return <DatabasesPage />;
    if (page === 'cron') return <CronPage />;
    if (page === 'files') return <FilesPage />;
    if (page === 'backups') return <BackupsPage />;
    if (page === 'security') return <SecurityPage />;
    if (page === 'php') return <PhpConfigPage />;
    if (page === 'firewall') return <FirewallPage />;
    if (page === 'fail2ban') return <Fail2banPage />;
    if (page === 'mcp') return <McpPage />;
    if (page === 'waf') return <WafPage />;
    if (page === 'waf-site') return <WafSitePage />;
    if (page === 'malware') return <MalwarePage />;
    if (page === 'access-logs') return <WafAccessLogsPage />;
    if (page === 'updates') return <UpdatesPage />;
    if (page === 'services') return <ServicesPage />;
    // One page for both addresses: the tokens are a tab of Panel settings.
    if (page === 'settings' || page === 'api-tokens') return <PanelSettingsPage />;
    if (page === 'users') return <UsersPage />;
    return <DashboardPage />;
  }

  // Login screen
  if (bootstrapping) {
    return <main className="login-page">
      <section className="login-card">
        <div className="login-brand">{renderBrandMark('login-brand-mark')}<div><p className="eyebrow">{panelSettings.app_name || 'SNPanel'}</p><h1>{t('Loading…')}</h1></div></div>
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
              <p className="eyebrow">{t('Server Management Panel')}</p>
              <h1>{panelSettings.app_name || 'SNPanel'}</h1>
              <p className="hint">{t('Manage websites, databases, backups, SSL, and services.')}</p>
            </div>
          </div>
          <div className="login-toggles">
            <LocaleSwitch className="theme-toggle"/>
            <ThemeToggle theme={theme} onToggle={toggleTheme}/>
          </div>
        </div>
        <div className="login-form">
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder={t('Username')} autoComplete="username" />
          <input value={password} onChange={e => setPassword(e.target.value)} placeholder={t('Password')} type="password" autoComplete="current-password" onKeyDown={e => { if (e.key === 'Enter') login(); }} />
          {needsTwoFactor && passkeyStatus === 'waiting' && <div className="login-passkey" role="status">
            <KeyRound size={18} aria-hidden="true"/>
            <span>{t('Confirm with your passkey…')}</span>
            <button type="button" className="link-button" onClick={() => passkeyAbort.current?.abort()}>{t('Use the authenticator code instead')}</button>
          </div>}
          {needsTwoFactor && passkeyStatus === 'failed' && <p className="login-passkey-failed" role="alert">{t('The passkey did not work. Enter the code from your authenticator app instead.')}</p>}
          {needsTwoFactor && passkeyStatus !== 'waiting' && <input value={otpCode} onChange={e => setOtpCode(e.target.value)} placeholder={t('Authentication code')} inputMode="numeric" autoComplete="one-time-code" autoFocus onKeyDown={e => { if (e.key === 'Enter') login(); }} />}
          <label className="login-remember">
            <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} />
            {t('Keep me signed in for 30 days')}
          </label>
          {passkeyStatus !== 'waiting' && <button disabled={!!loading || !username || !password} onClick={() => login()}>{loading ? t('Logging in...') : t('Login')}</button>}
          {needsTwoFactor && passkeyStatus === 'failed' && <button type="button" className="secondary" disabled={!!loading} onClick={() => login({ otp: '' })}>{t('Try the passkey again')}</button>}
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
      <aside className={`sidebar ${mobileMenuOpen ? 'open' : ''}`} role="navigation" aria-label={t('Main navigation')}>
        <div className="sidebar-head">
          <div className="sidebar-brand">
            {renderBrandMark()}
            <div>
              <strong>{panelSettings.app_name || 'SNPanel'}</strong>
              <small>{t('Server Panel')}</small>
            </div>
          </div>
          <button className="sidebar-close" onClick={() => setMobileMenuOpen(false)} aria-label={t('Close menu')}><X size={18}/></button>
        </div>
        <nav className="sidebar-nav">
          {mainNavItems.map(([key, label, Icon]) => <button key={key} type="button" className={navPage === key ? 'active' : ''} onClick={() => navigateToPage(key)} aria-current={navPage === key ? 'page' : undefined}>
            <Icon size={17}/>{label}
          </button>)}
          <div className={`sidebar-nav-group ${settingsMenuOpen ? 'open' : ''}`}>
            <button className={`sidebar-group-toggle ${settingsIsActive ? 'active' : ''}`} onClick={() => setSettingsMenuOpen(open => !open)} aria-expanded={settingsMenuOpen} aria-controls="settings-submenu">
              <SettingsIcon size={17}/><span>{t('Settings')}</span><ChevronDown className="sidebar-group-chevron" size={16}/>
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
          <button className="mobile-nav-toggle" onClick={() => setMobileMenuOpen(o => !o)} aria-expanded={mobileMenuOpen} aria-label={t('Toggle navigation')}>
            <Menu size={20}/><span><ActiveIcon size={17}/>{activeNavItem?.[1] || t('Menu')}</span>
          </button>
          <div className="page-title">
            <p className="eyebrow">{t('Server Management Panel')}</p>
            <h1>{activeNavItem?.[1] || panelSettings.app_name || 'SNPanel'}</h1>
          </div>
          <div className="login logged-in">
            <div className="account-pill" title={accountLabel}><span>{t('Logged in as')}</span><strong>{accountLabel}</strong></div>
            <div className="top-actions">
              <LocaleSwitch className="theme-toggle"/>
              <ThemeToggle theme={theme} onToggle={toggleTheme}/>
              <button className="secondary compact-btn" onClick={logout} aria-label={t('Logout')} title={t('Logout')}><LogOut size={15}/><span className="btn-label">{t('Logout')}</span></button>
            </div>
          </div>
        </section>
        <div className="content-body">
          {<PanelContext.Provider value={panelContext()}><Suspense fallback={<div className="loading">{t('Loading…')}</div>}>{renderPage()}</Suspense></PanelContext.Provider>}
          {loading && <div className="loading"><span></span>{loading}</div>}
        </div>
      </div>
    </section>
    {renderNotifications()}
  </main>;
}

createRoot(document.getElementById('root')).render(<LocaleProvider><App /></LocaleProvider>);
