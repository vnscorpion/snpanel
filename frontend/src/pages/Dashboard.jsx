import { useEffect, useState } from 'react';
import {
  Activity,
  Archive,
  ArrowRight,
  BrickWall,
  Bug,
  CircleCheckBig,
  Cpu,
  Database,
  Fingerprint,
  FolderKey,
  Globe,
  HardDrive,
  Lock,
  MemoryStick,
  Network,
  OctagonAlert,
  Plus,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  UserCog,
  UserPlus,
} from 'lucide-react';
import { followInPanel, routeForPage, scanRoute } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import { addonIcon, addonPage } from '../lib/addons.jsx';
import './Dashboard.css';

// The dashboard says how things are, not where they are: the sidebar already
// lists every page. A card per thing that can be wrong, coloured by whether
// it is; the list of what is actually wrong, worst first, each with the way
// to the page that fixes it; and the handful of things people come here to
// start.

const TONE_RANK = { bad: 0, warn: 1, info: 2 };

// "5 minutes ago", in the reader's language, for a moment in the past.
function useAgo() {
  const t = useT();
  return (stamp) => {
    if (!stamp) return '';
    const then = new Date(stamp).getTime();
    if (Number.isNaN(then)) return stamp;
    const minutes = Math.max(0, Math.round((Date.now() - then) / 60000));
    if (minutes < 1) return t('just now');
    if (minutes < 60) return t('{count} min ago', { count: minutes });
    const hours = Math.round(minutes / 60);
    if (hours < 48) return t('{count} h ago', { count: hours });
    return t('{count} days ago', { count: Math.round(hours / 24) });
  };
}

function StatusCard({ tone, icon: Icon, label, value, detail, page, href, onOpen }) {
  return <a className="dash-card" data-tone={tone} href={href || routeForPage(page)}
    onClick={(event) => followInPanel(event, onOpen)}>
    <span className="dash-card-icon"><Icon size={18} aria-hidden="true"/></span>
    <span className="dash-card-label">{label}</span>
    <strong className="dash-card-value">{value}</strong>
    <small className="dash-card-detail">{detail}</small>
  </a>;
}

function QuickAction({ icon: Icon, label, onOpen, href }) {
  return <a className="dash-action" href={href} onClick={(event) => followInPanel(event, onOpen)}>
    <span className="dash-action-icon"><Icon size={18} aria-hidden="true"/></span>
    <span>{label}</span>
  </a>;
}

export default function DashboardPage() {
  const {
    ResourceCard,
    addons,
    currentUser,
    formatBytes,
    formatPercent,
    isAdmin,
    navItems,
    navigateToPage,
    request,
    resourceUsage,
    setBackupTab,
    setUserTab,
    storageLimitBytes,
  } = usePanel();
  const t = useT();
  const ago = useAgo();
  const [summary, setSummary] = useState(null);
  const [updates, setUpdates] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  async function load() {
    setRefreshing(true);
    const data = await request('/dashboard/summary', { silent: true });
    if (data) setSummary(data);
    setRefreshing(false);
    // Asking the package manager takes a moment; the rest does not wait.
    if (isAdmin) {
      const pending = await request('/dashboard/updates', { silent: true });
      if (pending) setUpdates(pending);
    }
  }
  useEffect(() => { load(); }, [isAdmin]);

  const go = (page, options) => () => navigateToPage(page, options);
  const allowed = new Set(navItems.map(([key]) => key));
  const sites = summary?.websites || {};
  const total = Number(sites.total) || 0;

  // ---- what needs attention, worst first ----
  const attention = [];
  const need = (tone, key, text, page, action, options) => attention.push({ tone, key, text, page, action, options });
  if (summary && isAdmin) {
    const stopped = summary.services?.stopped || [];
    if (stopped.length) need('bad', 'services', t('Stopped: {names}', { names: stopped.join(', ') }), 'services', t('Open Services'));
    const fw = summary.firewall || {};
    if (fw.state === 'disabled') need('bad', 'firewall', t('The firewall is off.'), 'firewall', t('Turn it on'));
    else if (fw.state === 'enabled' && fw.chain_active === false) need('warn', 'firewall', t('The firewall is on but its rules are not loaded.'), 'firewall', t('Reload the rules'));
    const mw = summary.malware || {};
    if (mw.state === 'threats') {
      need('bad', 'malware', t('{count} threat(s) found by the last scan.', { count: mw.threats }), 'malware-scan', t('See what was found'),
        mw.infected_job ? { path: scanRoute(mw.infected_job) } : undefined);
    }
    const bk = summary.backups || {};
    if (bk.state === 'error') need('bad', 'backups', t('A scheduled backup failed.'), 'backups', t('Open Backups'));
    else if (bk.state === 'none') need('warn', 'backups', t('No backup schedule. Nothing is backed up on its own.'), 'backups', t('Add a schedule'));
    if (summary.waf && summary.waf.engine === false) need('warn', 'waf', t('The WAF engine is not installed on this server.'), 'waf', t('Open WAF'));
    if (mw.state === 'not_installed') need('warn', 'scanner', t('The malware scanner is not installed.'), 'malware', t('Install it'));
    else if (mw.state === 'never') need('warn', 'scanner', t('No malware scan has run yet.'), 'malware', t('Scan now'));
  }
  if (summary) {
    const noSsl = sites.without_ssl || [];
    if (noSsl.length) {
      need('warn', 'ssl', noSsl.length === 1
        ? t('{domain} has no SSL certificate.', { domain: noSsl[0] })
        : t('{count} websites have no SSL certificate.', { count: noSsl.length }), 'ssl', t('Install SSL'));
    }
    if (sites.suspended > 0) need('warn', 'suspended', t('{count} website(s) suspended.', { count: sites.suspended }), 'websites', t('Open Websites'));
  }
  if (summary && !isAdmin) {
    if (!summary.two_factor?.totp) need('warn', 'twofactor', t('Two-step verification is off for your account.'), 'security', t('Turn it on'));
  }
  if (!isAdmin && currentUser) {
    const limit = storageLimitBytes(currentUser);
    const used = Number(currentUser.storage_used_bytes) || 0;
    if (limit !== null && limit > 0 && used / limit >= 0.9) {
      need(used >= limit ? 'bad' : 'warn', 'storage', t('Storage is {percent} full.', { percent: formatPercent((used / limit) * 100) }), 'files', t('Open the files'));
    }
  }
  if (updates) {
    if (updates.os > 0) need('info', 'os-updates', t('{count} system update(s) available.', { count: updates.os }), 'updates', t('Open Updates'));
    if (updates.panel?.available) need('info', 'panel-update', t('SNPanel {version} is available.', { version: updates.panel.latest }), 'updates', t('Open Updates'));
  }
  attention.sort((a, b) => TONE_RANK[a.tone] - TONE_RANK[b.tone]);
  const shownAttention = attention.filter((item) => allowed.has(item.page) || item.page === 'malware-scan');

  // ---- the cards ----
  const cards = [];
  if (summary && isAdmin) {
    const bk = summary.backups || {};
    const fw = summary.firewall || {};
    const mw = summary.malware || {};
    const sv = summary.services || {};
    const withSsl = Number(sites.with_ssl) || 0;
    cards.push(
      { key: 'websites', icon: Globe, page: 'websites', label: t('Websites'), value: total,
        tone: sites.suspended > 0 ? 'warn' : 'ok',
        detail: sites.suspended > 0 ? t('{count} suspended', { count: sites.suspended }) : t('All active') },
      { key: 'ssl', icon: Lock, page: 'ssl', label: 'SSL', value: `${withSsl}/${total}`,
        tone: withSsl < total ? 'warn' : 'ok',
        detail: withSsl < total ? t('{count} without SSL', { count: total - withSsl }) : t('Every site has one') },
      { key: 'databases', icon: Database, page: 'databases', label: t('Databases'), value: summary.databases?.total ?? 0,
        tone: 'ok', detail: t('MariaDB') },
      { key: 'backups', icon: Archive, page: 'backups', label: t('Backups'),
        onOpen: () => { setBackupTab('schedule'); navigateToPage('backups'); },
        tone: bk.state === 'error' ? 'bad' : bk.state === 'ok' ? 'ok' : 'warn',
        value: { ok: t('On schedule'), error: t('Failed'), none: t('No schedule'), never: t('Not run yet') }[bk.state] || '—',
        detail: bk.last_run_at ? t('Last run {when}', { when: ago(bk.last_run_at) }) : t('{count} schedule(s)', { count: bk.schedules || 0 }) },
      { key: 'firewall', icon: BrickWall, page: 'firewall', label: t('Firewall'),
        tone: fw.state === 'enabled' ? (fw.chain_active === false ? 'warn' : 'ok') : fw.state === 'disabled' ? 'bad' : 'warn',
        value: fw.state === 'enabled' ? t('On') : fw.state === 'disabled' ? t('Off') : '—',
        detail: fw.state === 'enabled' ? (fw.chain_active === false ? t('Rules not loaded') : t('Enforcing')) : fw.state === 'disabled' ? t('Every port is open') : t('Unknown') },
      { key: 'waf', icon: ShieldCheck, page: 'waf', label: 'WAF',
        tone: summary.waf?.engine ? 'ok' : 'warn',
        value: summary.waf?.engine ? t('Installed') : t('Not installed'),
        detail: t('{count} of {total} website(s) protected', { count: sites.waf_on || 0, total }) },
      { key: 'malware', icon: Bug, page: mw.state === 'threats' && mw.infected_job ? 'malware-scan' : 'malware', label: t('Malware'),
        onOpen: mw.state === 'threats' && mw.infected_job ? go('malware-scan', { path: scanRoute(mw.infected_job) }) : undefined,
        href: mw.state === 'threats' && mw.infected_job ? scanRoute(mw.infected_job) : undefined,
        tone: mw.state === 'threats' ? 'bad' : mw.state === 'clean' ? 'ok' : 'warn',
        value: { clean: t('Clean'), threats: t('{count} threat(s)', { count: mw.threats }), never: t('Not scanned'), not_installed: t('Not installed') }[mw.state] || '—',
        detail: mw.last_scan_at ? t('Last scan {when}', { when: ago(mw.last_scan_at) }) : (mw.installed ? t('No scan yet') : t('Scanner not installed')) },
      { key: 'services', icon: Activity, page: 'services', label: t('Services'), value: `${sv.running ?? 0}/${sv.total ?? 0}`,
        tone: (sv.stopped || []).length ? 'bad' : 'ok',
        detail: (sv.stopped || []).length ? t('Stopped: {names}', { names: sv.stopped.join(', ') }) : t('All running') },
    );
  }
  if (summary && !isAdmin) {
    const withSsl = Number(sites.with_ssl) || 0;
    const twoFactor = summary.two_factor || {};
    cards.push(
      { key: 'ssl', icon: Lock, page: 'ssl', label: 'SSL', value: `${withSsl}/${total}`,
        tone: withSsl < total ? 'warn' : 'ok',
        detail: withSsl < total ? t('{count} without SSL', { count: total - withSsl }) : t('Every site has one') },
      { key: 'waf', icon: ShieldCheck, page: 'waf', label: 'WAF', value: `${sites.waf_on || 0}/${total}`,
        tone: total > 0 && (sites.waf_on || 0) < total ? 'warn' : 'ok',
        detail: t('{count} of {total} website(s) protected', { count: sites.waf_on || 0, total }) },
      { key: 'twofactor', icon: Fingerprint, page: 'security', label: t('Two-step verification'),
        tone: twoFactor.totp ? 'ok' : 'warn',
        value: twoFactor.totp ? t('On') : t('Off'),
        detail: twoFactor.totp ? t('{count} passkey(s)', { count: twoFactor.passkeys || 0 }) : t('Only a password protects the account') },
    );
  }

  // ---- quick actions ----
  const actions = [
    { key: 'new-site', icon: Globe, label: t('New website'), page: 'websites', options: { query: 'new=1' } },
    { key: 'new-db', icon: Database, label: t('New database'), page: 'databases', options: { query: 'new=1' } },
    { key: 'ssl', icon: Lock, label: t('Install SSL'), page: 'ssl' },
    { key: 'backup', icon: Archive, label: t('Back up'), page: 'backups', before: () => setBackupTab('website') },
    isAdmin
      // A new panel user - who can then have SFTP logins of their own. Called
      // "New SFTP account" it read as the SFTP page's job.
      ? { key: 'new-user', icon: UserPlus, label: t('New account'), page: 'users', before: () => setUserTab('add') }
      : { key: 'sftp', icon: FolderKey, label: t('SFTP login'), page: 'security' },
    isAdmin && { key: 'users', icon: UserCog, label: t('Panel users'), page: 'users', before: () => setUserTab('list') },
    // Every installed addon has its way in from here too.
    ...addons.items.filter((addon) => addon.installed).map((addon) => ({
      key: `addon-${addon.slug}`, icon: addonIcon(addon.slug), label: addon.name, page: addonPage(addon.slug),
    })),
  ].filter((action) => action && allowed.has(action.page));

  // ---- the resource figures ----
  const cpu = resourceUsage?.cpu || {};
  const memory = resourceUsage?.memory || {};
  const disk = resourceUsage?.disk || {};
  const network = resourceUsage?.network || {};
  const networkTotal = (Number(network.rx_per_sec) || 0) + (Number(network.tx_per_sec) || 0);
  const storageUsed = Number(currentUser?.storage_used_bytes) || 0;
  const storageLimit = storageLimitBytes(currentUser);
  const storagePercent = storageLimit === null ? null : storageLimit > 0 ? (storageUsed / storageLimit) * 100 : 100;
  const siteLimit = Number(currentUser?.website_limit) || 0;

  return <div className="dashboard">
    {isAdmin && <section className="resource-grid" aria-label={t('Server resources')}>
      <ResourceCard icon={Cpu} label="CPU" value={formatPercent(cpu.percent)} percent={cpu.percent} detail={cpu.load?.length ? t('Load {load}', { load: cpu.load.join(' / ') }) : t('{count} cores', { count: cpu.cores || '--' })} />
      <ResourceCard icon={MemoryStick} label="RAM" value={formatPercent(memory.percent)} percent={memory.percent} detail={`${formatBytes(memory.used)} / ${formatBytes(memory.total)}`} />
      <ResourceCard icon={HardDrive} label={t('Disk')} value={formatPercent(disk.percent)} percent={disk.percent} detail={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}`} />
      <ResourceCard icon={Network} label={t('Network')} value={`${formatBytes(networkTotal)}/s`} detail={t('Down {down}/s / Up {up}/s', { down: formatBytes(network.rx_per_sec), up: formatBytes(network.tx_per_sec) })} />
    </section>}

    {currentUser && !isAdmin && <section className="resource-grid dash-usage" aria-label={t('Package usage')}>
      <ResourceCard icon={Globe} label={t('Websites')} value={siteLimit > 0 ? `${total}/${siteLimit}` : total}
        percent={siteLimit > 0 ? (total / siteLimit) * 100 : null}
        detail={currentUser.package_name ? t('Package {name}', { name: currentUser.package_name }) : (siteLimit > 0 ? t('{count} left', { count: Math.max(0, siteLimit - total) }) : t('No limit'))} />
      <ResourceCard icon={Database} label={t('Databases')} value={summary?.databases?.total ?? '—'} detail={t('MariaDB')} />
      {storagePercent === null
        ? <ResourceCard icon={HardDrive} label={t('Storage')} value={formatBytes(storageUsed)} detail={t('No limit')} />
        : <ResourceCard icon={HardDrive} label={t('Storage')} value={formatPercent(storagePercent)} percent={storagePercent} detail={`${formatBytes(storageUsed)} / ${formatBytes(storageLimit)}`} />}
    </section>}

    {cards.length > 0 && <section className={`dash-cards ${isAdmin ? 'admin' : 'customer'}`} aria-label={t('Status')}>
      {cards.map(({ key, onOpen, page, ...card }) => <StatusCard key={key} page={page} onOpen={onOpen || go(page)} {...card} />)}
    </section>}
    {!summary && <section className="dash-cards skeleton" aria-busy="true">
      {Array.from({ length: isAdmin ? 8 : 3 }, (_, i) => <span className="dash-card" key={i}/>)}
    </section>}

    <div className="dash-lower">
      <section className="section dash-attention" aria-labelledby="dash-attention-title">
        <div className="dash-section-head">
          <h2 id="dash-attention-title">{t('Needs attention')}</h2>
          <button type="button" className="secondary-light icon-button" onClick={load} disabled={refreshing}
            aria-label={t('Check again')} title={t('Check again')}><RefreshCw size={15} className={refreshing ? 'spin' : ''} aria-hidden="true"/></button>
        </div>
        {!summary
          ? <p className="hint">{t('Checking…')}</p>
          : shownAttention.length === 0
            ? <p className="dash-all-good"><CircleCheckBig size={18} aria-hidden="true"/> {t('Everything is fine.')}</p>
            : <ul className="dash-attention-list">
              {shownAttention.map((item) => <li key={item.key} data-tone={item.tone}>
                {item.tone === 'bad' ? <OctagonAlert size={17} aria-hidden="true"/> : <TriangleAlert size={17} aria-hidden="true"/>}
                <span className="dash-attention-text">{item.text}</span>
                <a className="dash-attention-go" href={item.options?.path || routeForPage(item.page)}
                  onClick={(event) => followInPanel(event, go(item.page, item.options))}>
                  {item.action} <ArrowRight size={14} aria-hidden="true"/>
                </a>
              </li>)}
            </ul>}
      </section>

      <section className="section dash-quick" aria-labelledby="dash-quick-title">
        <div className="dash-section-head"><h2 id="dash-quick-title">{t('Quick actions')}</h2></div>
        <div className="dash-actions">
          {actions.map(({ key, icon, label, page, options, before }) => <QuickAction key={key} icon={icon} label={label}
            href={options?.query ? `${routeForPage(page)}?${options.query}` : routeForPage(page)}
            onOpen={() => { before?.(); navigateToPage(page, options); }} />)}
        </div>
        {total === 0 && summary && <p className="hint dash-first-hint"><Plus size={13} aria-hidden="true"/> {t('No website yet: start with New website.')}</p>}
      </section>
    </div>
  </div>;
}
