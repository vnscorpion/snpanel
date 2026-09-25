import {
  Activity,
  Archive,
  Boxes,
  BrickWall,
  Bug,
  CalendarClock,
  Cpu,
  Database,
  FileCode2,
  Fingerprint,
  FolderOpen,
  Globe,
  HardDrive,
  Lock,
  MemoryStick,
  Network,
  Plus,
  Puzzle,
  RefreshCw,
  ScrollText,
  Settings,
  ShieldBan,
  ShieldCheck,
  UserCog,
} from 'lucide-react';
import { routeForPage } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './Dashboard.css';

// The dashboard is a map of the panel: every page this user can open, as a
// tile, grouped by what it is for. A tile is a page key and appears only if
// that page is in this user's navigation, so what a role may see and which
// addons are installed are decided in one place - the navigation - and the
// dashboard cannot offer a page the sidebar hides. Labels come from there too,
// so a place has one name wherever it is shown.
const GROUPS = [
  {
    id: 'hosting',
    title: msg('Hosting'),
    tone: 'blue',
    tiles: [
      ['websites', Globe],
      ['ssl', Lock],
      ['databases', Database],
      ['files', FolderOpen],
      ['backups', Archive],
      ['cron', CalendarClock],
    ],
  },
  {
    id: 'security',
    title: msg('Security'),
    tone: 'rose',
    tiles: [
      ['security', Fingerprint],
      ['firewall', BrickWall],
      ['waf', ShieldCheck],
      ['malware', Bug],
      ['access-logs', ScrollText],
    ],
  },
  {
    id: 'server',
    title: msg('Server'),
    tone: 'teal',
    tiles: [
      ['php', FileCode2],
      ['services', Activity],
      ['updates', RefreshCw],
    ],
  },
  {
    id: 'admin',
    title: msg('Administration'),
    tone: 'slate',
    tiles: [
      ['users', UserCog],
      ['settings', Settings],
      ['addons', Puzzle],
    ],
  },
];

// The page and icon of each addon that has a page of its own. Every
// installed addon gets a tile - nothing installed may be invisible - so one
// that is not listed here gets a tile that opens the Addons page.
const ADDON_TILES = {
  application: ['applications', Boxes],
  fail2ban: ['fail2ban', ShieldBan],
};

// A plain click stays in the panel; a click that asks for a new tab or window
// is left to the browser, which is what the link's href is for.
function followInPanel(event, open) {
  if (event.defaultPrevented || event.button !== 0) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  open();
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
    resourceUsage,
    storageLimitBytes,
    websites,
  } = usePanel();
  const t = useT();

  const navLabel = new Map(navItems.map(([key, label]) => [key, label]));

  const groups = [];
  for (const group of GROUPS) {
    const tiles = group.tiles
      .filter(([page]) => navLabel.has(page))
      .map(([page, Icon]) => ({ key: page, page, Icon, label: navLabel.get(page) }));
    if (tiles.length > 0) groups.push({ ...group, title: t(group.title), tiles });
  }
  const addonTiles = addons.items
    .filter((addon) => addon.installed)
    .map((addon) => {
      const [page, Icon] = ADDON_TILES[addon.slug] || ['addons', Puzzle];
      return { key: `addon-${addon.slug}`, page, Icon, label: page === 'addons' ? addon.name : navLabel.get(page) };
    })
    .filter((tile) => navLabel.has(tile.page));
  if (addonTiles.length > 0) groups.push({ id: 'addons', title: t('Addons'), tone: 'violet', tiles: addonTiles });

  const cpu = resourceUsage?.cpu || {};
  const memory = resourceUsage?.memory || {};
  const disk = resourceUsage?.disk || {};
  const network = resourceUsage?.network || {};
  const networkTotal = (Number(network.rx_per_sec) || 0) + (Number(network.tx_per_sec) || 0);

  // A customer's quota was one of the old counters and the one of them they
  // need, so it stays - as a card like the server's disk. Only an
  // administrator has no limit; a limit of zero is a limit, and full.
  const storageUsed = Number(currentUser?.storage_used_bytes) || 0;
  const storageLimit = storageLimitBytes(currentUser);
  const storagePercent = storageLimit === null ? null : storageLimit > 0 ? (storageUsed / storageLimit) * 100 : 100;

  return <div className="dashboard">
    {isAdmin && <section className="resource-grid">
      <ResourceCard icon={Cpu} label="CPU" value={formatPercent(cpu.percent)} percent={cpu.percent} detail={cpu.load?.length ? t('Load {load}', { load: cpu.load.join(' / ') }) : t('{count} cores', { count: cpu.cores || '--' })} />
      <ResourceCard icon={MemoryStick} label="RAM" value={formatPercent(memory.percent)} percent={memory.percent} detail={`${formatBytes(memory.used)} / ${formatBytes(memory.total)}`} />
      <ResourceCard icon={HardDrive} label={t('Disk')} value={formatPercent(disk.percent)} percent={disk.percent} detail={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}`} />
      <ResourceCard icon={Network} label={t('Network')} value={`${formatBytes(networkTotal)}/s`} detail={t('Down {down}/s / Up {up}/s', { down: formatBytes(network.rx_per_sec), up: formatBytes(network.tx_per_sec) })} />
    </section>}
    {currentUser && !isAdmin && <section className="resource-grid dash-storage">
      {storagePercent === null
        ? <ResourceCard icon={HardDrive} label={t('Storage')} value={formatBytes(storageUsed)} detail={t('No limit')} />
        : <ResourceCard icon={HardDrive} label={t('Storage')} value={formatPercent(storagePercent)} percent={storagePercent} detail={`${formatBytes(storageUsed)} / ${formatBytes(storageLimit)}`} />}
    </section>}

    {websites.length === 0 && <section className="dash-first-run">
      <span className="dash-first-run-icon"><Globe size={20} aria-hidden="true"/></span>
      <p>{currentUser?.package_name
        ? t('{package} is ready. Attach your first domain to start hosting.', { package: currentUser.package_name })
        : t('No domain attached yet.')}</p>
      <button type="button" onClick={() => navigateToPage('websites')}><Plus size={15} aria-hidden="true"/> {t('Add domain')}</button>
    </section>}

    <div className="dash-groups">
      {groups.map((group) => <section className="dash-group" data-tone={group.tone} key={group.id} aria-labelledby={`dash-${group.id}`}>
        <h2 className="dash-group-title" id={`dash-${group.id}`}>{group.title}</h2>
        <div className="dash-grid">
          {group.tiles.map(({ key, page, Icon, label }) => <a className="dash-tile" key={key} href={routeForPage(page)}
            onClick={(event) => followInPanel(event, () => navigateToPage(page))}>
            <span className="dash-tile-icon"><Icon size={22} aria-hidden="true"/></span>
            <span className="dash-tile-label">{label}</span>
          </a>)}
        </div>
      </section>)}
    </div>
  </div>;
}
