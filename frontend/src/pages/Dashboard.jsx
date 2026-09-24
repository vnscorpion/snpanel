import { Cpu, Globe, HardDrive, MemoryStick, Network, Plus } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function DashboardPage() {
  const {
    EmptyState,
    ResourceCard,
    currentUser,
    databases,
    formatBytes,
    formatPercent,
    isAdmin,
    navigateToPage,
    resourceUsage,
    storageLimitBytes,
    websiteUrl,
    websites,
  } = usePanel();

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

  return renderDashboard();
}
