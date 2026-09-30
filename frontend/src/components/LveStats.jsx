import { useEffect, useState } from 'react';
import { ArrowRight, Gauge, RefreshCw, TriangleAlert } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

// The account's CloudLinux resource usage beside its dashboard, the way
// cPanel shows "Statistics": each limit, how much of it is in use, and how
// often it was hit in the last day. Hosting Edition with CloudLinux only.
const REFRESH_MS = 30000;

export default function LveStats() {
  const t = useT();
  const { request, navigateToPage } = usePanel();
  const [data, setData] = useState(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    const d = await request('/hosting/usage', { silent: true });
    if (d) { setData(d); setFailed(false); } else setFailed(true);
    setBusy(false);
  }
  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  }, []);

  const u = data?.usage || {};
  const l = data?.limits || {};
  const f = data?.faults_24h || {};
  const rows = [
    { key: 'cpu', label: t('CPU usage'), used: u.cpu_percent, limit: l.speed_percent, unit: '%' },
    { key: 'pmem', label: t('Physical memory'), used: u.pmem_mb, limit: l.pmem_mb, unit: ' MB' },
    { key: 'ep', label: t('Entry processes'), used: u.ep, limit: l.ep },
    { key: 'nproc', label: t('Processes'), used: u.nproc, limit: l.nproc },
    { key: 'io', label: t('I/O usage'), used: u.io_kbps, limit: l.io_kbps, unit: ' KB/s' },
    { key: 'iops', label: t('IOPS'), used: u.iops, limit: l.iops },
  ];
  const fmt = (n) => (n === undefined || n === null ? '—' : Number(n).toLocaleString(undefined, { maximumFractionDigits: 1 }));

  return <aside className="section lve-stats" aria-labelledby="lve-stats-title">
    <div className="dash-section-head">
      <h2 id="lve-stats-title"><Gauge size={17} aria-hidden="true"/> {t('Statistics')}</h2>
      <button type="button" className="secondary-light icon-button" onClick={load} disabled={busy}
        aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={15} className={busy ? 'spin' : ''} aria-hidden="true"/></button>
    </div>
    {data?.package && <p className="hint lve-stats-package">{t('Package {name}', { name: data.package })}</p>}
    {!data && !failed && <p className="hint">{t('Reading resource usage...')}</p>}
    {!data && failed && <p className="hint">{t('Resource usage is not available right now.')}</p>}
    {data && <ul className="lve-stats-list">
      {rows.map(({ key, label, used, limit, unit = '' }) => {
        const unlimited = !limit;
        const percent = unlimited ? 0 : Math.min(100, (Number(used) / Number(limit)) * 100);
        const tone = percent >= 90 ? 'bad' : percent >= 70 ? 'warn' : 'ok';
        const hits = Number(f[key]) || 0;
        return <li key={key} data-tone={tone}>
          <div className="lve-stats-row">
            <span className="lve-stats-label">{label}</span>
            <span className="lve-stats-value">{fmt(used)}{unit} / {unlimited ? '∞' : `${fmt(limit)}${unit}`}</span>
          </div>
          <div className="lve-stats-bar" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(percent)}>
            <span style={{ width: `${percent}%` }}/>
          </div>
          {hits > 0 && <small className="lve-stats-faults"><TriangleAlert size={12} aria-hidden="true"/> {t('Limit reached {count} time(s) in 24 hours', { count: hits })}</small>}
        </li>;
      })}
    </ul>}
    <button type="button" className="secondary-light lve-stats-more" onClick={() => navigateToPage('resource-usage')}>
      {t('Resource usage')} <ArrowRight size={14} aria-hidden="true"/>
    </button>
  </aside>;
}
