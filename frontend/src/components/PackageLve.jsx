import { useEffect, useState } from 'react';
import { Gauge, Pencil, RefreshCw, RotateCcw, Save } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

// CloudLinux LVE limits per package (Hosting Edition). CloudLinux keeps them
// (lvectl package-set) and gives every account the limits of the package the
// panel says it is on; CloudLinux Manager's Packages tab edits the same ones.
const FIELDS = [
  ['speed_percent', 'CPU (%)', 1, 12800],
  ['pmem_mb', 'Memory (MB)', 64, 1048576],
  ['ep', 'Entry processes', 0, 10000],
  ['nproc', 'Processes', 0, 100000],
  ['io_kbps', 'IO (KB/s)', 0, 10485760],
  ['iops', 'IOPS', 0, 1000000],
];

export default function PackageLve({ packages }) {
  const t = useT();
  const { request, loading } = usePanel();
  const [lve, setLve] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({});

  async function load() {
    const d = await request('/hosting/lve', { silent: true });
    if (d) setLve(d);
  }
  useEffect(() => { load(); }, [packages.length]);

  const byName = Object.fromEntries((lve?.packages || []).map(p => [p.name, p]));
  const limitsOf = pkg => byName[pkg.name]?.limits || lve?.default;
  const unlimited = n => (Number(n) === 0 ? t('unlimited') : n);
  const summary = l => l ? t('{cpu}% CPU · {mem} MB · {ep} EP · {nproc} proc · IO {io} KB/s · {iops} IOPS', {
    cpu: l.speed_percent, mem: l.pmem_mb, ep: unlimited(l.ep), nproc: unlimited(l.nproc), io: unlimited(l.io_kbps), iops: unlimited(l.iops),
  }) : '';

  function edit(pkg) {
    setEditing(pkg.id);
    setForm({ ...(limitsOf(pkg) || {}) });
  }

  async function save(pkg) {
    const body = Object.fromEntries(FIELDS.map(([k]) => [k, Number(form[k])]));
    const d = await request(`/hosting/lve/packages/${pkg.id}`, { method: 'PUT', body: JSON.stringify(body) }, t('Saving {name}...', { name: pkg.name }));
    if (d) { setLve(d); setEditing(null); }
  }

  async function reset(pkg) {
    const d = await request(`/hosting/lve/packages/${pkg.id}`, { method: 'DELETE' }, t('Saving {name}...', { name: pkg.name }));
    if (d) { setLve(d); setEditing(null); }
  }

  if (!packages.length) return null;
  return <div className="package-lve">
    <div className="section-title user-panel-title">
      <div><h2>{t('CloudLinux limits')}</h2><p className="hint">{t('Every account gets the LVE limits of its package. A package without its own limits uses the default: {limits}.', { limits: summary(lve?.default) })}</p></div>
      <button className="secondary-light" disabled={!!loading} onClick={load}><RefreshCw size={14}/> {t('Refresh')}</button>
    </div>
    <div className="package-list">
      {packages.map(pkg => {
        const own = byName[pkg.name]?.custom;
        return <div className="package-row package-lve-row" key={pkg.id}>
          {editing === pkg.id ? <>
            <div className="user-main"><strong>{pkg.name}</strong></div>
            <div className="package-lve-fields">
              {FIELDS.map(([k, label, min, max]) => <label key={k}><span>{t(label)}</span>
                <input type="number" min={min} max={max} value={form[k] ?? ''} onChange={e => setForm(prev => ({ ...prev, [k]: e.target.value }))} /></label>)}
            </div>
            <p className="hint">{t('0 means unlimited for entry processes, processes, IO and IOPS.')}</p>
            <div className="row-actions">
              <button className="mini secondary-light" onClick={() => setEditing(null)}>{t('Cancel')}</button>
              <button className="mini" disabled={!!loading} onClick={() => save(pkg)}><Save size={14}/> {t('Save')}</button>
            </div>
          </> : <>
            <div className="user-main"><strong>{pkg.name}</strong><small>{summary(limitsOf(pkg))}</small></div>
            <span className="user-metric"><Gauge size={13}/>{own ? t('Own limits') : t('Default limits')}</span>
            <div className="row-actions">
              <button className="mini secondary-light" disabled={!!loading || !lve} onClick={() => edit(pkg)}><Pencil size={14}/> {t('Edit')}</button>
              {own && <button className="mini secondary-light" disabled={!!loading} onClick={() => reset(pkg)} title={t('Use the default limits')}><RotateCcw size={14}/> {t('Use default')}</button>}
            </div>
          </>}
        </div>;
      })}
    </div>
  </div>;
}
