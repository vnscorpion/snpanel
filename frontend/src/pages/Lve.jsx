import { useEffect, useState } from 'react';
import { Pencil, RefreshCw, RotateCcw, Save, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Lve.css';

// The six LVE limits, in the order CloudLinux lists them. `unlimited` marks
// the ones where 0 means "no limit".
const FIELDS = [
  { key: 'speed_percent', label: 'CPU (%)', hint: '100 = one core', min: 1 },
  { key: 'pmem_mb', label: 'Memory (MB)', hint: 'physical memory', min: 64 },
  { key: 'ep', label: 'Entry processes', hint: 'concurrent requests', min: 0, unlimited: true },
  { key: 'nproc', label: 'Processes', hint: '', min: 0, unlimited: true },
  { key: 'io_kbps', label: 'IO (KB/s)', hint: 'disk throughput', min: 0, unlimited: true },
  { key: 'iops', label: 'IOPS', hint: 'IO operations per second', min: 0, unlimited: true },
];

function toPayload(draft) {
  const out = {};
  for (const f of FIELDS) out[f.key] = Number.parseInt(draft[f.key], 10);
  return out;
}

function LimitInputs({ idPrefix, draft, setDraft }) {
  const t = useT();
  return <div className="lve-fields">
    {FIELDS.map(f => <div className="lve-field" key={f.key}>
      <label htmlFor={`${idPrefix}-${f.key}`}>{t(f.label)}</label>
      <input id={`${idPrefix}-${f.key}`} type="number" inputMode="numeric" min={f.min} step="1"
        value={draft[f.key] ?? ''} onChange={e => setDraft({ ...draft, [f.key]: e.target.value })}/>
      {(f.hint || f.unlimited) && <span className="hint">{[f.hint && t(f.hint), f.unlimited && t('0 = unlimited')].filter(Boolean).join(' · ')}</span>}
    </div>)}
  </div>;
}

function shown(field, value) {
  if (field.unlimited && Number(value) === 0) return '∞';
  return value;
}

export default function LvePage() {
  const t = useT();
  const { loading, request } = usePanel();
  const [data, setData] = useState(null);
  const [defaults, setDefaults] = useState({});
  const [editing, setEditing] = useState(null);
  const [draft, setDraft] = useState({});

  async function load() {
    const d = await request('/hosting/lve', {}, t('Loading LVE limits...'));
    if (d) {
      setData(d);
      setDefaults(d.default || {});
    }
  }

  useEffect(() => { load(); }, []);

  async function saveDefaults() {
    const d = await request('/hosting/lve/default', { method: 'PUT', body: JSON.stringify(toPayload(defaults)) }, t('Saving default limits...'));
    if (d) { setData(d); setDefaults(d.default || {}); }
  }

  async function saveUser(username) {
    const d = await request(`/hosting/lve/users/${encodeURIComponent(username)}`, { method: 'PUT', body: JSON.stringify(toPayload(draft)) }, t('Saving limits for {name}...', { name: username }));
    if (d) { setData(d); setEditing(null); }
  }

  async function resetUser(username) {
    const d = await request(`/hosting/lve/users/${encodeURIComponent(username)}`, { method: 'DELETE' }, t('Resetting {name} to the default limits...', { name: username }));
    if (d) { setData(d); setEditing(null); }
  }

  const users = data?.users || [];

  return <section className="section lve-page">
    <div className="section-title">
      <div>
        <h2>{t('Resource limits (LVE)')}</h2>
        <p className="hint">{t('CloudLinux LVE caps what each hosting account can use, so one busy site cannot slow the server for everyone.')}</p>
      </div>
      <button className="secondary-light" disabled={!!loading} onClick={load}><RefreshCw size={15}/> {t('Refresh')}</button>
    </div>

    <div className="lve-card">
      <h3>{t('Default limits')}</h3>
      <p className="hint">{t('Every account without limits of its own uses these.')}</p>
      <LimitInputs idPrefix="lve-default" draft={defaults} setDraft={setDefaults}/>
      <button disabled={!!loading || !data} onClick={saveDefaults}><Save size={15}/> {t('Save default limits')}</button>
    </div>

    <div className="lve-card">
      <h3>{t('Accounts')}</h3>
      {!users.length && <p className="hint">{t('No hosting accounts yet.')}</p>}
      {!!users.length && <div className="lve-table-wrap"><table className="lve-table">
        <thead><tr>
          <th>{t('Account')}</th>
          {FIELDS.map(f => <th key={f.key}>{t(f.label)}</th>)}
          <th/>
        </tr></thead>
        <tbody>
          {users.map(u => {
            const own = new Set(u.custom || []);
            if (editing === u.username) {
              return <tr key={u.username} className="lve-editing"><td colSpan={FIELDS.length + 2}>
                <strong>{u.username}</strong>
                <LimitInputs idPrefix={`lve-${u.username}`} draft={draft} setDraft={setDraft}/>
                <div className="lve-row-actions">
                  <button className="mini" disabled={!!loading} onClick={() => saveUser(u.username)}><Save size={13}/> {t('Save')}</button>
                  <button className="mini secondary-light" onClick={() => setEditing(null)}><X size={13}/> {t('Cancel')}</button>
                </div>
              </td></tr>;
            }
            return <tr key={u.username}>
              <td>
                <strong>{u.username}</strong>
                {u.domain && <div className="hint">{u.domain}</div>}
                <span className={u.cagefs ? 'badge ok' : 'badge'}>{u.cagefs ? t('CageFS on') : t('CageFS off')}</span>
              </td>
              {FIELDS.map(f => <td key={f.key} className={own.has(f.key) ? 'lve-own' : ''}>
                {shown(f, u.limits?.[f.key])}
                {own.has(f.key) && <span className="lve-own-tag">{t('own')}</span>}
              </td>)}
              <td className="lve-row-actions">
                <button className="mini secondary-light" onClick={() => { setEditing(u.username); setDraft({ ...u.limits }); }}><Pencil size={13}/> {t('Edit')}</button>
                {!!own.size && <button className="mini secondary-light" disabled={!!loading} onClick={() => resetUser(u.username)}><RotateCcw size={13}/> {t('Default')}</button>}
              </td>
            </tr>;
          })}
        </tbody>
      </table></div>}
    </div>
  </section>;
}
