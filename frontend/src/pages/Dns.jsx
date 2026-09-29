import { useEffect, useMemo, useState } from 'react';
import { Boxes, CircleCheckBig, Globe, Network, OctagonAlert, Pencil, Plus, RefreshCw, RotateCcw, Save, Search, Settings2, Trash2, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './Dns.css';

// The DNS Manager addon: the zones this server's PowerDNS answers for. An
// administrator sees every zone, the service and the settings (nameservers
// and the template a new website's zone is made from); a customer the zones
// of their own websites' domains. The API speaks in RRsets - one name and
// type with all its values - and the table shows one row per value, so an
// edit or a delete here is the whole RRset sent back without (or with) it.

const PLACEHOLDER = {
  A: '203.0.113.10',
  AAAA: '2001:db8::10',
  CNAME: 'example.com',
  MX: '10 mail.example.com',
  TXT: 'v=spf1 a mx ~all',
  SRV: '10 5 5060 sip.example.com',
  CAA: '0 issue "letsencrypt.org"',
  NS: 'ns1.example.net',
};

const TYPE_HINT = {
  A: msg('An IPv4 address.'),
  AAAA: msg('An IPv6 address.'),
  CNAME: msg('Another name. Not at @, and alone on its name.'),
  MX: msg('Priority, then the mail server.'),
  TXT: msg('Any text; it is quoted for you.'),
  SRV: msg('Priority, weight, port, then the host.'),
  CAA: msg('Flag, tag (issue, issuewild, iodef), then the value.'),
  NS: msg('A nameserver for a name below this zone.'),
};

const TTLS = [[300, msg('5 minutes')], [900, msg('15 minutes')], [3600, msg('1 hour')], [14400, msg('4 hours')], [86400, msg('1 day')]];

const blankRecord = (ttl) => ({ name: '', type: 'A', ttl, content: '', editing: null });

function ttlLabel(seconds, t) {
  const preset = TTLS.find(([value]) => value === seconds);
  return preset ? t(preset[1]) : t('{count} seconds', { count: seconds });
}

// The content as the table shows it: a name without its final dot.
const shown = (type, content) => (['CNAME', 'NS', 'MX', 'SRV'].includes(type) ? content.replace(/\.$/, '') : content);

export default function DnsPage() {
  const t = useT();
  const { EmptyState, addons, isAdmin, navigateToPage, request, loading, setNotice } = usePanel();
  const installed = !!addons.items.find((item) => item.slug === 'dns')?.installed;
  const [overview, setOverview] = useState(null);
  const [zone, setZone] = useState(null);
  const [selected, setSelected] = useState('');
  const [filter, setFilter] = useState('');
  const [form, setForm] = useState(blankRecord(3600));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const busy = !!loading;

  async function load(keep = selected) {
    const data = await request('/dns', {}, t('Loading DNS...'));
    if (!data) return;
    setOverview(data);
    const next = data.zones.includes(keep) ? keep : data.zones[0] || '';
    setSelected(next);
    if (next) openZone(next); else setZone(null);
  }

  async function openZone(name) {
    setSelected(name);
    setForm(blankRecord(overview?.settings?.default_ttl || 3600));
    const data = await request(`/dns/zones/${encodeURIComponent(name)}`, { silent: true });
    setZone(data);
  }

  useEffect(() => { if (installed) load(''); }, [installed]);

  const zones = overview?.zones || [];
  const visibleZones = useMemo(() => zones.filter((z) => z.includes(filter.trim().toLowerCase())), [zones, filter]);

  async function resetZone() {
    if (!confirm(t('Reset {domain} from the template?\n\nEvery record is replaced by the template\'s; records you added are removed.', { domain: selected }))) return;
    const data = await request(`/dns/zones/${encodeURIComponent(selected)}/reset`, { method: 'POST' }, t('Resetting the zone...'));
    if (data) { setZone(data); setNotice(t('The zone is back to the template.')); }
  }

  async function patch(rrsets, label, done) {
    const data = await request(`/dns/zones/${encodeURIComponent(selected)}`, { method: 'PATCH', body: JSON.stringify({ rrsets }) }, label);
    if (data) { setZone(data); if (done) setNotice(done); }
    return !!data;
  }

  const setOf = (name, type) => zone?.rrsets.find((set) => set.name === name && set.type === type);

  async function saveRecord(event) {
    event.preventDefault();
    const name = form.name.trim() || '@';
    const content = form.content.trim();
    if (!content) return;
    const changes = [];
    const was = form.editing;
    const target = setOf(name, form.type);
    let records = target ? [...target.records] : [];
    if (was && was.name === name && was.type === form.type) {
      records = records.map((value) => (value === was.content ? content : value));
    } else {
      if (was) {
        const old = setOf(was.name, was.type);
        changes.push({ name: was.name, type: was.type, ttl: old?.ttl, records: (old?.records || []).filter((value) => value !== was.content) });
      }
      // A CNAME is alone on its name: a new one replaces the old.
      records = form.type === 'CNAME' ? [content] : [...records, content];
    }
    changes.push({ name, type: form.type, ttl: Number(form.ttl), records });
    const ok = await patch(changes, t('Saving the record...'), was ? t('Record saved.') : t('Record added.'));
    if (ok) setForm(blankRecord(form.ttl));
  }

  async function deleteRecord(set, content) {
    if (!confirm(t('Delete {name} {type} {content}?', { name: set.name, type: set.type, content: shown(set.type, content) }))) return;
    await patch([{ name: set.name, type: set.type, ttl: set.ttl, records: set.records.filter((value) => value !== content) }],
      t('Deleting the record...'), t('Record deleted.'));
  }

  function editRecord(set, content) {
    setForm({ name: set.name, type: set.type, ttl: set.ttl, content: shown(set.type, content), editing: { name: set.name, type: set.type, content } });
  }

  if (addons.loaded && !installed) {
    return <section className="section">
      <div className="section-title"><div><h2>{t('DNS Manager')}</h2></div></div>
      <EmptyState icon={Network} message={t('The DNS Manager addon is not installed on this server.')} />
      {isAdmin && <div className="addon-missing-actions">
        <button disabled={busy} onClick={() => navigateToPage('addons')}><Boxes size={14}/> {t('Go to Addons')}</button>
      </div>}
    </section>;
  }
  if (!overview) return <div className="dns-page"><section className="section"><p className="hint">{t('Loading DNS...')}</p></section></div>;

  const rows = (zone?.rrsets || []).flatMap((set) => set.records.map((content) => ({ set, content })));
  const types = overview.types || Object.keys(PLACEHOLDER);
  const service = overview.service;

  return <div className="dns-page">
    {overview.is_admin && <ServiceCard overview={overview} service={service} busy={busy} onRefresh={() => load()} onSettings={() => setSettingsOpen((open) => !open)} settingsOpen={settingsOpen} t={t} />}
    {overview.is_admin && settingsOpen && <SettingsCard overview={overview} busy={busy} request={request} setNotice={setNotice}
      onSaved={(settings) => setOverview((prev) => ({ ...prev, settings, nameservers: settings.nameservers }))} t={t} />}
    {overview.is_reseller && <ResellerNameservers overview={overview} busy={busy} request={request} setNotice={setNotice}
      onSaved={() => load()} t={t} />}
    {overview.problem && <div className="dns-banner" data-tone="bad"><OctagonAlert size={18} aria-hidden="true"/><span>{overview.problem}</span></div>}

    <div className="dns-layout">
      <section className="section dns-zones">
        <div className="dns-section-head">
          <h2>{t('Zones')}</h2>
          <p className="hint">{overview.is_admin ? t('Every website and alias gets its zone by itself.') : t('Each of your websites and aliases gets its zone by itself.')}</p>
        </div>
        {zones.length > 6 && <label className="dns-search"><Search size={14} aria-hidden="true"/>
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t('Find a zone')} aria-label={t('Find a zone')} /></label>}
        {zones.length === 0
          ? <p className="empty-note">{t('No zones yet. Every website and alias gets one by itself.')}</p>
          : <ul className="dns-zone-list">
            {visibleZones.map((name) => <li key={name}>
              <button type="button" className={name === selected ? 'active' : ''} aria-current={name === selected ? 'true' : undefined} onClick={() => openZone(name)}>
                <Globe size={14} aria-hidden="true"/> <span>{name}</span>
              </button>
            </li>)}
          </ul>}
      </section>

      <section className="section dns-records">
        {!zone
          ? <p className="empty-note">{zones.length ? t('Choose a zone.') : t('Zones appear here as websites are added.')}</p>
          : <>
            <div className="dns-zone-head">
              <div>
                <h2>{zone.name}</h2>
                <p className="hint">{t('Serial {serial}', { serial: zone.serial })} · {t('Nameservers: {list}', { list: zone.nameservers.join(', ') })}</p>
              </div>
              <div className="dns-zone-actions">
                <button type="button" className="secondary" disabled={busy} onClick={resetZone}><RotateCcw size={14} aria-hidden="true"/> {t('Reset from template')}</button>
              </div>
            </div>

            <form className="dns-record-form" onSubmit={saveRecord} aria-label={form.editing ? t('Edit record') : t('Add record')}>
              <label><span>{t('Name')}</span>
                <div className="dns-name-input">
                  <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="@" spellCheck="false" autoComplete="off" />
                  <span className="dns-suffix" title={zone.name}>.{zone.name}</span>
                </div>
              </label>
              <label><span>{t('Type')}</span>
                <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                  {types.map((type) => <option key={type} value={type}>{type}</option>)}
                </select>
              </label>
              <label><span>TTL</span>
                <select value={form.ttl} onChange={(e) => setForm({ ...form, ttl: Number(e.target.value) })}>
                  {[...TTLS.map(([v]) => v), ...(TTLS.some(([v]) => v === form.ttl) ? [] : [form.ttl])].sort((a, b) => a - b)
                    .map((value) => <option key={value} value={value}>{ttlLabel(value, t)}</option>)}
                </select>
              </label>
              <label className="dns-content"><span>{t('Value')}</span>
                <input value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} placeholder={PLACEHOLDER[form.type]} spellCheck="false" autoComplete="off" />
              </label>
              <div className="dns-form-buttons">
                <button type="submit" disabled={busy || !form.content.trim()}>
                  {form.editing ? <><Save size={15} aria-hidden="true"/> {t('Save')}</> : <><Plus size={15} aria-hidden="true"/> {t('Add')}</>}
                </button>
                {form.editing && <button type="button" className="secondary" onClick={() => setForm(blankRecord(form.ttl))}><X size={15} aria-hidden="true"/> {t('Cancel')}</button>}
              </div>
            </form>
            <p className="hint dns-type-hint">{t(TYPE_HINT[form.type])} {t('@ is the domain itself.')}</p>

            <div className="data-table-wrap">
              <table className="data-table dns-table">
                <thead><tr>
                  <th scope="col">{t('Name')}</th><th scope="col">{t('Type')}</th><th scope="col">TTL</th><th scope="col">{t('Value')}</th><th scope="col"><span className="sr-only">{t('Actions')}</span></th>
                </tr></thead>
                <tbody>
                  {rows.map(({ set, content }) => {
                    const editing = form.editing && form.editing.name === set.name && form.editing.type === set.type && form.editing.content === content;
                    return <tr key={`${set.name}|${set.type}|${content}`} className={editing ? 'editing' : ''}>
                      <td className="dns-name" title={set.fqdn}>{set.name}</td>
                      <td><span className="dns-type" data-type={set.type}>{set.type}</span></td>
                      <td className="data-table-muted dns-ttl">{ttlLabel(set.ttl, t)}</td>
                      <td className="dns-value"><code>{shown(set.type, content)}</code></td>
                      <td className="dns-row-actions">
                        {set.editable
                          ? <>
                            <button type="button" className="secondary icon-button" disabled={busy} onClick={() => editRecord(set, content)} aria-label={t('Edit')} title={t('Edit')}><Pencil size={14} aria-hidden="true"/></button>
                            <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => deleteRecord(set, content)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14} aria-hidden="true"/></button>
                          </>
                          : <span className="data-table-muted dns-locked">{set.type === 'SOA' ? t('Automatic') : t('Administrator')}</span>}
                      </td>
                    </tr>;
                  })}
                </tbody>
              </table>
            </div>
          </>}
      </section>
    </div>
  </div>;
}

function ServiceCard({ overview, service, busy, onRefresh, onSettings, settingsOpen, t }) {
  const up = service?.running && service?.listening && service?.api;
  return <section className="section dns-status" data-state={up ? 'on' : 'off'}>
    <div className="dns-status-head">
      <span className="dns-status-icon">{up ? <CircleCheckBig size={22} aria-hidden="true"/> : <OctagonAlert size={22} aria-hidden="true"/>}</span>
      <div className="dns-status-text">
        <h2>{up ? t('PowerDNS is answering on port 53') : t('PowerDNS is not answering')}</h2>
        <p className="hint">{service?.version ? t('PowerDNS Authoritative {version}', { version: service.version }) : t('PowerDNS Authoritative')}
          {!up && ` · ${t('Install the addon again from Addons to start it.')}`}</p>
      </div>
      <div className="dns-status-actions">
        <button type="button" className="secondary icon-button" disabled={busy} onClick={onRefresh} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
        <button type="button" className={settingsOpen ? '' : 'secondary'} onClick={onSettings} aria-expanded={settingsOpen}><Settings2 size={15} aria-hidden="true"/> {t('Settings')}</button>
      </div>
    </div>
    <div className="dns-delegation">
      <Network size={16} aria-hidden="true"/>
      <div>
        <p>{t('At each domain\'s registrar, set the nameservers to:')} {overview.nameservers.map((ns) => <code key={ns}>{ns}</code>)}</p>
        {overview.server_ip && <p className="hint">{t('Where the nameservers are under a domain of yours, register them at its registrar as glue (child nameservers) with this server\'s address {ip}.', { ip: overview.server_ip })}</p>}
      </div>
    </div>
  </section>;
}

function SettingsCard({ overview, busy, request, setNotice, onSaved, t }) {
  const [draft, setDraft] = useState(() => toDraft(overview.settings));
  const set = (field) => (e) => setDraft({ ...draft, [field]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  const setRow = (index, field, value) => setDraft({ ...draft, template: draft.template.map((row, i) => (i === index ? { ...row, [field]: value } : row)) });

  async function save(event) {
    event.preventDefault();
    const body = {
      nameservers: draft.nameserversText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
      hostmaster: draft.hostmaster,
      server_ip: draft.server_ip,
      server_ipv6: draft.server_ipv6,
      default_ttl: Number(draft.default_ttl),
      template: draft.template.filter((row) => row.content.trim()).map((row) => ({ name: row.name || '@', type: row.type, content: row.content, ttl: row.ttl ? Number(row.ttl) : null })),
    };
    const data = await request('/dns/settings', { method: 'PUT', body: JSON.stringify(body) }, t('Saving DNS settings...'));
    if (data) { onSaved(data.settings); setDraft(toDraft(data.settings)); setNotice(t('DNS settings saved.')); }
  }

  return <section className="section dns-settings">
    <div className="dns-section-head">
      <h2>{t('DNS settings')}</h2>
      <p className="hint">{t('Used for new zones. Zones that exist keep their records.')}</p>
    </div>
    <form onSubmit={save} className="dns-settings-form">
      <div className="dns-settings-grid">
        <label><span>{t('Nameservers')}</span>
          <textarea rows={2} value={draft.nameserversText} onChange={set('nameserversText')} spellCheck="false" /></label>
        <label><span>{t('Hostmaster e-mail')}</span>
          <input value={draft.hostmaster} onChange={set('hostmaster')} spellCheck="false" autoComplete="off" /></label>
        <label><span>{t('Server IPv4')}</span>
          <input value={draft.server_ip} onChange={set('server_ip')} placeholder={overview.server_ip ? t('Automatic: {ip}', { ip: overview.server_ip }) : ''} spellCheck="false" autoComplete="off" /></label>
        <label><span>{t('Server IPv6')}</span>
          <input value={draft.server_ipv6} onChange={set('server_ipv6')} placeholder={t('None: no AAAA records')} spellCheck="false" autoComplete="off" /></label>
        <label><span>{t('Default TTL (seconds)')}</span>
          <input value={draft.default_ttl} onChange={set('default_ttl')} inputMode="numeric" /></label>
      </div>

      <div className="dns-template-head">
        <h3>{t('Zone template')}</h3>
        <p className="hint">{t('{domain} is the zone, {ip} and {ipv6} this server\'s addresses; a line whose address is not set is skipped. SOA and NS come from the settings above.')}</p>
      </div>
      <div className="dns-template">
        {draft.template.map((row, index) => <div className="dns-template-row" key={index}>
          <input value={row.name} onChange={(e) => setRow(index, 'name', e.target.value)} placeholder="@" aria-label={t('Name')} spellCheck="false" />
          <select value={row.type} onChange={(e) => setRow(index, 'type', e.target.value)} aria-label={t('Type')}>
            {overview.types.filter((type) => type !== 'NS').map((type) => <option key={type} value={type}>{type}</option>)}
          </select>
          <input value={row.content} onChange={(e) => setRow(index, 'content', e.target.value)} placeholder={PLACEHOLDER[row.type]} aria-label={t('Value')} spellCheck="false" />
          <button type="button" className="secondary icon-button danger-hover" onClick={() => setDraft({ ...draft, template: draft.template.filter((_, i) => i !== index) })}
            aria-label={t('Remove')} title={t('Remove')}><X size={14} aria-hidden="true"/></button>
        </div>)}
      </div>
      <div className="dns-settings-actions">
        <button type="button" className="secondary" onClick={() => setDraft({ ...draft, template: [...draft.template, { name: '', type: 'A', content: '', ttl: null }] })}><Plus size={14} aria-hidden="true"/> {t('Add a line')}</button>
        <button type="button" className="secondary" onClick={() => setDraft({ ...draft, template: overview.default_template.map((row) => ({ ...row })) })}><RotateCcw size={14} aria-hidden="true"/> {t('Default template')}</button>
        <button type="submit" disabled={busy}><Save size={15} aria-hidden="true"/> {t('Save settings')}</button>
      </div>
    </form>
  </section>;
}

function toDraft(settings) {
  return { ...settings, nameserversText: settings.nameservers.join('\n'), template: settings.template.map((row) => ({ ...row })) };
}

// A reseller's own nameservers: its zones and its customers' are delegated
// to them (empty: the server's).
function ResellerNameservers({ overview, busy, request, setNotice, onSaved, t }) {
  const [text, setText] = useState((overview.reseller_nameservers || []).join('\n'));
  async function save(event) {
    event.preventDefault();
    const nameservers = text.split(/[\s,]+/).map((n) => n.trim()).filter(Boolean);
    const data = await request('/dns/nameservers', { method: 'PUT', body: JSON.stringify({ nameservers }) }, t('Saving the nameservers...'));
    if (data) { setNotice(t('Nameservers saved; {count} zone(s) updated.', { count: data.zones_changed })); onSaved(); }
  }
  return <section className="section dns-reseller-ns">
    <div className="dns-section-head">
      <h2>{t('Your nameservers')}</h2>
      <p className="hint">{t('Your domains and your customers\' are delegated to these. Leave empty to use the server\'s: {list}.', { list: (overview.default_nameservers || []).join(', ') })}</p>
    </div>
    <form className="dns-ns-form" onSubmit={save}>
      <label><span>{t('Nameservers')}</span>
        <textarea rows={2} value={text} onChange={(e) => setText(e.target.value)} placeholder={'ns1.example.com\nns2.example.com'} spellCheck="false" /></label>
      <button type="submit" disabled={busy}><Save size={15} aria-hidden="true"/> {t('Save nameservers')}</button>
    </form>
    {overview.server_ip && <p className="hint">{t('Where the nameservers are under a domain of yours, register them at its registrar as glue (child nameservers) with this server\'s address {ip}.', { ip: overview.server_ip })}</p>}
  </section>;
}
