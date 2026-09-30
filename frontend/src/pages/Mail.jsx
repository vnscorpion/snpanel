import { useEffect, useMemo, useState } from 'react';
import { Boxes, Copy, Dices, ExternalLink, Forward, Globe, Inbox, KeyRound, Mail, Plus, RefreshCw, Save, Search, Server, Trash2, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './Mail.css';

// The Email addon, laid out as OPanel lays it out: one card with the
// webmail and the tabs - mailboxes, forwarders, the mail domains and (for an
// administrator) the server - and one with what a mail app needs. Every
// answer from the API is the whole page again.

const SERVICES = [['exim', 'Exim'], ['dovecot', 'Dovecot'], ['rspamd', 'Rspamd'], ['webmail', msg('Webmail')]];

function size(bytes) {
  if (bytes < 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

const domainOf = (address) => address.split('@')[1] || '';

export default function MailPage() {
  const t = useT();
  const { EmptyState, addons, isAdmin, navigateToPage, request, loading, setNotice, generateRandomPassword } = usePanel();
  const installed = !!addons.items.find((item) => item.slug === 'mail')?.installed;
  const dnsInstalled = !!addons.items.find((item) => item.slug === 'dns')?.installed;
  const [data, setData] = useState(null);
  const [tab, setTab] = useState('mailboxes');
  const [filterDomain, setFilterDomain] = useState('');
  const [query, setQuery] = useState('');
  const [creating, setCreating] = useState(false);
  const [box, setBox] = useState({ local: '', domain: '', password: '', quota: '' });
  const [fwd, setFwd] = useState({ local: '', domain: '', destinations: '' });
  const [editing, setEditing] = useState(null);
  const [copied, setCopied] = useState('');
  const busy = !!loading;

  async function load() {
    const d = await request('/mail', {}, t('Loading email...'));
    if (d) setData(d);
  }
  useEffect(() => { if (installed) load(); }, [installed]);
  useEffect(() => { setCreating(false); setEditing(null); }, [tab]);

  const localDomains = useMemo(() => (data?.domains || []).filter((d) => d.local), [data]);
  const matches = (address) => (!filterDomain || domainOf(address) === filterDomain) && (!query.trim() || address.includes(query.trim().toLowerCase()));
  const mailboxes = useMemo(() => (data?.mailboxes || []).filter((b) => matches(b.address)), [data, filterDomain, query]);
  const forwarders = useMemo(() => (data?.forwarders || []).filter((f) => matches(f.source) || f.destinations.some((d) => d.includes(query.trim().toLowerCase()))), [data, filterDomain, query]);

  if (addons.loaded && !installed) {
    return <section className="section">
      <div className="section-title"><div><h2>{t('Email')}</h2></div></div>
      <EmptyState icon={Mail} message={t('The Email addon is not installed on this server.')} />
      {isAdmin && <div className="addon-missing-actions">
        <button disabled={busy} onClick={() => navigateToPage('addons')}><Boxes size={14}/> {t('Go to Addons')}</button>
      </div>}
    </section>;
  }
  if (!data) return <div className="mail-page"><section className="section"><p className="hint">{t('Loading email...')}</p></section></div>;

  async function send(path, method, body, label) {
    const d = await request(path, { method, body: body ? JSON.stringify(body) : undefined }, label);
    if (d) setData(d);
    return !!d;
  }

  function openCreate() {
    const first = filterDomain && localDomains.some((d) => d.domain === filterDomain) ? filterDomain : localDomains[0]?.domain || '';
    if (tab === 'mailboxes') setBox({ local: '', domain: first, password: generateRandomPassword(16), quota: String(data.default_quota_mb) });
    else setFwd({ local: '', domain: filterDomain || data.domains[0]?.domain || '', destinations: '' });
    setCreating(true);
  }

  async function createMailbox(event) {
    event.preventDefault();
    const body = { address: `${box.local.trim()}@${box.domain}`, password: box.password };
    if (box.quota !== '') body.quota_mb = Number(box.quota);
    if (await send('/mail/mailboxes', 'POST', body, t('Making the mailbox...'))) setCreating(false);
  }

  async function saveMailbox(event) {
    event.preventDefault();
    const body = {};
    if (editing.password) body.password = editing.password;
    if (String(editing.quota) !== String(editing.original)) body.quota_mb = Number(editing.quota);
    if (!Object.keys(body).length) { setEditing(null); return; }
    if (await send(`/mail/mailboxes/${encodeURIComponent(editing.address)}`, 'PATCH', body, t('Saving the mailbox...'))) setEditing(null);
  }

  async function deleteMailbox(address) {
    if (!confirm(t('Delete {address}?\n\nThe mailbox and every message in it are deleted. This cannot be undone.', { address }))) return;
    await send(`/mail/mailboxes/${encodeURIComponent(address)}`, 'DELETE', null, t('Deleting the mailbox...'));
  }

  async function openWebmail(address) {
    // Opened now, while the click still counts as the person's: a window
    // opened after the request would be blocked as a pop-up.
    const win = window.open('about:blank', '_blank');
    const d = await request(`/mail/mailboxes/${encodeURIComponent(address)}/webmail`, { method: 'POST' }, t('Opening the webmail...'));
    if (d?.url && win) { win.opener = null; win.location.href = d.url; } else if (win) win.close();
  }

  async function createForwarder(event) {
    event.preventDefault();
    const body = { source: `${fwd.local.trim()}@${fwd.domain}`, destinations: fwd.destinations };
    if (await send('/mail/forwarders', 'POST', body, t('Saving the forwarder...'))) setCreating(false);
  }

  async function deleteForwarder(source) {
    if (!confirm(t('Stop forwarding {address}?', { address: source }))) return;
    await send(`/mail/forwarders/${encodeURIComponent(source)}`, 'DELETE', null, t('Removing the forwarder...'));
  }

  async function setLocal(domain, local) {
    await send(`/mail/domains/${encodeURIComponent(domain)}`, 'PUT', { local }, t('Saving...'));
  }

  async function copy(text, key) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setNotice(t('Copied')); setTimeout(() => setCopied(''), 1500); } catch { setCopied(''); }
  }

  const client = data.client;
  const tabs = [
    ['mailboxes', Inbox, t('Mailboxes')],
    ['forwarders', Forward, t('Forwarders')],
    ['domains', Globe, t('Domains')],
    ...(data.is_admin && data.service ? [['server', Server, t('Server')]] : []),
  ];
  const domainSelect = (value, onChange, list, all) => <select value={value} onChange={(e) => onChange(e.target.value)} aria-label={t('Domain')}>
    {all && <option value="">{t('All domains')}</option>}
    {list.map((d) => <option key={d.domain} value={d.domain}>{d.domain}{d.owner ? ` (${d.owner})` : ''}</option>)}
  </select>;

  const toolbar = (label) => <div className="mail-toolbar">
    {domainSelect(filterDomain, setFilterDomain, data.domains, true)}
    <div className="mail-search">
      <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('Search')} aria-label={t('Search')} spellCheck="false" />
      <button type="button" className="secondary icon-button" aria-label={t('Search')} title={t('Search')}><Search size={15} aria-hidden="true"/></button>
    </div>
    <button type="button" className="mail-new" disabled={busy || data.domains.length === 0 || (tab === 'mailboxes' && localDomains.length === 0)} onClick={openCreate}><Plus size={15} aria-hidden="true"/> {label}</button>
  </div>;

  return <div className="mail-page">
    <section className="section mail-main">
      <div className="section-title">
        <div>
          <h2>{t('Email')}</h2>
          <p className="hint">{data.is_admin ? t('Mailboxes, forwarders and DNS records of every mail domain on this server.') : t('Mailboxes and forwarders of your websites\' domains.')}</p>
        </div>
        <div className="mail-head-actions">
          <a className="button secondary" href={client.webmail} target="_blank" rel="noreferrer noopener"><ExternalLink size={15} aria-hidden="true"/> {t('Webmail')}</a>
          <button type="button" className="secondary" disabled={busy} onClick={load}><RefreshCw size={15} aria-hidden="true"/> {t('Refresh')}</button>
        </div>
      </div>
      <div className="tab-bar" role="tablist" aria-label={t('Email sections')}>
        {tabs.map(([key, Icon, label]) => <button key={key} type="button" role="tab" aria-selected={tab === key}
          className={tab === key ? 'tab active' : 'tab'} onClick={() => setTab(key)}><Icon size={14} aria-hidden="true"/> {label}</button>)}
      </div>

      {data.domains.length === 0 && <EmptyState icon={Mail} message={t('Add a website first: mailboxes are made on the websites\' domains.')} />}

      {tab === 'mailboxes' && data.domains.length > 0 && <div className="mail-tab">
        {toolbar(t('New mailbox'))}
        {creating && <form className="mail-create" onSubmit={createMailbox}>
          <div className="mail-create-head"><strong>{t('New mailbox')}</strong>
            <button type="button" className="secondary icon-button" onClick={() => setCreating(false)} aria-label={t('Close')} title={t('Close')}><X size={15} aria-hidden="true"/></button></div>
          <div className="mail-create-grid">
            <label className="mail-create-address"><span>{t('Address')}</span>
              <div className="mail-address-pick">
                <input value={box.local} onChange={(e) => setBox({ ...box, local: e.target.value })} placeholder="info" spellCheck="false" autoComplete="off" autoFocus />
                <span aria-hidden="true">@</span>
                {domainSelect(box.domain, (v) => setBox({ ...box, domain: v }), localDomains, false)}
              </div>
            </label>
            <label><span>{t('Password')}</span>
              <div className="mail-password-input">
                <input type="text" value={box.password} onChange={(e) => setBox({ ...box, password: e.target.value })} spellCheck="false" autoComplete="new-password" />
                <button type="button" className="secondary icon-button" onClick={() => setBox({ ...box, password: generateRandomPassword(16) })} aria-label={t('Generate')} title={t('Generate')}><Dices size={15} aria-hidden="true"/></button>
                <button type="button" className="secondary icon-button" onClick={() => copy(box.password, 'new')} aria-label={t('Copy')} title={t('Copy')}><Copy size={15} aria-hidden="true"/></button>
              </div>
            </label>
            <label><span>{t('Size (MB)')} <em>{t('0 = unlimited')}</em></span>
              <input value={box.quota} onChange={(e) => setBox({ ...box, quota: e.target.value.replace(/\D/g, '') })} inputMode="numeric" /></label>
            <button type="submit" disabled={busy || !box.local.trim() || box.password.length < 8 || !box.domain}><Plus size={15} aria-hidden="true"/> {t('Create')}</button>
          </div>
          <p className="hint">{t('Copy the password now: it is not shown again. It signs in to the webmail and to any mail app, with the full address as the username.')}</p>
        </form>}
        {mailboxes.length === 0
          ? <EmptyState icon={Inbox} message={t('No mailboxes yet.')} />
          : <div className="mail-list">
            {mailboxes.map((b) => {
              const quota = b.quota_mb * 1024 * 1024;
              const percent = quota ? Math.min(100, Math.round((b.used_bytes / quota) * 100)) : 0;
              const isEditing = editing?.address === b.address;
              return <div className="mail-row" key={b.address}>
                <div className="mail-row-main"><strong>{b.address}</strong>{b.owner && <small>{t('Account: {name}', { name: b.owner })}</small>}</div>
                <div className="mail-usage">
                  <span>{size(b.used_bytes)} / {b.quota_mb ? `${b.quota_mb} MB` : t('No limit')}</span>
                  <span className="mail-bar" data-level={percent >= 90 ? 'high' : percent >= 70 ? 'mid' : 'low'}><span style={{ width: `${b.quota_mb ? percent : 0}%` }} /></span>
                </div>
                <div className="mail-row-actions">
                  <button type="button" disabled={busy} onClick={() => openWebmail(b.address)}><Mail size={14} aria-hidden="true"/> {t('Webmail')}</button>
                  <button type="button" className="secondary" disabled={busy} onClick={() => setEditing(isEditing ? null : { address: b.address, password: '', quota: b.quota_mb, original: b.quota_mb })}><KeyRound size={14} aria-hidden="true"/> {t('Edit')}</button>
                  <button type="button" className="secondary icon-button danger-hover mail-delete" disabled={busy} onClick={() => deleteMailbox(b.address)} aria-label={t('Delete {name}', { name: b.address })} title={t('Delete')}><Trash2 size={14} aria-hidden="true"/></button>
                </div>
                {isEditing && <form className="mail-edit" onSubmit={saveMailbox}>
                  <label><span>{t('New password')}</span>
                    <div className="mail-password-input">
                      <input type="text" value={editing.password} onChange={(e) => setEditing({ ...editing, password: e.target.value })} placeholder={t('Unchanged')} spellCheck="false" autoComplete="new-password" />
                      <button type="button" className="secondary icon-button" onClick={() => setEditing({ ...editing, password: generateRandomPassword(16) })} aria-label={t('Generate')} title={t('Generate')}><Dices size={15} aria-hidden="true"/></button>
                    </div>
                  </label>
                  <label><span>{t('Size (MB)')} <em>{t('0 = unlimited')}</em></span>
                    <input value={editing.quota} onChange={(e) => setEditing({ ...editing, quota: e.target.value.replace(/\D/g, '') })} inputMode="numeric" /></label>
                  <div className="mail-edit-buttons">
                    <button type="submit" disabled={busy || (editing.password && editing.password.length < 8) || editing.quota === ''}><Save size={15} aria-hidden="true"/> {t('Save')}</button>
                    <button type="button" className="secondary" onClick={() => setEditing(null)}>{t('Cancel')}</button>
                  </div>
                </form>}
              </div>;
            })}
          </div>}
      </div>}

      {tab === 'forwarders' && data.domains.length > 0 && <div className="mail-tab">
        {toolbar(t('New forwarder'))}
        {creating && <form className="mail-create" onSubmit={createForwarder}>
          <div className="mail-create-head"><strong>{t('New forwarder')}</strong>
            <button type="button" className="secondary icon-button" onClick={() => setCreating(false)} aria-label={t('Close')} title={t('Close')}><X size={15} aria-hidden="true"/></button></div>
          <div className="mail-create-grid mail-fwd-grid">
            <label className="mail-create-address"><span>{t('Address')}</span>
              <div className="mail-address-pick">
                <input value={fwd.local} onChange={(e) => setFwd({ ...fwd, local: e.target.value })} placeholder="sales" spellCheck="false" autoComplete="off" autoFocus />
                <span aria-hidden="true">@</span>
                {domainSelect(fwd.domain, (v) => setFwd({ ...fwd, domain: v }), data.domains, false)}
              </div>
            </label>
            <label><span>{t('Forward to')}</span>
              <input value={fwd.destinations} onChange={(e) => setFwd({ ...fwd, destinations: e.target.value })} placeholder="you@gmail.com, team@example.com" spellCheck="false" autoComplete="off" /></label>
            <button type="submit" disabled={busy || !fwd.local.trim() || !fwd.destinations.trim() || !fwd.domain}><Plus size={15} aria-hidden="true"/> {t('Create')}</button>
          </div>
          <p className="hint">{t('Mail to an address here is sent on to other addresses. On a mailbox, a copy stays in it.')}</p>
        </form>}
        {forwarders.length === 0
          ? <EmptyState icon={Forward} message={t('No forwarders yet.')} />
          : <div className="mail-list">
            {forwarders.map((f) => <div className="mail-row mail-fwd-row" key={f.source}>
              <div className="mail-row-main"><strong>{f.source}</strong>{f.owner && <small>{t('Account: {name}', { name: f.owner })}</small>}</div>
              <div className="mail-destinations"><Forward size={14} aria-hidden="true"/><span>{f.destinations.join(', ')}</span></div>
              <div className="mail-row-actions">
                <button type="button" className="secondary icon-button danger-hover mail-delete" disabled={busy} onClick={() => deleteForwarder(f.source)} aria-label={t('Delete {name}', { name: f.source })} title={t('Delete')}><Trash2 size={14} aria-hidden="true"/></button>
              </div>
            </div>)}
          </div>}
      </div>}

      {tab === 'domains' && data.domains.length > 0 && <div className="mail-tab">
        <p className="hint">{t('Every website and alias is a mail domain. Mail for one arrives here once its MX record points at {host}.', { host: client.host })}</p>
        <div className="mail-list">
          {data.domains.map((d) => <div className="mail-row mail-domain-row" key={d.domain}>
            <div className="mail-row-main"><strong>{d.domain}</strong>
              <small>{t('{mailboxes} mailboxes · {forwarders} forwarders', { mailboxes: d.mailboxes, forwarders: d.forwarders ?? 0 })}{d.owner ? ` · ${t('Account: {name}', { name: d.owner })}` : ''}</small></div>
            <label className="check-line mail-local">
              <input type="checkbox" checked={d.local} disabled={busy} onChange={(e) => setLocal(d.domain, e.target.checked)} />
              <span>{d.local ? t('Mail is received here') : t('Mail goes to its own server (MX elsewhere)')}</span>
            </label>
            <div className="mail-row-actions">
              {dnsInstalled && <button type="button" className="secondary" onClick={() => navigateToPage('dns', { query: `zone=${encodeURIComponent(d.domain)}` })}><Globe size={14} aria-hidden="true"/> {t('DNS records')}</button>}
            </div>
          </div>)}
        </div>
      </div>}

      {tab === 'server' && data.service && <div className="mail-tab">
        <div className="mail-server">
          <div><span className="hint">{t('Hostname')}</span><strong>{data.service.hostname}</strong></div>
          <div><span className="hint">{t('Queue')}</span><strong>{t('{count} message(s) waiting to be delivered', { count: data.service.queue ?? '?' })}</strong></div>
        </div>
        <ul className="mail-services" aria-label={t('Services')}>
          {SERVICES.map(([key, name]) => <li key={key} data-on={data.service.services?.[key] ? 'yes' : 'no'}>
            <span>{t(name)}</span><strong>{data.service.services?.[key] ? t('Running') : t('Stopped')}</strong></li>)}
        </ul>
      </div>}
    </section>

    <section className="section mail-client">
      <div className="mail-client-head">
        <div><h2>{t('Mail app settings')}</h2>
          <p className="hint">{t('For Outlook, Thunderbird, Apple Mail or a phone. The username is the full email address, the password the mailbox\'s own.')}</p></div>
      </div>
      <div className="mail-server-name">
        <span>{t('Server (IMAP, POP3 and SMTP)')}</span>
        <button type="button" className="secondary" onClick={() => copy(client.host, 'host')}><Copy size={14} aria-hidden="true"/> {copied === 'host' ? t('Copied') : t('Copy')}</button>
      </div>
      <pre className="mail-host">{client.host}</pre>
      <ul className="mail-ports">
        <li><strong>IMAP</strong><span>{t('port {port}, SSL/TLS', { port: client.imap })}</span></li>
        <li><strong>POP3</strong><span>{t('port {port}, SSL/TLS', { port: client.pop3 })}</span></li>
        <li><strong>SMTP</strong><span>{t('port {port}, SSL/TLS — or {submission} with STARTTLS', { port: client.smtp, submission: client.submission })}</span></li>
      </ul>
    </section>
  </div>;
}
