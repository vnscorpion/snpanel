import { useEffect, useMemo, useState } from 'react';
import { Boxes, CircleCheckBig, Copy, Dices, ExternalLink, Forward, KeyRound, Mail, OctagonAlert, Plus, RefreshCw, Save, Trash2, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Mail.css';

// The Email addon: mailboxes and forwarders on the domains of the caller's
// websites (every domain, for an administrator), how to set up a mail
// client, and the webmail, opened signed in. Every answer is the whole page
// again, so a change shows as soon as it is made.

const SERVICES = [['exim', 'Exim'], ['dovecot', 'Dovecot'], ['rspamd', 'Rspamd'], ['webmail', 'Webmail']];

function size(bytes) {
  if (bytes < 1024 * 1024) return `${Math.max(0, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function MailPage() {
  const t = useT();
  const { EmptyState, addons, isAdmin, navigateToPage, request, loading, setNotice, generateRandomPassword } = usePanel();
  const installed = !!addons.items.find((item) => item.slug === 'mail')?.installed;
  const [data, setData] = useState(null);
  const [domain, setDomain] = useState('');
  const [box, setBox] = useState({ local: '', password: '', quota: '' });
  const [fwd, setFwd] = useState({ local: '', destinations: '' });
  const [editing, setEditing] = useState(null);
  const [copied, setCopied] = useState('');
  const busy = !!loading;

  async function load() {
    const d = await request('/mail', {}, t('Loading email...'));
    if (d) take(d);
  }
  function take(d) {
    setData(d);
    setDomain((current) => (d.domains.some((x) => x.domain === current) ? current : d.domains[0]?.domain || ''));
  }
  useEffect(() => { if (installed) load(); }, [installed]);

  const mailboxes = useMemo(() => (data?.mailboxes || []).filter((b) => !domain || b.address.endsWith(`@${domain}`)), [data, domain]);
  const forwarders = useMemo(() => (data?.forwarders || []).filter((f) => !domain || f.source.endsWith(`@${domain}`)), [data, domain]);

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

  const current = data.domains.find((d) => d.domain === domain);

  async function send(path, method, body, label) {
    const d = await request(path, { method, body: body ? JSON.stringify(body) : undefined }, label);
    if (d) take(d);
    return !!d;
  }

  async function createMailbox(event) {
    event.preventDefault();
    const body = { address: `${box.local.trim()}@${domain}`, password: box.password };
    if (box.quota !== '') body.quota_mb = Number(box.quota);
    if (await send('/mail/mailboxes', 'POST', body, t('Making the mailbox...'))) setBox({ local: '', password: '', quota: '' });
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
    const body = { source: `${fwd.local.trim()}@${domain}`, destinations: fwd.destinations };
    if (await send('/mail/forwarders', 'POST', body, t('Saving the forwarder...'))) setFwd({ local: '', destinations: '' });
  }

  async function deleteForwarder(source) {
    if (!confirm(t('Stop forwarding {address}?', { address: source }))) return;
    await send(`/mail/forwarders/${encodeURIComponent(source)}`, 'DELETE', null, t('Removing the forwarder...'));
  }

  async function setLocal(local) {
    await send(`/mail/domains/${encodeURIComponent(domain)}`, 'PUT', { local }, t('Saving...'));
  }

  async function copy(text, key) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(''), 1500); } catch { setCopied(''); }
  }

  const client = data.client;
  const up = data.service && Object.values(data.service.services || {}).every(Boolean);

  return <div className="mail-page">
    {data.is_admin && data.service && <section className="section mail-status" data-state={up ? 'on' : 'off'}>
      <div className="mail-status-head">
        <span className="mail-status-icon">{up ? <CircleCheckBig size={22} aria-hidden="true"/> : <OctagonAlert size={22} aria-hidden="true"/>}</span>
        <div className="mail-status-text">
          <h2>{up ? t('The mail server is running') : t('Part of the mail server is stopped')}</h2>
          <p className="hint">{t('Queue: {count} message(s) waiting to be delivered', { count: data.service.queue ?? '?' })}</p>
        </div>
        <ul className="mail-services" aria-label={t('Services')}>
          {SERVICES.map(([key, name]) => <li key={key} data-on={data.service.services?.[key] ? 'yes' : 'no'}>{name}</li>)}
        </ul>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={load} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
    </section>}

    {data.domains.length === 0
      ? <section className="section"><EmptyState icon={Mail} message={t('Add a website first: mailboxes are made on the websites\' domains.')} /></section>
      : <>
        <section className="section mail-domain-bar">
          <label className="mail-domain-pick"><span>{t('Domain')}</span>
            <select value={domain} onChange={(e) => { setDomain(e.target.value); setEditing(null); }}>
              {data.domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain} ({d.mailboxes})</option>)}
            </select>
          </label>
          {current && <label className="check-line mail-local">
            <input type="checkbox" checked={current.local} disabled={busy} onChange={(e) => setLocal(e.target.checked)} />
            <span>{t('Receive this domain\'s mail here')}</span>
          </label>}
          {current && !current.local && <p className="hint mail-remote-hint">{t('Its MX points elsewhere (Google Workspace, Microsoft 365...): mail from this server to it goes there.')}</p>}
        </section>

        <section className="section mail-boxes">
          <div className="mail-section-head">
            <h2>{t('Mailboxes')}</h2>
            <p className="hint">{t('Each mailbox signs in to the webmail and to mail apps with its full address.')}</p>
          </div>
          <form className="mail-box-form" onSubmit={createMailbox}>
            <label><span>{t('Address')}</span>
              <div className="mail-address-input">
                <input value={box.local} onChange={(e) => setBox({ ...box, local: e.target.value })} placeholder="info" spellCheck="false" autoComplete="off" />
                <span className="mail-suffix" title={domain}>@{domain}</span>
              </div>
            </label>
            <label><span>{t('Password')}</span>
              <div className="mail-password-input">
                <input type="text" value={box.password} onChange={(e) => setBox({ ...box, password: e.target.value })} placeholder={t('At least 8 characters')} spellCheck="false" autoComplete="new-password" />
                <button type="button" className="secondary icon-button" onClick={() => setBox({ ...box, password: generateRandomPassword(16) })} aria-label={t('Generate')} title={t('Generate')}><Dices size={15} aria-hidden="true"/></button>
              </div>
            </label>
            <label><span>{t('Quota (MB)')}</span>
              <input value={box.quota} onChange={(e) => setBox({ ...box, quota: e.target.value.replace(/\D/g, '') })} placeholder={String(data.default_quota_mb)} inputMode="numeric" />
            </label>
            <button type="submit" disabled={busy || !box.local.trim() || box.password.length < 8 || !current?.local}><Plus size={15} aria-hidden="true"/> {t('Add mailbox')}</button>
          </form>
          {current && !current.local && <p className="hint">{t('Turn on "Receive this domain\'s mail here" to make mailboxes on it.')}</p>}

          {mailboxes.length === 0
            ? <p className="empty-note">{t('No mailboxes on {domain} yet.', { domain })}</p>
            : <div className="data-table-wrap"><table className="data-table mail-table">
              <thead><tr><th scope="col">{t('Address')}</th><th scope="col">{t('Used')}</th><th scope="col"><span className="sr-only">{t('Actions')}</span></th></tr></thead>
              <tbody>
                {mailboxes.map((b) => {
                  const quota = b.quota_mb * 1024 * 1024;
                  const percent = quota ? Math.min(100, Math.round((b.used_bytes / quota) * 100)) : 0;
                  const isEditing = editing?.address === b.address;
                  return <tr key={b.address} className={isEditing ? 'editing' : ''}>
                    <td className="mail-address">{b.address}</td>
                    <td className="mail-usage">
                      <span>{size(b.used_bytes)} / {b.quota_mb ? size(quota) : t('No limit')}</span>
                      {b.quota_mb > 0 && <span className="mail-bar" data-level={percent >= 90 ? 'high' : percent >= 70 ? 'mid' : 'low'}><span style={{ width: `${percent}%` }} /></span>}
                    </td>
                    <td className="mail-row-actions">
                      <button type="button" className="secondary" disabled={busy} onClick={() => openWebmail(b.address)}><ExternalLink size={14} aria-hidden="true"/> {t('Webmail')}</button>
                      <button type="button" className="secondary icon-button" disabled={busy} onClick={() => setEditing({ address: b.address, password: '', quota: b.quota_mb, original: b.quota_mb })} aria-label={t('Change password or quota')} title={t('Change password or quota')}><KeyRound size={14} aria-hidden="true"/></button>
                      <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => deleteMailbox(b.address)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14} aria-hidden="true"/></button>
                    </td>
                  </tr>;
                })}
              </tbody>
            </table></div>}

          {editing && <form className="mail-edit" onSubmit={saveMailbox} aria-label={t('Change password or quota')}>
            <strong>{editing.address}</strong>
            <label><span>{t('New password')}</span>
              <div className="mail-password-input">
                <input type="text" value={editing.password} onChange={(e) => setEditing({ ...editing, password: e.target.value })} placeholder={t('Unchanged')} spellCheck="false" autoComplete="new-password" />
                <button type="button" className="secondary icon-button" onClick={() => setEditing({ ...editing, password: generateRandomPassword(16) })} aria-label={t('Generate')} title={t('Generate')}><Dices size={15} aria-hidden="true"/></button>
              </div>
            </label>
            <label><span>{t('Quota (MB, 0 = no limit)')}</span>
              <input value={editing.quota} onChange={(e) => setEditing({ ...editing, quota: e.target.value.replace(/\D/g, '') })} inputMode="numeric" />
            </label>
            <div className="mail-edit-buttons">
              <button type="submit" disabled={busy || (editing.password && editing.password.length < 8) || editing.quota === ''}><Save size={15} aria-hidden="true"/> {t('Save')}</button>
              <button type="button" className="secondary" onClick={() => setEditing(null)}><X size={15} aria-hidden="true"/> {t('Cancel')}</button>
            </div>
          </form>}
        </section>

        <section className="section mail-forwarders">
          <div className="mail-section-head">
            <h2>{t('Forwarders')}</h2>
            <p className="hint">{t('Mail to an address here is sent on to other addresses. On a mailbox, a copy stays in it.')}</p>
          </div>
          <form className="mail-fwd-form" onSubmit={createForwarder}>
            <label><span>{t('Address')}</span>
              <div className="mail-address-input">
                <input value={fwd.local} onChange={(e) => setFwd({ ...fwd, local: e.target.value })} placeholder="sales" spellCheck="false" autoComplete="off" />
                <span className="mail-suffix" title={domain}>@{domain}</span>
              </div>
            </label>
            <label><span>{t('Forward to')}</span>
              <input value={fwd.destinations} onChange={(e) => setFwd({ ...fwd, destinations: e.target.value })} placeholder="you@gmail.com, team@example.com" spellCheck="false" autoComplete="off" />
            </label>
            <button type="submit" disabled={busy || !fwd.local.trim() || !fwd.destinations.trim()}><Forward size={15} aria-hidden="true"/> {t('Add forwarder')}</button>
          </form>
          {forwarders.length === 0
            ? <p className="empty-note">{t('No forwarders on {domain}.', { domain })}</p>
            : <ul className="mail-fwd-list">
              {forwarders.map((f) => <li key={f.source}>
                <span className="mail-address">{f.source}</span>
                <Forward size={14} aria-hidden="true"/>
                <span className="mail-destinations">{f.destinations.join(', ')}</span>
                <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => deleteForwarder(f.source)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14} aria-hidden="true"/></button>
              </li>)}
            </ul>}
        </section>
      </>}

    <section className="section mail-client">
      <div className="mail-section-head">
        <h2>{t('Mail apps')}</h2>
        <p className="hint">{t('For Outlook, Thunderbird, Apple Mail or a phone: the username is the full address, the password the mailbox\'s.')}</p>
      </div>
      <dl className="mail-client-grid">
        {[
          ['host', t('Server'), client.host],
          ['imap', 'IMAP', `${client.host} · ${client.imap} · SSL/TLS`],
          ['pop3', 'POP3', `${client.host} · ${client.pop3} · SSL/TLS`],
          ['smtp', 'SMTP', `${client.host} · ${client.smtp} SSL/TLS ${t('or')} ${client.submission} STARTTLS`],
        ].map(([key, label, value]) => <div key={key}>
          <dt>{label}</dt>
          <dd><code>{value}</code>
            {key === 'host' && <button type="button" className="secondary icon-button" onClick={() => copy(value, key)} aria-label={t('Copy')} title={copied === key ? t('Copied') : t('Copy')}><Copy size={13} aria-hidden="true"/></button>}
          </dd>
        </div>)}
        <div>
          <dt>{t('Webmail')}</dt>
          <dd><a href={client.webmail} target="_blank" rel="noreferrer noopener">{client.webmail}</a></dd>
        </div>
      </dl>
    </section>
  </div>;
}
