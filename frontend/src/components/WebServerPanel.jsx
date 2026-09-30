import { useEffect, useState } from 'react';
import { ArrowLeftRight, CircleCheckBig, Copy, ExternalLink, KeyRound, OctagonAlert, RefreshCw, RotateCcw, ShieldCheck, TriangleAlert } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './WebServerPanel.css';

// LiteSpeed Enterprise and its Apache standby (Hosting Edition): who answers
// the sites now, the last failover and switching back, and LiteSpeed's own
// management - restart, licence, WebAdmin. Hidden where LiteSpeed is not
// installed (the API answers 409 there).
export default function WebServerPanel() {
  const t = useT();
  const { request, loading } = usePanel();
  const [web, setWeb] = useState(null);
  const [secret, setSecret] = useState(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    const d = await request('/hosting/web', { silent: true });
    setWeb(d || { missing: true });
  }
  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  if (!web || web.missing) return null;

  async function switchTo(to) {
    const d = await request('/hosting/web/switch', { method: 'POST', body: JSON.stringify({ to }) },
      to === 'lsws' ? t('Switching the sites back to LiteSpeed...') : t('Switching the sites to Apache...'));
    if (d) setWeb(d);
  }
  async function restartLsws() {
    const d = await request('/hosting/lsws/restart', { method: 'POST' }, t('Restarting LiteSpeed...'));
    if (d) setWeb(d);
  }
  async function newPassword() {
    setCopied(false);
    const d = await request('/hosting/lsws/admin-password', { method: 'POST' }, t('Setting a new WebAdmin password...'));
    if (d?.password) setSecret(d);
  }
  async function openAdminPort() {
    const d = await request('/firewall/allow-port', { method: 'POST', body: JSON.stringify({ port: String(web.admin.port), protocol: 'tcp' }) },
      t('Opening port {port}...', { port: web.admin.port }));
    if (d) await load();
  }
  async function copySecret() {
    try { await navigator.clipboard.writeText(secret.password); setCopied(true); } catch { setCopied(false); }
  }

  const onApache = web.live === 'apache';
  const failover = web.last_failover;
  const adminUrl = `https://${window.location.hostname}:${web.admin.port}/`;
  const ok = (flag) => <span className={flag ? 'badge ok' : 'badge bad'}>{flag ? t('Yes') : t('No')}</span>;

  return <section className="section web-server-panel">
    <div className="section-title">
      <div><h2>{t('Web server')}</h2><p className="hint">{t('LiteSpeed serves the sites; Apache stands by and takes over if LiteSpeed stops or its licence runs out.')}</p></div>
      <button className="secondary-light" disabled={!!loading} onClick={load}><RefreshCw size={15}/> {t('Refresh')}</button>
    </div>

    {onApache
      ? <div className="web-banner" data-tone="bad">
          <OctagonAlert size={20} aria-hidden="true"/>
          <div>
            <strong>{t('The sites are running on Apache (failover).')}</strong>
            {failover && <p>{t('Switched at {at}: {reason}', { at: failover.at, reason: failover.text.replace(/^FAILOVER to apache:\s*/, '') })}</p>}
            <p>{web.lsws.answering
              ? t('LiteSpeed is answering again. Switch the sites back when you are ready.')
              : t('LiteSpeed is not answering. Restart it, then switch the sites back.')}</p>
          </div>
          <div className="web-banner-actions">
            {!web.lsws.answering && <button onClick={restartLsws} disabled={!!loading}><RotateCcw size={14}/> {t('Restart LiteSpeed')}</button>}
            <button onClick={() => switchTo('lsws')} disabled={!!loading || !web.lsws.answering}><ArrowLeftRight size={14}/> {t('Switch back to LiteSpeed')}</button>
          </div>
        </div>
      : <div className="web-banner" data-tone="ok">
          <CircleCheckBig size={20} aria-hidden="true"/>
          <div>
            <strong>{t('LiteSpeed is serving the sites.')}</strong>
            {failover && <p className="hint">{t('Last failover: {at}', { at: failover.at })}</p>}
          </div>
        </div>}

    {!web.watchdog_active && <p className="web-warning"><TriangleAlert size={15} aria-hidden="true"/> {t('The failover watchdog is not running: if LiteSpeed stops, the sites stop with it.')}</p>}

    <div className="web-grid">
      <div className="web-card">
        <h3>LiteSpeed Enterprise {web.lsws.version && <small>{web.lsws.version}</small>}</h3>
        <dl>
          <dt>{t('Running')}</dt><dd>{ok(web.lsws.active)}</dd>
          <dt>{t('Answering')}</dt><dd>{ok(web.lsws.answering)}</dd>
          <dt>{t('Licence')}</dt><dd>
            <span className={web.lsws.licence_ok ? 'badge ok' : 'badge bad'}>{web.lsws.licence_ok ? t('Valid') : t('Check')}</span>
            {web.lsws.licence.map((line, i) => <small key={i} className="web-licence">{line}</small>)}
          </dd>
        </dl>
        <div className="row-actions">
          <button className="mini secondary-light" onClick={restartLsws} disabled={!!loading}><RotateCcw size={14}/> {t('Restart LiteSpeed')}</button>
          {!onApache && <button className="mini secondary-light" onClick={() => switchTo('apache')} disabled={!!loading || !web.apache.answering}
            title={t('For maintenance: send the sites to Apache until you switch back')}><ArrowLeftRight size={14}/> {t('Switch to Apache')}</button>}
        </div>
      </div>

      <div className="web-card">
        <h3>{t('LiteSpeed WebAdmin')}</h3>
        <dl>
          <dt>{t('Address')}</dt><dd><code>{adminUrl}</code></dd>
          <dt>{t('User')}</dt><dd><code>admin</code></dd>
          <dt>{t('Port {port}', { port: web.admin.port })}</dt><dd>
            {web.admin.open
              ? <span className="badge ok">{t('Open in the firewall')}</span>
              : <><span className="badge bad">{t('Closed in the firewall')}</span> <button className="mini" onClick={openAdminPort} disabled={!!loading}><ShieldCheck size={13}/> {t('Open port {port}', { port: web.admin.port })}</button></>}
          </dd>
        </dl>
        {secret && <div className="web-secret">
          <p>{t('New WebAdmin password - shown only now:')}</p>
          <code>{secret.password}</code>
          <button className="mini secondary-light" onClick={copySecret}><Copy size={13}/> {copied ? t('Copied') : t('Copy')}</button>
        </div>}
        <div className="row-actions">
          <button className="mini secondary-light" onClick={newPassword} disabled={!!loading}><KeyRound size={14}/> {t('New WebAdmin password')}</button>
          <a className="button-link mini" href={adminUrl} target="_blank" rel="noopener noreferrer"><ExternalLink size={14}/> {t('Open WebAdmin')}</a>
        </div>
      </div>

      <div className="web-card">
        <h3>{t('Apache (standby)')}</h3>
        <dl>
          <dt>{t('Running')}</dt><dd>{ok(web.apache.active)}</dd>
          <dt>{t('Answering')}</dt><dd>{ok(web.apache.answering)}</dd>
          <dt>{t('Watchdog')}</dt><dd>{ok(web.watchdog_active)}</dd>
        </dl>
        <p className="hint">{t('Both servers read the same site configuration, so a switch takes effect at once and restarts nothing.')}</p>
      </div>
    </div>
  </section>;
}
