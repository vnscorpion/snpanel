import { Plus, RefreshCw, RotateCw, ShieldAlert, ShieldCheck, ShieldOff, ShieldQuestion, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Firewall.css';

// The blocklist status is text for people, with a few lines the page reads:
// the URLs under "URLs:", the two set sizes under "Sets:", and the timer's
// `systemctl is-enabled` answer, the first line under "Timer:". The helper's
// `blocklist_status_lines` writes them, and its test
// `the_blocklist_status_headers_are_what_the_browser_parses` holds them still.
export function parseBlocklistStatus(text) {
  const urls = [];
  let section = '';
  let blocked = null;
  let timer = null;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (/^[A-Z][A-Za-z ]*:$/.test(line)) { section = line.slice(0, -1); continue; }
    if (section === 'URLs' && /^https?:\/\//i.test(line)) urls.push(line);
    if (section === 'Sets') {
      const count = /^snpanel-block[46]\s+(\d+) entries$/.exec(line);
      if (count) blocked = (blocked || 0) + Number(count[1]);
    }
    // One lowercase word - "enabled", "disabled" - or nothing: a unit that
    // does not exist leaves the list-timers table as the first line instead.
    if (section === 'Timer' && timer === null && /^[a-z-]+$/.test(line)) timer = line;
  }
  return { urls, blocked, timer };
}

// On, off, on but not enforcing, or not known - from the summary the API
// takes out of the helper's `firewall-list`.
function firewallState(status) {
  if (!status) return 'loading';
  const { state, chain_active: chainActive } = status.summary || {};
  if (state === 'disabled') return 'off';
  if (state === 'enabled') return chainActive === false ? 'idle' : 'on';
  return 'unknown';
}

const STATE_VIEW = {
  loading: { Icon: ShieldQuestion },
  on: { Icon: ShieldCheck },
  idle: { Icon: ShieldAlert },
  off: { Icon: ShieldOff },
  unknown: { Icon: ShieldQuestion },
};

export default function FirewallPage() {
  const {
    addFirewallBlocklistUrl,
    addFirewallRule,
    deleteFirewallBlocklistUrl,
    deleteFirewallRule,
    disableFirewall,
    enableFirewall,
    firewallBlocklistUrl,
    firewallBlocklists,
    firewallRule,
    firewallStatus,
    isAdmin,
    loadFirewall,
    loadFirewallBlocklists,
    loading,
    reloadFirewall,
    setFirewallBlocklistUrl,
    setFirewallRule,
    updateFirewallBlocklistsNow,
  } = usePanel();
  const t = useT();

  if (!isAdmin) return <section className="section"><h2>{t('Firewall')}</h2><p className="hint">{t('No permission.')}</p></section>;

  const busy = !!loading;
  const state = firewallState(firewallStatus);
  const { Icon: StateIcon } = STATE_VIEW[state];
  const title = {
    loading: t('Loading firewall status…'),
    on: t('The firewall is on'),
    idle: t('The firewall is on, but not enforcing'),
    off: t('The firewall is off'),
    unknown: t('The firewall did not report its state'),
  }[state];
  const hint = {
    loading: '',
    on: t('Connections are refused unless a rule below or an always-open port lets them in.'),
    idle: t('Its rules are saved but not loaded, so nothing is being filtered. Reload the rules to load them.'),
    off: t('Every port on this server can be reached.'),
    unknown: t('What the helper said is under Technical details.'),
  }[state];

  const protectedPorts = firewallStatus?.summary?.protected_ports || [];
  const rules = (firewallStatus?.rules || []).filter((rule) => !rule.protected);
  const blocklist = parseBlocklistStatus(firewallBlocklists?.stdout);

  const rule = firewallRule;
  const blocking = rule.action === 'block';
  const hasPort = rule.port.trim() !== '';
  // Blocking needs an address: the helper will not deny a port to everyone.
  const canAdd = blocking ? rule.ip.trim() !== '' : rule.ip.trim() !== '' || hasPort;
  const change = (field) => (event) => setFirewallRule((prev) => ({ ...prev, [field]: event.target.value }));

  return <div className="fw-page">
    <section className="section fw-status" data-state={state}>
      <div className="fw-status-head">
        <span className="fw-status-icon"><StateIcon size={22} aria-hidden="true"/></span>
        <div className="fw-status-text">
          <h2>{title}</h2>
          {hint && <p className="hint">{hint}</p>}
        </div>
        <div className="fw-status-actions">
          <button type="button" className="secondary icon-button" disabled={busy} onClick={() => { loadFirewall(); loadFirewallBlocklists(); }}
            aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
          <button type="button" className="secondary" disabled={busy} onClick={reloadFirewall}><RotateCw size={15} aria-hidden="true"/> {t('Reload rules')}</button>
          {state === 'off'
            ? <button type="button" disabled={busy} onClick={enableFirewall}><ShieldCheck size={15} aria-hidden="true"/> {t('Turn on')}</button>
            : <button type="button" className="secondary fw-turn-off" disabled={busy || state === 'loading'} onClick={disableFirewall}><ShieldOff size={15} aria-hidden="true"/> {t('Turn off')}</button>}
        </div>
      </div>
      {protectedPorts.length > 0 && <p className="fw-ports">
        <span>{t('Always open')}</span>
        {protectedPorts.map((port) => <code key={port}>{port}</code>)}
      </p>}
    </section>

    <section className="section fw-rules">
      <div className="fw-section-head">
        <h2>{t('Rules')}</h2>
        <p className="hint">{t('Allow or block an address, a port, or a port for one address.')}</p>
      </div>
      <form className="fw-rule-form" onSubmit={(event) => { event.preventDefault(); if (canAdd) addFirewallRule(); }}>
        <label><span>{t('Action')}</span>
          <select value={rule.action} onChange={change('action')}>
            <option value="allow">{t('Allow')}</option>
            <option value="block">{t('Block')}</option>
          </select>
        </label>
        <label><span>{t('From address')}</span>
          <input value={rule.ip} onChange={change('ip')} placeholder={blocking ? '203.0.113.7' : t('Anyone')} spellCheck="false" autoComplete="off" />
        </label>
        <label><span>{t('Port')}</span>
          <input value={rule.port} onChange={change('port')} placeholder={t('All ports')} inputMode="numeric" autoComplete="off" />
        </label>
        <label><span>{t('Protocol')}</span>
          <select value={rule.protocol} onChange={change('protocol')} disabled={!hasPort} title={hasPort ? undefined : t('Only for a rule with a port')}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </label>
        <button type="submit" className={blocking ? 'danger' : undefined} disabled={busy || !canAdd}>
          <Plus size={15} aria-hidden="true"/> {blocking ? t('Add block') : t('Add allow')}
        </button>
      </form>

      {rules.length === 0
        ? <p className="fw-empty">{t('No rules yet. Only the always-open ports accept connections.')}</p>
        : <div className="fw-table-wrap">
          <table className="fw-table">
            <thead><tr>
              <th scope="col">#</th>
              <th scope="col">{t('Action')}</th>
              <th scope="col">{t('From address')}</th>
              <th scope="col">{t('Port')}</th>
              <th scope="col"><span className="sr-only">{t('Delete')}</span></th>
            </tr></thead>
            <tbody>
              {rules.map((item) => <tr key={item.id}>
                <td className="fw-id">{item.id}</td>
                <td><span className={`badge ${item.action === 'DENY' ? 'bad' : 'ok'}`}>{item.action === 'DENY' ? t('Block') : t('Allow')}</span></td>
                <td>{item.from === 'any' ? <span className="fw-any">{t('Anyone')}</span> : <code>{item.from}</code>}</td>
                <td>{item.to === 'any' ? <span className="fw-any">{t('All ports')}</span> : <code>{item.to}</code>}</td>
                <td className="fw-row-actions">
                  <button type="button" className="secondary icon-button fw-delete" disabled={busy} onClick={() => deleteFirewallRule(item.id)}
                    aria-label={t('Delete rule #{number}', { number: item.id })} title={t('Delete rule #{number}', { number: item.id })}><Trash2 size={15} aria-hidden="true"/></button>
                </td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </section>

    <section className="section fw-blocklists">
      <div className="fw-section-head fw-section-head-row">
        <div>
          <h2>{t('IP blocklists')}</h2>
          <p className="hint">{t('Lists of addresses to block, downloaded again every day at 01:00. A list of a million addresses still costs one lookup per packet.')}</p>
        </div>
        <button type="button" className="secondary" disabled={busy || blocklist.urls.length === 0} onClick={updateFirewallBlocklistsNow}>
          <RefreshCw size={15} aria-hidden="true"/> {t('Update now')}
        </button>
      </div>
      <form className="fw-url-form" onSubmit={(event) => { event.preventDefault(); if (firewallBlocklistUrl.trim()) addFirewallBlocklistUrl(); }}>
        <input value={firewallBlocklistUrl} onChange={(event) => setFirewallBlocklistUrl(event.target.value)}
          placeholder="https://example.com/blocklist.txt" aria-label={t('List URL')} spellCheck="false" autoComplete="off" />
        <button type="submit" disabled={busy || !firewallBlocklistUrl.trim()}><Plus size={15} aria-hidden="true"/> {t('Add list')}</button>
      </form>
      {blocklist.urls.length > 0 && <ul className="fw-url-list">
        {blocklist.urls.map((url) => <li key={url}>
          <code title={url}>{url}</code>
          <button type="button" className="secondary icon-button fw-delete" disabled={busy} onClick={() => deleteFirewallBlocklistUrl(url)}
            aria-label={t('Remove list {url}', { url })} title={t('Remove list {url}', { url })}><Trash2 size={15} aria-hidden="true"/></button>
        </li>)}
      </ul>}
      {firewallBlocklists && <p className="fw-blocklist-facts">
        {blocklist.blocked !== null && <span>{t('{count} networks blocked', { count: blocklist.blocked.toLocaleString() })}</span>}
        {blocklist.timer && <span>{blocklist.timer === 'enabled' ? t('Daily update: on') : t('Daily update: {state}', { state: blocklist.timer })}</span>}
      </p>}
    </section>

    <details className="fw-details">
      <summary>{t('Technical details')}</summary>
      <div className="fw-details-body">
        <h3>{t('Firewall status')}</h3>
        <pre>{firewallStatus?.stdout || firewallStatus?.stderr || t('Not loaded yet.')}</pre>
        <h3>{t('IP blocklist status')}</h3>
        <pre>{firewallBlocklists?.stdout || firewallBlocklists?.stderr || t('Not loaded yet.')}</pre>
      </div>
    </details>
  </div>;
}
