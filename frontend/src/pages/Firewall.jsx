import { Plus, RefreshCw, Shield, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function FirewallPage() {
  const {
    addFirewallBlocklistUrl,
    allowFirewallIp,
    blockFirewallIp,
    deleteFirewallBlocklistUrl,
    deleteFirewallRule,
    disableFirewall,
    enableFirewall,
    firewallAllowIp,
    firewallAllowPort,
    firewallAllowProtocol,
    firewallBlockIp,
    firewallBlockPort,
    firewallBlockProtocol,
    firewallBlocklistUrl,
    firewallBlocklists,
    firewallDeleteNumber,
    firewallPort,
    firewallProtocol,
    firewallStatus,
    isAdmin,
    loadFirewall,
    loadFirewallBlocklists,
    loading,
    openFirewallPort,
    parseFirewallBlocklistUrls,
    reloadFirewall,
    setFirewallAllowIp,
    setFirewallAllowPort,
    setFirewallAllowProtocol,
    setFirewallBlockIp,
    setFirewallBlockPort,
    setFirewallBlockProtocol,
    setFirewallBlocklistUrl,
    setFirewallDeleteNumber,
    setFirewallPort,
    setFirewallProtocol,
    updateFirewallBlocklistsNow,
  } = usePanel();

  function renderFirewall() {
    if (!isAdmin) return <section className="section"><h2>Firewall</h2><p className="hint">No permission.</p></section>;
    const firewallText = firewallStatus?.stdout || firewallStatus?.stderr || 'Click Refresh to load status.';
    const blocklistText = firewallBlocklists?.stdout || firewallBlocklists?.stderr || 'No blocklist status loaded.';
    const blocklistUrls = parseFirewallBlocklistUrls(blocklistText);
    const allRules = firewallStatus?.rules || [];
    const userRules = allRules.filter(rule => !rule.protected);
    const panelRules = allRules.filter(rule => rule.protected);
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Firewall (iptables + ipset)</h2><p className="hint">SSH, the panel port and 80/443/465/587 are always kept open.</p></div>
        </div>
        <div className="actions">
          <button disabled={!!loading} onClick={loadFirewall}><RefreshCw size={14}/> Refresh</button>
          <button disabled={!!loading} onClick={enableFirewall}><Shield size={14}/> Enable</button>
          <button disabled={!!loading} onClick={disableFirewall}>Disable</button>
          <button disabled={!!loading} onClick={reloadFirewall}>Reload</button>
        </div>
        {panelRules.length > 0 && <p className="hint">Protected ports: {panelRules.map(rule => rule.to).join(', ')}</p>}
        {userRules.length > 0 && <div className="table firewall-rule-table">
          {userRules.map(rule => <div className="firewall-rule" key={rule.id}>
            <span>
              <strong>#{rule.id}</strong>{' '}
              <span className={rule.action === 'DENY' ? 'badge danger' : 'badge ok'}>{rule.action}</span>{' '}
              {rule.to} from {rule.from}
            </span>
            <div className="firewall-rule-actions">
              <button className="danger" disabled={!!loading} onClick={() => deleteFirewallRule(rule.id)}><Trash2 size={14}/> Delete</button>
            </div>
          </div>)}
        </div>}
        {userRules.length === 0 && <p className="hint">No custom rules yet. Only the protected ports are open.</p>}
        <div className="info-box firewall-status">
          <strong>Firewall status</strong>
          <pre>{firewallText}</pre>
          <div className="firewall-delete-inline">
            <label><span>Delete rule #</span><input value={firewallDeleteNumber} onChange={e => setFirewallDeleteNumber(e.target.value)} placeholder="12" inputMode="numeric" /></label>
            <button className="danger" disabled={!!loading || !firewallDeleteNumber} onClick={() => deleteFirewallRule()}>Delete</button>
          </div>
        </div>
      </section>
      <section className="section">
        <h2>Open port</h2>
        <div className="firewall-form">
          <label><span>Port</span><input value={firewallPort} onChange={e => setFirewallPort(e.target.value)} placeholder="80" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallProtocol} onChange={e => setFirewallProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button disabled={!!loading || !firewallPort} onClick={openFirewallPort}>Open port</button>
        </div>
      </section>
      <section className="section">
        <h2>Allow IP</h2>
        <div className="firewall-form">
          <label><span>IP / CIDR</span><input value={firewallAllowIp} onChange={e => setFirewallAllowIp(e.target.value)} placeholder="1.2.3.4" /></label>
          <label><span>Port (optional)</span><input value={firewallAllowPort} onChange={e => setFirewallAllowPort(e.target.value)} placeholder="22" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallAllowProtocol} onChange={e => setFirewallAllowProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button disabled={!!loading || !firewallAllowIp} onClick={allowFirewallIp}>Allow</button>
        </div>
      </section>
      <section className="section">
        <h2>Block IP</h2>
        <div className="firewall-form">
          <label><span>IP / CIDR</span><input value={firewallBlockIp} onChange={e => setFirewallBlockIp(e.target.value)} placeholder="5.6.7.8" /></label>
          <label><span>Port (optional)</span><input value={firewallBlockPort} onChange={e => setFirewallBlockPort(e.target.value)} placeholder="All ports" inputMode="numeric" /></label>
          <label><span>Protocol</span><select value={firewallBlockProtocol} onChange={e => setFirewallBlockProtocol(e.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <button className="danger" disabled={!!loading || !firewallBlockIp} onClick={blockFirewallIp}>Block</button>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>IP blocklist URLs</h2><p className="hint">TXT files are fetched daily at 01:00 into an ipset, so even million-entry lists cost one kernel lookup per packet.</p></div>
          <button disabled={!!loading} onClick={loadFirewallBlocklists}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="firewall-form firewall-blocklist-form">
          <label><span>TXT URL</span><input value={firewallBlocklistUrl} onChange={e => setFirewallBlocklistUrl(e.target.value)} placeholder="https://example.com/blocklist.txt" /></label>
          <button disabled={!!loading || !firewallBlocklistUrl.trim()} onClick={addFirewallBlocklistUrl}><Plus size={14}/> Add URL</button>
          <button className="secondary-light" disabled={!!loading} onClick={updateFirewallBlocklistsNow}><RefreshCw size={14}/> Update now</button>
        </div>
        {blocklistUrls.length > 0 && <div className="table firewall-blocklist-table">
          {blocklistUrls.map(url => <div className="firewall-rule" key={url}>
            <span>{url}</span>
            <div className="firewall-rule-actions"><button className="danger" disabled={!!loading} onClick={() => deleteFirewallBlocklistUrl(url)}><Trash2 size={14}/> Delete</button></div>
          </div>)}
        </div>}
        <div className="info-box firewall-status"><strong>IP blocklist status</strong><pre>{blocklistText}</pre></div>
      </section>
    </>;
  }

  return renderFirewall();
}
