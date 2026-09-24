import { Globe, Plus, RefreshCw, Settings as SettingsIcon, Shield, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function WafPage() {
  const {
    EmptyState,
    addGlobalBots,
    botBlocks,
    bulkBotOpen,
    crs,
    globalBotFilter,
    globalBotPaste,
    globalBots,
    isAdmin,
    loadBotBlocks,
    loadCrs,
    loadWafRules,
    loading,
    newBotName,
    openWafSite,
    saveCrsMode,
    saveGlobalBots,
    setBulkBotOpen,
    setGlobalBotFilter,
    setGlobalBotPaste,
    setGlobalBots,
    setNewBotName,
    wafRules,
    websites,
  } = usePanel();

  function renderWaf() {
    const statusText = wafRules.status?.stdout || wafRules.status?.stderr || 'Click Refresh to load WAF status.';
    // The effective list, not the site's own: a site with nothing of its own
    // still enforces the global list, and reporting "No bots" for it was a lie.
    const rowFor = id => botBlocks?.websites?.find(w => w.website_id === id);
    const botCountFor = id => (rowFor(id)?.effective_blocked_bots || []).length;
    const ownCountFor = id => (rowFor(id)?.blocked_bots || []).length;
    return <>
      <section className="section">
        <div className="section-title">
          <div>
            <h2>WAF</h2>
            <p className="hint">{isAdmin
              ? 'Engine status and per-website protection. Open a website to configure its rules, flood limits and blocked bots.'
              : 'Protection for your websites. Open one to configure its rules and blocked bots.'}</p>
          </div>
          <button disabled={!!loading} onClick={() => { loadBotBlocks(); if (isAdmin) { loadWafRules(); loadCrs(); } }}><RefreshCw size={14}/> Refresh</button>
        </div>
        {isAdmin && <div className="info-box firewall-status"><strong>Status</strong><pre>{statusText}</pre></div>}
      </section>

      {isAdmin && <section className="section">
        <div className="section-title">
          <div>
            <h2>OWASP Core Rule Set</h2>
            <p className="hint">
              SNPanel's own rules block known bad paths. CRS inspects the payload - SQL injection, XSS,
              command injection - and scores each request instead of refusing on a single match.
              Off by default because CRS needs tuning against real traffic before it can be trusted to block.
            </p>
          </div>
          <button disabled={!!loading} onClick={loadCrs}><RefreshCw size={14}/> Check</button>
        </div>
        {!crs && <p className="hint">Click Check to read the current state.</p>}
        {crs && <>
          <div className="waf-overview-badges" style={{ marginBottom: 12 }}>
            <span className={crs.mode === 'block' ? 'badge ok' : 'badge'}>
              {crs.mode === 'off' ? 'Off' : (crs.mode === 'detect' ? 'Detect only' : 'Blocking')}
            </span>
            <span className={crs.installed ? 'badge ok' : 'badge'}>
              {crs.installed ? `${crs.rule_files} rule file(s) installed` : 'Not installed'}
            </span>
            <span className="badge">{crs.sites_opted_in ?? 0} site(s) opted in</span>
            <span className="badge">nginx now: {crs.nginx_pss_mb || 0} MB</span>
            <span className={(crs.ram_available_mb || 0) < 1024 ? 'badge danger' : 'badge'}>
              {crs.ram_available_mb || 0} MB RAM free
            </span>
          </div>
          <div className="info-box" style={{ marginBottom: 12 }}>
            <strong>Memory</strong>
            <p className="hint">
              Each site that loads CRS adds its own copy of the rule set, so the cost grows with the
              number opted in — roughly {crs.rss_mb_per_site || 50} MB each. "nginx now" above is measured on this
              server, not estimated, and it is the figure to act on; watch it and the free-RAM figure
              beside it as you opt sites in. Note that `ps` reports several times this, because it
              counts pages the nginx workers share once for each worker.
            </p>
          </div>
          <div className="segmented-control">
            {[['off', 'Off'], ['detect', 'Detect only'], ['block', 'Block']].map(([value, label]) => (
              <button
                key={value}
                className={crs.mode === value ? 'active' : ''}
                disabled={!!loading || crs.mode === value}
                onClick={() => saveCrsMode(value)}
              >{label}</button>
            ))}
          </div>
          <p className="hint" style={{ marginTop: 10 }}>
            {crs.mode === 'off' && 'Nothing from CRS is loaded. Payload attacks are not inspected.'}
            {crs.mode === 'detect' && 'Every CRS rule runs and nothing is refused. Each request that Block mode would have stopped is recorded in /var/log/nginx/snpanel-modsec-audit.log, with the rule IDs that scored it. Read that for a while, add exceptions per site, then switch to Block.'}
            {crs.mode === 'block' && 'Requests scoring above the threshold are refused on every site with the WAF on. Add SecRuleRemoveById <id> to a site’s custom rules to excuse it from one rule.'}
          </p>
          {crs.mode !== 'off' && crs.panel_mode !== crs.mode && (
            <p className="hint">Panel setting says "{crs.panel_mode}" but the server reports "{crs.mode}".</p>
          )}
          <p className="hint">
            This is the server-wide switch. Which sites load CRS is chosen per website below.
          </p>
        </>}
      </section>}

      <section className="section">
        <div className="section-title"><h2>Websites</h2></div>
        {websites.length === 0 && <EmptyState icon={Globe} message="No websites yet." />}
        <div className="table waf-overview-list">
          {websites.map(site => {
            const bots = botCountFor(site.id);
            const crsRow = (crs?.websites || []).find(w => w.website_id === site.id);
            const crsOn = !!crsRow?.crs_enabled;
            const crsLive = crsOn && site.waf_enabled && crs?.mode && crs.mode !== 'off';
            return <div className="waf-overview-row" key={site.id}>
              <span className="waf-overview-domain"><strong>{site.domain}</strong></span>
              <div className="waf-overview-badges">
                <span className={site.waf_enabled ? 'badge ok' : 'badge'}>{site.waf_enabled ? 'WAF on' : 'WAF off'}</span>
                <span
                  className={crsLive ? 'badge ok' : 'badge'}
                  title={crsOn && !crsLive ? 'Opted in, but CRS is off server-wide' : ''}
                >{crsOn ? (crsLive ? `CRS ${crs.mode}` : 'CRS pending') : 'CRS off'}</span>
                <span className={site.http_flood_enabled ? 'badge ok' : 'badge'}>{site.http_flood_enabled ? 'Flood on' : 'Flood off'}</span>
                <span
                  className={bots > 0 ? 'badge ok' : 'badge'}
                  title={ownCountFor(site.id) > 0 ? `${ownCountFor(site.id)} set on this site, the rest from the global list` : 'All from the global list'}
                >{bots > 0 ? `${bots} bot(s)` : 'No bots'}</span>
              </div>
              <button disabled={!!loading} onClick={() => openWafSite(site.id)}><SettingsIcon size={14}/> Configure</button>
            </div>;
          })}
        </div>
      </section>

      {isAdmin && <section className="section">
        <div className="section-title">
          <div>
            <h2>Global bad bots</h2>
            <p className="hint">
              Blocked on every website on this server. A site can add more of its own from its page.
              {globalBots.length > 0 ? ` Currently ${globalBots.length} bot(s).` : ' Nothing blocked globally yet.'}
            </p>
          </div>
          <button disabled={!!loading} onClick={() => setBulkBotOpen(open => !open)}>{bulkBotOpen ? 'Hide' : 'Edit'}</button>
        </div>

        {bulkBotOpen && <div className="global-bots">
          <div className="global-bots-add">
            <input
              value={newBotName}
              placeholder="Add one bot, e.g. Amazonbot"
              onChange={e => setNewBotName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { addGlobalBots(newBotName); setNewBotName(''); } }}
            />
            <button type="button" disabled={!newBotName.trim()} onClick={() => { addGlobalBots(newBotName); setNewBotName(''); }}>
              <Plus size={14}/> Add
            </button>
            <input
              className="global-bots-filter"
              value={globalBotFilter}
              placeholder="Filter the list"
              onChange={e => setGlobalBotFilter(e.target.value)}
            />
          </div>

          <div className="global-bots-list">
            {globalBots.length === 0 && <p className="hint">No bots yet. Add one above, or paste a list below.</p>}
            {globalBots
              .filter(name => !globalBotFilter.trim() || name.toLowerCase().includes(globalBotFilter.trim().toLowerCase()))
              .map(name => <span className="global-bot-chip" key={name}>
                <code>{name}</code>
                <button
                  type="button"
                  title={`Remove ${name}`}
                  onClick={() => setGlobalBots(prev => prev.filter(n => n !== name))}
                ><X size={12}/></button>
              </span>)}
          </div>

          <details className="global-bots-paste">
            <summary>Paste a list</summary>
            <textarea
              className="code-editor"
              rows={6}
              spellCheck={false}
              value={globalBotPaste}
              onChange={e => setGlobalBotPaste(e.target.value)}
              placeholder={'AhrefsBot\nSemrushBot\nMJ12bot'}
            />
            <button type="button" disabled={!globalBotPaste.trim()} onClick={() => { addGlobalBots(globalBotPaste); setGlobalBotPaste(''); }}>
              <Plus size={14}/> Add to list
            </button>
          </details>

          <div className="global-bots-actions">
            <button disabled={!!loading} onClick={() => saveGlobalBots(globalBots)}>
              <Shield size={14}/> Save and apply to all {websites.length} website(s)
            </button>
            <button
              className="secondary-light"
              disabled={!!loading}
              onClick={() => setGlobalBots(botBlocks?.global_blocked_bots || [])}
            >Reset</button>
            <span className="hint">
              {globalBots.length} bot(s)
              {botBlocks?.max_bots ? ` - max ${botBlocks.max_bots}` : ''}
              {JSON.stringify(globalBots) !== JSON.stringify(botBlocks?.global_blocked_bots || []) ? ' - unsaved changes' : ''}
            </span>
          </div>
        </div>}
      </section>}
    </>;
  }

  return renderWaf();
}
