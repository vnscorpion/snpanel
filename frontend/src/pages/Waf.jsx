import { Globe, Plus, RefreshCw, Settings as SettingsIcon, Shield, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Waf.css';

export default function WafPage() {
  const t = useT();
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
    saveGlobalBots,
    setBulkBotOpen,
    setGlobalBotFilter,
    setGlobalBotPaste,
    setGlobalBots,
    setNewBotName,
    toggleWebsiteWaf,
    wafRules,
    websites,
  } = usePanel();

  // The helper reports the engine as JSON; shown as facts, not as JSON.
  const wafStatus = (() => {
    try {
      const value = JSON.parse(wafRules.status?.stdout || '');
      return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
    } catch { return null; }
  })();
  // Unknown until the status has been read: nothing is said about it then.
  const engine = wafStatus ? !!wafStatus.installed : null;
  // The effective list, not the site's own: a site with nothing of its own
  // still enforces the global list, and reporting "No bots" for it was a lie.
  const rowFor = id => botBlocks?.websites?.find(w => w.website_id === id);
  const botCountFor = id => (rowFor(id)?.effective_blocked_bots || []).length;
  const ownCountFor = id => (rowFor(id)?.blocked_bots || []).length;
  const protectedCount = websites.filter(site => site.waf_enabled).length;
  // A site switched on before the switch carried the OWASP rule set has its
  // own rules running and not the rule set: said once, with the way to fix it.
  const withoutRuleSet = id => {
    const row = (crs?.websites || []).find(w => w.website_id === id);
    return engine && row && !row.crs_enabled;
  };

  return <>
    <section className="section">
      <div className="section-title">
        <div>
          <h2>WAF</h2>
          <p className="hint">{t('One switch per website: the panel\'s rules and the OWASP rule set, blocking attacks before they reach the site.')}</p>
        </div>
        <button className="secondary-light" disabled={!!loading} onClick={() => { loadBotBlocks(); if (isAdmin) { loadWafRules(); loadCrs(); } }}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      {isAdmin && <div className="waf-status-line">
        {engine === null
          ? <span className="hint">{t('Reading the WAF status…')}</span>
          : <span className={engine ? 'badge ok' : 'badge bad'}>{engine ? t('Engine installed') : t('Engine not available')}</span>}
        <span className="badge">{t('{count} of {total} website(s) protected', { count: protectedCount, total: websites.length })}</span>
      </div>}
      {engine === false && <p className="hint waf-no-engine">{t('This server\'s nginx has no ModSecurity module, so the WAF cannot run here. Flood limits and bot blocking still work.')}</p>}
    </section>

    <section className="section">
      <div className="section-title"><h2>{t('Websites')}</h2></div>
      {websites.length === 0 && <EmptyState icon={Globe} message={t('No websites yet.')} />}
      <div className="waf-sites">
        {websites.map(site => {
          const bots = botCountFor(site.id);
          return <div className="waf-site-row" key={site.id}>
            <label className="waf-switch" title={site.waf_enabled ? t('Turn the WAF off for {domain}', { domain: site.domain }) : t('Turn the WAF on for {domain}', { domain: site.domain })}>
              <input type="checkbox" role="switch" checked={!!site.waf_enabled} disabled={!!loading || engine === false}
                onChange={() => toggleWebsiteWaf(site)} aria-label={t('WAF for {domain}', { domain: site.domain })} />
              <span className="waf-switch-track" aria-hidden="true"><span className="waf-switch-thumb"/></span>
            </label>
            <div className="waf-site-name">
              <strong>{site.domain}</strong>
              <small>{site.waf_enabled ? t('Protected') : t('Not protected')}
                {site.waf_enabled && withoutRuleSet(site.id) && <span className="waf-legacy" title={t('Turn the WAF off and on again to load the OWASP rule set on this website.')}> · {t('rule set not loaded')}</span>}
              </small>
            </div>
            <div className="waf-site-badges">
              <span className={site.http_flood_enabled ? 'badge ok' : 'badge'}>{site.http_flood_enabled ? t('Flood on') : t('Flood off')}</span>
              <span
                className={bots > 0 ? 'badge ok' : 'badge'}
                title={ownCountFor(site.id) > 0 ? t('{value} set on this site, the rest from the global list', { value: ownCountFor(site.id) }) : t('All from the global list')}
              >{bots > 0 ? t('{bots} bot(s)', { bots }) : t('No bots')}</span>
            </div>
            <button className="secondary-light" disabled={!!loading} onClick={() => openWafSite(site.id)}
              aria-label={t('Configure {domain}', { domain: site.domain })}><SettingsIcon size={14} aria-hidden="true"/> <span className="waf-configure-label">{t('Configure')}</span></button>
          </div>;
        })}
      </div>
    </section>

    {isAdmin && <section className="section">
      <div className="section-title">
        <div>
          <h2>{t('Global bad bots')}</h2>
          <p className="hint">
            {globalBots.length > 0
              ? t('Blocked on every website on this server. A site can add more of its own from its page. Currently {count} bot(s).', { count: globalBots.length })
              : t('Blocked on every website on this server. A site can add more of its own from its page. Nothing blocked globally yet.')}
          </p>
        </div>
        <button className="secondary-light" disabled={!!loading} onClick={() => setBulkBotOpen(open => !open)}>{bulkBotOpen ? t('Hide') : t('Edit')}</button>
      </div>

      {bulkBotOpen && <div className="global-bots">
        <div className="global-bots-add">
          <input
            value={newBotName}
            placeholder={t('Add one bot, e.g. Amazonbot')}
            onChange={e => setNewBotName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') { addGlobalBots(newBotName); setNewBotName(''); } }}
          />
          <button type="button" disabled={!newBotName.trim()} onClick={() => { addGlobalBots(newBotName); setNewBotName(''); }}>
            <Plus size={14}/> {t('Add')}
          </button>
          <input
            className="global-bots-filter"
            value={globalBotFilter}
            placeholder={t('Filter the list')}
            onChange={e => setGlobalBotFilter(e.target.value)}
          />
        </div>

        <div className="global-bots-list">
          {globalBots.length === 0 && <p className="hint">{t('No bots yet. Add one above, or paste a list below.')}</p>}
          {globalBots
            .filter(name => !globalBotFilter.trim() || name.toLowerCase().includes(globalBotFilter.trim().toLowerCase()))
            .map(name => <span className="global-bot-chip" key={name}>
              <code>{name}</code>
              <button
                type="button"
                title={t('Remove {name}', { name })}
                onClick={() => setGlobalBots(prev => prev.filter(n => n !== name))}
              ><X size={12}/></button>
            </span>)}
        </div>

        <details className="global-bots-paste">
          <summary>{t('Paste a list')}</summary>
          <textarea
            className="code-editor"
            rows={6}
            spellCheck={false}
            value={globalBotPaste}
            onChange={e => setGlobalBotPaste(e.target.value)}
            placeholder={'AhrefsBot\nSemrushBot\nMJ12bot'}
          />
          <button type="button" disabled={!globalBotPaste.trim()} onClick={() => { addGlobalBots(globalBotPaste); setGlobalBotPaste(''); }}>
            <Plus size={14}/> {t('Add to list')}
          </button>
        </details>

        <div className="global-bots-actions">
          <button disabled={!!loading} onClick={() => saveGlobalBots(globalBots)}>
            <Shield size={14}/> {t('Save and apply to all {count} website(s)', { count: websites.length })}
          </button>
          <button
            className="secondary-light"
            disabled={!!loading}
            onClick={() => setGlobalBots(botBlocks?.global_blocked_bots || [])}
          >{t('Reset')}</button>
          <span className="hint">
            {t('{count} bot(s)', { count: globalBots.length })}
            {botBlocks?.max_bots ? ` · ${t('at most {max}', { max: botBlocks.max_bots })}` : ''}
            {JSON.stringify(globalBots) !== JSON.stringify(botBlocks?.global_blocked_bots || []) ? ` · ${t('unsaved changes')}` : ''}
          </span>
        </div>
      </div>}
    </section>}
  </>;
}
