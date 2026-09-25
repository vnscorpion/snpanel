import { ArrowLeft, Globe, Shield } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { serverText, useT } from '../i18n/index.jsx';

export default function WafSitePage() {
  const t = useT();
  const {
    EmptyState,
    botBlocks,
    crs,
    httpFloodForm,
    loadWebsiteWafConfig,
    loading,
    navigateToPage,
    saveSiteBots,
    saveWebsiteHttpFlood,
    saveWebsiteWafRules,
    selectedWafWebsiteId,
    setHttpFloodForm,
    setSiteBotText,
    setWafCustomRules,
    siteBotText,
    toggleSiteCrs,
    toggleWafDefaultRule,
    toggleWebsiteWaf,
    wafCustomRules,
    wafRules,
    wafSiteConfig,
    websites,
  } = usePanel();

  function renderWafSite() {
    const selectedSite = websites.find(site => String(site.id) === String(selectedWafWebsiteId));
    const groupedRules = (wafSiteConfig?.default_rules || wafRules.default_rule_definitions || []).reduce((groups, rule) => {
      const category = rule.category || 'General';
      groups[category] = groups[category] || [];
      groups[category].push(rule);
      return groups;
    }, {});
    const siteBotNames = siteBotText.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    const siteBotUnique = new Set(siteBotNames.map(s => s.toLowerCase()));
    return <>
      <section className="section">
        <div className="section-title waf-site-header">
          <div>
            <h2>{wafSiteConfig?.domain || selectedSite?.domain || t('Website')}</h2>
            <p className="hint">{t('WAF rules, flood limits and blocked bots for this website.')}</p>
          </div>
          <div className="waf-site-header-actions">
            <select value={selectedWafWebsiteId} onChange={e => loadWebsiteWafConfig(e.target.value)}>
              {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
            <button className="secondary-light" onClick={() => navigateToPage('waf')}><ArrowLeft size={14}/> {t('All websites')}</button>
          </div>
        </div>
        <div className="waf-site-toggles">
          <span className={selectedSite?.waf_enabled ? 'badge ok' : 'badge'}>{selectedSite?.waf_enabled ? t('WAF enabled') : t('WAF disabled')}</span>
          <button disabled={!selectedWafWebsiteId || !!loading} onClick={() => selectedSite && toggleWebsiteWaf(selectedSite)}>
            <Shield size={14}/> {selectedSite?.waf_enabled ? t('Disable WAF') : t('Enable WAF')}
          </button>
          <span className={wafSiteConfig?.crs_active ? 'badge ok' : 'badge'}>
            {wafSiteConfig?.crs_enabled
              ? (wafSiteConfig?.crs_mode === 'off' ? t('CRS on (server-wide: off)') : t('CRS {crs_mode}', { crs_mode: wafSiteConfig.crs_mode }))
              : t('CRS off')}
          </span>
          <button
            disabled={!selectedWafWebsiteId || !!loading || !selectedSite?.waf_enabled}
            title={selectedSite?.waf_enabled ? '' : t('Enable the WAF first')}
            onClick={() => wafSiteConfig && toggleSiteCrs({
              website_id: wafSiteConfig.website_id,
              domain: wafSiteConfig.domain,
              crs_enabled: wafSiteConfig.crs_enabled,
            })}
          >
            <Shield size={14}/> {wafSiteConfig?.crs_enabled ? t('Disable CRS') : t('Enable CRS')}
          </button>
        </div>
        <p className="hint">
          {t('The WAF blocks known bad paths. OWASP CRS adds payload inspection — SQL injection, XSS, command injection — for this site, at roughly {mb} MB of nginx memory.', { mb: crs?.rss_mb_per_site || 50 })}
          {wafSiteConfig?.crs_enabled && wafSiteConfig?.crs_mode === 'off'
            ? t(' This site is opted in, but CRS is switched off server-wide on the WAF page, so nothing is loaded.')
            : ''}
          {wafSiteConfig?.crs_active
            ? t(' Add SecRuleRemoveById <id> to the custom rules below to excuse this site from one CRS rule.')
            : ''}
        </p>
      </section>

      {!wafSiteConfig && websites.length === 0 && <section className="section"><EmptyState icon={Globe} message={t('No websites yet.')} /></section>}

      {wafSiteConfig && <section className="section bot-block-panel">
        <div className="section-title">
          <div>
            <h2>{t('Blocked bots')}</h2>
            <p className="hint">{t('One name per line, matched anywhere in User-Agent. Matched literally, so {literal} will not also match {other}. Blocked requests get 403 before WAF and rate limiting run.', { literal: <code>bingbot/2.0</code>, other: <code>bingbotX2Y0</code> })}</p>
          </div>
        </div>
        <textarea
          className="code-editor"
          value={siteBotText}
          onChange={e => setSiteBotText(e.target.value)}
          rows={10}
          spellCheck={false}
          placeholder={'AhrefsBot\nSemrushBot\nMJ12bot'}
        />
        <p className="hint">
          {t('{size} bot(s)', { size: siteBotUnique.size })}
          {siteBotNames.length !== siteBotUnique.size ? t(' ({value} duplicate(s) will be dropped)', { value: siteBotNames.length - siteBotUnique.size }) : ''}
          {botBlocks?.max_bots ? t(' - max {max_bots}', { max_bots: botBlocks.max_bots }) : ''}
        </p>
        <div className="actions">
          <button disabled={!!loading} onClick={saveSiteBots}><Shield size={14}/> {t('Save blocked bots')}</button>
          <button className="secondary-light" disabled={!!loading || siteBotNames.length === 0} onClick={() => setSiteBotText('')}>{t('Clear list')}</button>
        </div>
      </section>}

      {wafSiteConfig && <section className="section http-flood-panel">
        <div className="section-title">
          <h2>{t('HTTP Flood')}</h2>
          <span className={httpFloodForm.http_flood_enabled ? 'badge ok' : 'badge'}>{httpFloodForm.http_flood_enabled ? t('Enabled') : t('Disabled')}</span>
        </div>
        <label className="schedule-toggle http-flood-toggle">
          <input type="checkbox" checked={!!httpFloodForm.http_flood_enabled} onChange={e => setHttpFloodForm(prev => ({ ...prev, http_flood_enabled: e.target.checked }))} />
          {t('Enabled')}
        </label>
        <div className="http-flood-grid">
          <label><span>{t('Requests')}</span><input type="number" min="1" max="100000" value={httpFloodForm.access_limit_requests} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_requests: e.target.value }))} /></label>
          <label><span>{t('Window (sec)')}</span><input type="number" min="1" max="3600" value={httpFloodForm.access_limit_window} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_window: e.target.value }))} /></label>
          <label><span>{t('Burst')}</span><input type="number" min="0" max="100000" value={httpFloodForm.access_limit_burst} onChange={e => setHttpFloodForm(prev => ({ ...prev, access_limit_burst: e.target.value }))} /></label>
          <label><span>{t('Connections/IP')}</span><input type="number" min="1" max="10000" value={httpFloodForm.connection_limit} onChange={e => setHttpFloodForm(prev => ({ ...prev, connection_limit: e.target.value }))} /></label>
          <button disabled={!!loading} onClick={saveWebsiteHttpFlood}><Shield size={14}/> {t('Save HTTP Flood')}</button>
        </div>
      </section>}

      {wafSiteConfig && <section className="section waf-rules-grid">
        <div className="waf-rule-panel">
          <div className="section-title"><h2>{t('Default rules')}</h2></div>
          <div className="waf-default-groups">
            {Object.entries(groupedRules).map(([category, rules]) => <div className="waf-rule-group" key={category}>
              <h3>{category}</h3>
              {rules.map(rule => <label className="waf-rule-toggle" key={rule.id}>
                <input type="checkbox" checked={!!rule.enabled} onChange={e => toggleWafDefaultRule(rule.id, e.target.checked)} />
                <span><strong>{serverText(rule.title)}</strong><small>{serverText(rule.description)}</small></span>
              </label>)}
            </div>)}
          </div>
        </div>
        <div className="waf-rule-panel">
          <div className="section-title"><h2>{t('Custom rules')}</h2></div>
          <textarea
            className="code-editor"
            value={wafCustomRules}
            onChange={e => setWafCustomRules(e.target.value)}
            rows={14}
            spellCheck={false}
            placeholder="SecRule ..."
            readOnly={wafSiteConfig.may_edit_custom_rules === false}
          />
          <p className="hint">
            {wafSiteConfig.may_edit_custom_rules === false
              ? t('Custom rules are arbitrary ModSecurity directives, so only an administrator can change them. Ask your provider if you need a rule added or excluded.')
              : t('Saved into {rules_file}', { rules_file: wafSiteConfig.rules_file })}
          </p>
          <div className="actions"><button disabled={!!loading} onClick={saveWebsiteWafRules}>{t('Save website WAF rules')}</button></div>
        </div>
      </section>}
    </>;
  }

  return renderWafSite();
}
