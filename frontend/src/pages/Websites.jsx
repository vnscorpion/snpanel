import { Copy, Dices, FileText, FolderOpen, Globe, KeyRound, Lock, Plus, RefreshCw, RotateCcw, Save, Search, Settings as SettingsIcon, TerminalIcon, Trash2, X } from 'lucide-react';
import { lazy, Suspense } from 'react';
// xterm.js is most of this page's weight and only the terminal panel uses
// it, so it is fetched when that panel is opened rather than with the page.
const Terminal = lazy(() => import('../components/Terminal').then((m) => ({ default: m.Terminal })));
import { API, NGINX_REWRITE_MODES, SITE_APP_KIND_LABELS, WEBSITE_MODES, WordPressIcon, isProxiedAppType } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function WebsitesPage() {
  const t = useT();
  const {
    EmptyState,
    addWebsiteAlias,
    adminEmail,
    aliasDrafts,
    aliasModes,
    appsFeatureEnabled,
    createSiteAppId,
    createSslMode,
    createSslToken,
    createWordPress,
    deleteWebsite,
    deleteWebsiteAlias,
    domain,
    generateRandomPassword,
    installWordPress,
    installWordPressOnSite,
    isAdmin,
    loadWebsiteList,
    loadWebsiteLog,
    loading,
    logViewer,
    navigateToPage,
    nginxCustomEditing,
    openNginxCustom,
    openWebsiteFileManager,
    openWebsiteLogs,
    openWebsiteTerminal,
    openWordPressInstaller,
    phpVersion,
    phpVersions,
    resetNginxDefault,
    saveNginxCustom,
    saveWebsiteSettings,
    setAdminEmail,
    setAliasDrafts,
    setAliasModes,
    setCreateSiteAppId,
    setCreateSslMode,
    setCreateSslToken,
    setDomain,
    setInstallWordPress,
    setLogViewer,
    setNginxCustomEditing,
    setPhpVersion,
    setSiteType,
    setTerminalViewer,
    setWebsiteSearch,
    setWebsiteSettingsForm,
    setWordpressInstaller,
    setWpAdminPassword,
    setWpAdminUser,
    siteApps,
    siteType,
    terminalViewer,
    updateWordPressAll,
    viewFullNginxConfig,
    websiteList,
    websiteSearch,
    websiteSearching,
    websiteSettingsForm,
    websiteUrl,
    websites,
    wordpressInstaller,
    wpAdminPassword,
    wpAdminUser,
  } = usePanel();

  function renderNginxEditor() {
    if (!nginxCustomEditing) return null;
    const fullConfig = nginxCustomEditing.mode === 'full';
    const selectedAppType = websiteSettingsForm.app_type || nginxCustomEditing.site?.app_type || 'wordpress';
    const rewriteDisabled = selectedAppType !== 'php';
    const proxied = isProxiedAppType(selectedAppType);
    const settingsSite = nginxCustomEditing.site || {};
    const siteDomains = settingsSite.aliases || [];
    const aliasMode = aliasModes[nginxCustomEditing.id] || 'alias';
    return <section className="section nginx-modal inline-nginx-editor">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>{fullConfig ? t('Full Nginx config') : t('Website settings')} - {nginxCustomEditing.domain}</h2>
          <p className="hint">{fullConfig
            ? t('This is read-only. SNPanel manages the main vhost template.')
            : t('Managed settings rewrite the main vhost safely. Custom Nginx is still stored as a separate include.')}</p>
        </div>
        <div className="actions">
          {!fullConfig && isAdmin && <button className="secondary-light" disabled={!!loading} onClick={viewFullNginxConfig}><FileText size={14}/> {t('View all')}</button>}
          {fullConfig && <button className="secondary-light" disabled={!!loading} onClick={() => setNginxCustomEditing(prev => ({ ...prev, mode: 'custom', content: prev?.customContent ?? prev?.content ?? '' }))}><SettingsIcon size={14}/> {t('Settings')}</button>}
          <button className="secondary-light" onClick={() => setNginxCustomEditing(null)}><X size={14}/> {t('Close')}</button>
        </div>
      </div>
      {!fullConfig && <div className="website-settings-grid">
        <label><span>{t('Website mode')}</span><select
          value={websiteSettingsForm.app_type}
          onChange={e => setWebsiteSettingsForm(prev => ({
            ...prev,
            app_type: e.target.value,
            nginx_rewrite_mode: e.target.value === 'php' ? prev.nginx_rewrite_mode || 'none' : e.target.value === 'wordpress' ? 'front_controller' : 'none',
          }))}
          disabled={!!loading}
        >
          {WEBSITE_MODES.map(([value, label]) => <option
            key={value}
            value={value}
            disabled={value === 'application' && !appsFeatureEnabled}
          >{t(label)}</option>)}
        </select></label>
        {proxied && <label><span>{t('Application')}</span><select
          value={websiteSettingsForm.app_id || ''}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, app_id: e.target.value }))}
          disabled={!!loading}
        >
          <option value="">{t('Select an application')}</option>
          {siteApps.items.map(app => <option key={app.id} value={app.id}>{app.name} · {t(SITE_APP_KIND_LABELS[app.kind] || app.kind)} · :{app.port}</option>)}
        </select></label>}
        {selectedAppType !== 'static' && !proxied && <label><span>{t('PHP version')}</span><select
          value={websiteSettingsForm.php_version}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, php_version: e.target.value }))}
          disabled={!!loading}
        >
          {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
        </select></label>}
        <label><span>{t('Nginx rewrite')}</span><select
          value={rewriteDisabled ? (selectedAppType === 'wordpress' ? 'front_controller' : 'none') : websiteSettingsForm.nginx_rewrite_mode}
          onChange={e => setWebsiteSettingsForm(prev => ({ ...prev, nginx_rewrite_mode: e.target.value }))}
          disabled={!!loading || rewriteDisabled}
        >
          {NGINX_REWRITE_MODES.map(mode => <option key={mode.value} value={mode.value}>{t(mode.label)}</option>)}
        </select></label>
        <div className="website-settings-actions">
          <button disabled={!!loading} onClick={saveWebsiteSettings}><Save size={14}/> {t('Save settings')}</button>
        </div>
      </div>}
      {!fullConfig && <div className="site-aliases settings-domain-manager">
        <div className="domain-manager-head">
          <h3>{t('Domains')}</h3>
          <p className="hint">{t('Alias serves the same app. Redirect sends visitors to {domain}.', { domain: nginxCustomEditing.domain })}</p>
        </div>
        <div className="alias-list">
          <span className="alias-chip primary-domain"><Globe size={12}/>{nginxCustomEditing.domain}<span>{t('Main')}</span></span>
          {siteDomains.length === 0
            ? <span className="alias-empty">{t('No extra domains')}</span>
            : siteDomains.map(alias => <span className="alias-chip" key={alias.id}>
              <Globe size={12}/>{alias.domain}<span>{alias.mode === 'redirect' ? t('Redirect') : t('Alias')}</span>
              <button type="button" disabled={!!loading} title={t('Remove {domain}', { domain: alias.domain })} aria-label={t('Remove {domain}', { domain: alias.domain })} onClick={() => deleteWebsiteAlias(settingsSite, alias)}><X size={12}/></button>
            </span>)}
        </div>
        <div className="alias-form settings-domain-form">
          <input
            value={aliasDrafts[nginxCustomEditing.id] || ''}
            onChange={e => setAliasDrafts(prev => ({ ...prev, [nginxCustomEditing.id]: e.target.value }))}
            onKeyDown={e => { if (e.key === 'Enter') addWebsiteAlias(settingsSite); }}
            placeholder="domain-alias.com"
            disabled={!!loading}
          />
          <select
            value={aliasMode}
            onChange={e => setAliasModes(prev => ({ ...prev, [nginxCustomEditing.id]: e.target.value }))}
            disabled={!!loading}
          >
            <option value="alias">{t('Alias')}</option>
            <option value="redirect">{t('Redirect')}</option>
          </select>
          <button className="secondary-light" disabled={!!loading || !(aliasDrafts[nginxCustomEditing.id] || '').trim()} onClick={() => addWebsiteAlias(settingsSite)}><Plus size={14}/> {t('Add domain')}</button>
        </div>
      </div>}
      <div className="custom-nginx-block">
        {!fullConfig && <h3>{t('Custom Nginx')}</h3>}
        <textarea
          className="code-editor"
          value={nginxCustomEditing.content}
          onChange={e => setNginxCustomEditing(prev => ({ ...prev, content: e.target.value, customContent: e.target.value }))}
          placeholder={fullConfig
            ? `server {\n    listen 80;\n    server_name ${nginxCustomEditing.domain};\n}`
            : `# Optional extra directives only. Use Nginx rewrite above for location / routing.`}
          spellCheck={false}
          rows={fullConfig ? 18 : 10}
          readOnly={fullConfig}
        />
      </div>
      <div className="actions">
        {!fullConfig && <button disabled={!!loading} onClick={saveNginxCustom}>{t('Save and reload Nginx')}</button>}
        {!fullConfig && <button className="secondary-light" disabled={!!loading} onClick={resetNginxDefault}><RotateCcw size={14}/> {t('Reset custom')}</button>}
        <button className="secondary-light" disabled={!!loading} onClick={() => setNginxCustomEditing(null)}>{fullConfig ? t('Close') : t('Cancel')}</button>
      </div>
    </section>;
  }

  function renderWordPressInstaller() {
    if (!wordpressInstaller) return null;
    return <section className="section nginx-modal inline-nginx-editor wordpress-install-modal">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>{t('Install WordPress - {domain}', { domain: wordpressInstaller.domain })}</h2>
          <p className="hint">PHP {wordpressInstaller.php_version || '8.4'}</p>
        </div>
        <button className="secondary-light" onClick={() => setWordpressInstaller(null)}><X size={14}/> {t('Close')}</button>
      </div>
      <div className="website-settings-grid">
        <label><span>{t('Site title')}</span><input
          value={wordpressInstaller.title}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, title: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>{t('Admin user')}</span><input
          value={wordpressInstaller.admin_user}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_user: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>{t('Admin email')}</span><input
          value={wordpressInstaller.admin_email}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_email: e.target.value }))}
          disabled={!!loading}
        /></label>
        <label><span>{t('Admin password')}</span><input
          value={wordpressInstaller.admin_password}
          onChange={e => setWordpressInstaller(prev => ({ ...prev, admin_password: e.target.value }))}
          disabled={!!loading}
        /></label>
        <div className="website-settings-actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => setWordpressInstaller(prev => prev ? ({ ...prev, admin_password: generateRandomPassword(20) }) : prev)}><Dices size={14}/> {t('Generate')}</button>
          <button disabled={!!loading || !wordpressInstaller.admin_user || !wordpressInstaller.admin_email || !wordpressInstaller.admin_password} onClick={installWordPressOnSite}><WordPressIcon size={14}/> {t('Install')}</button>
        </div>
      </div>
    </section>;
  }

  function renderWebsiteTerminal() {
    if (!terminalViewer) return null;
    return <section className="section nginx-modal terminal-modal">
      <div className="section-title">
        <h2>{t('Terminal - {domain}', { domain: terminalViewer.domain })}</h2>
        <button className="secondary-light" onClick={() => setTerminalViewer(null)}><X size={14}/> {t('Close')}</button>
      </div>
      <div style={{ height: '500px', marginTop: '8px' }}>
        <Suspense fallback={<div className="loading">{t('Loading terminal…')}</div>}>
          <Terminal websiteId={terminalViewer.id} apiBase={API} />
        </Suspense>
      </div>
    </section>;
  }

  function renderWebsiteLogViewer() {
    if (!logViewer) return null;
    return <section className="section nginx-modal log-viewer">
      <div className="section-title">
        <div className="nginx-config-title">
          <h2>{t('Nginx logs - {domain}', { domain: logViewer.domain })}</h2>
          <p className="hint">{logViewer.path || `/var/log/nginx/${logViewer.domain}.${logViewer.kind}.log`}</p>
        </div>
        <button className="secondary-light" onClick={() => setLogViewer(null)}><X size={14}/> {t('Close')}</button>
      </div>
      <div className="log-toolbar">
        <div className="segmented-control">
          <button className={logViewer.kind === 'access' ? 'active' : ''} disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, 'access', logViewer.lines, logViewer.domain)}>{t('Access')}</button>
          <button className={logViewer.kind === 'error' ? 'active' : ''} disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, 'error', logViewer.lines, logViewer.domain)}>{t('Error')}</button>
        </div>
        <select value={logViewer.lines} onChange={e => loadWebsiteLog(logViewer.id, logViewer.kind, Number(e.target.value), logViewer.domain)} disabled={!!loading}>
          <option value={100}>{t('100 lines')}</option>
          <option value={200}>{t('200 lines')}</option>
          <option value={500}>{t('500 lines')}</option>
          <option value={1000}>{t('1000 lines')}</option>
          <option value={2000}>{t('2000 lines')}</option>
        </select>
        <button className="secondary-light" disabled={!!loading} onClick={() => loadWebsiteLog(logViewer.id, logViewer.kind, logViewer.lines, logViewer.domain)}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      <pre className="log-output">{logViewer.exists ? (logViewer.content || t('Log is empty.')) : t('Log file has not been created yet.')}</pre>
    </section>;
  }

  function renderWebsites() {
    const wpFieldsEnabled = siteType === 'wordpress' && installWordPress;
    const searchActive = !!websiteSearch.trim();
    const visibleWebsites = searchActive ? websiteList : (websiteList.length ? websiteList : websites);
    const createTitle = websites.length ? t('Create website') : t('Attach first domain');
    const createHint = websites.length
      ? null
      : t('This creates the first hosted site for the current account.');
    return <>
      <section className="section">
        <h2>{createTitle}</h2>
        {createHint && <p className="hint">{createHint}</p>}
        <div className="form-row create-site-row">
          <label className="field"><span>{t('Domain')}</span><input value={domain} onChange={e => setDomain(e.target.value)} placeholder="domain.com" /></label>
          <label className="field"><span>{t('Website mode')}</span><select value={siteType} onChange={e => setSiteType(e.target.value)}>
            {WEBSITE_MODES.map(([value, label]) => <option
              key={value}
              value={value}
              disabled={value === 'application' && !appsFeatureEnabled}
            >{t(label)}</option>)}
          </select></label>
          {siteType === 'application'
            ? <label className="field"><span>{t('Application')}</span><select value={createSiteAppId} onChange={e => setCreateSiteAppId(e.target.value)}>
              <option value="">{t('Select an application')}</option>
              {siteApps.items.map(app => <option key={app.id} value={app.id}>{app.name} · {t(SITE_APP_KIND_LABELS[app.kind] || app.kind)} · :{app.port}</option>)}
            </select></label>
            : <label className="field"><span>{t('PHP version')}</span><select value={phpVersion} onChange={e => setPhpVersion(e.target.value)}>
              {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
            </select></label>}
          {wpFieldsEnabled && <label className="field"><span>{t('Admin email')}</span><input value={adminEmail} onChange={e => setAdminEmail(e.target.value)} placeholder="admin@domain.com" /></label>}
          {wpFieldsEnabled && <label className="field"><span>{t('Admin user')}</span><input value={wpAdminUser} onChange={e => setWpAdminUser(e.target.value)} placeholder={t('WP admin user')} /></label>}
          {wpFieldsEnabled && <label className="field"><span>{t('Admin password')}</span><input value={wpAdminPassword} onChange={e => setWpAdminPassword(e.target.value)} placeholder={t('Leave blank for a random one')} type="password" /></label>}
        </div>
        {siteType === 'application' && siteApps.items.length === 0 && <p className="hint">
          {t('No applications installed yet. Install one on the {page} page first.', { page: <button type="button" className="link-button" onClick={() => navigateToPage('applications')}>{t('Applications')}</button> })}
        </p>}
        {siteType === 'wordpress' && <label className="check-line">
          <input type="checkbox" checked={installWordPress} onChange={e => setInstallWordPress(e.target.checked)} />
          {t('Install WordPress (creates database, downloads WP, configures vhost)')}
        </label>}
        <div className="create-ssl-row">
          <span className="create-ssl-label">{t('SSL after creating')}</span>
          <div className="segmented ssl-mode-tabs">
            <button type="button" className={createSslMode === 'none' ? 'active' : ''} onClick={() => setCreateSslMode('none')}>{t('Off')}</button>
            <button type="button" className={createSslMode === 'letsencrypt' ? 'active' : ''} onClick={() => setCreateSslMode('letsencrypt')}><Lock size={13}/> {t('Let\'s Encrypt')}</button>
            <button type="button" className={createSslMode === 'wildcard' ? 'active' : ''} onClick={() => setCreateSslMode('wildcard')}><Globe size={13}/> {t('Wildcard')}</button>
            <button type="button" className={createSslMode === 'shared' ? 'active' : ''} onClick={() => setCreateSslMode('shared')}><Copy size={13}/> {t('Existing cert')}</button>
            <button type="button" className={createSslMode === 'manual' ? 'active' : ''} onClick={() => setCreateSslMode('manual')}><KeyRound size={13}/> {t('Manual')}</button>
          </div>
        </div>
        {createSslMode !== 'none' && <div className="ssl-sub-form create-ssl-sub">
          {createSslMode === 'letsencrypt' && <p className="hint">{t('A certificate is issued right after the site is created — the domain must already point to this server.')}</p>}
          {createSslMode === 'wildcard' && <>
            <p className="hint">{t('Issues {names} over Cloudflare DNS. Leave the token blank to reuse one already saved for the zone.', { names: <code>zone + *.zone</code> })}</p>
            <input type="password" autoComplete="off" placeholder={t('Cloudflare API token (Zone → DNS → Edit)')}
              value={createSslToken} onChange={e => setCreateSslToken(e.target.value)} />
          </>}
          {createSslMode === 'shared' && <p className="hint">{t('After the site is created the panel points it at an existing certificate that covers this domain (a wildcard first). If none does, the site is created without SSL.')}</p>}
          {createSslMode === 'manual' && <p className="hint">{t('The site is created, then the panel opens the SSL page so you can paste the certificate and key.')}</p>}
        </div>}
        <p className="hint">{wpFieldsEnabled
          ? t('WordPress will be installed and the panel will show the URL, admin account, and password after creation.')
          : siteType === 'application'
            ? t('Nginx will forward this domain to the selected application on 127.0.0.1, including WebSocket upgrades.')
            : t('A PHP-FPM vhost will be created with public_html/ folder. Upload your PHP, HTML, or static files via File Manager.')}</p>
        <div className="create-site-actions"><button disabled={!!loading || !domain} onClick={createWordPress}><Plus size={15}/> {t('Create website')}</button></div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>{t('Website list')}</h2><p className="hint">{searchActive ? t('{count} result(s)', { count: visibleWebsites.length }) : t('{count} website(s)', { count: visibleWebsites.length })}</p></div>
          <button className="secondary-light" disabled={!!loading || websiteSearching} onClick={() => loadWebsiteList(websiteSearch, true)}><RefreshCw size={15} className={websiteSearching ? 'spin' : ''}/> {t('Refresh')}</button>
        </div>
        <div className="website-search-bar">
          <Search size={16}/>
          <input
            value={websiteSearch}
            onChange={e => setWebsiteSearch(e.target.value)}
            placeholder={t('Search domain, alias, path, or Linux user')}
            aria-label={t('Search websites')}
          />
          {websiteSearch && <button className="secondary-light icon-button" type="button" onClick={() => setWebsiteSearch('')} aria-label={t('Clear website search')} title={t('Clear search')}><X size={15}/></button>}
        </div>
        {visibleWebsites.length === 0 && <EmptyState icon={Globe} message={searchActive ? t('No websites match this search.') : t('No websites yet.')} />}
        <div className="site-grid">
          {visibleWebsites.map(site => <div className="site-stack" key={site.id}>
          <article className="site-card">
            <div className="site-head">
              <div>
                <a className="site-link" href={websiteUrl(site)} target="_blank" rel="noopener noreferrer">{site.domain}</a>
                <small>{site.root_path}</small>
              </div>
            </div>
            <div className="site-meta">
              <span className={`badge site-ssl-badge ${site.ssl_enabled ? 'ok' : ''}`}>{site.ssl_enabled ? t('SSL OK') : t('No SSL')}</span>
              <span>{t('Type {value}', { value: <strong>{site.app_type || 'wordpress'}</strong> })}</span>
              <span>PHP <strong>{site.php_version}</strong></span>
              {site.app_type === 'php' && site.nginx_rewrite_mode && site.nginx_rewrite_mode !== 'none' && <span>{t('Rewrite {value}', { value: <strong>{site.nginx_rewrite_mode}</strong> })}</span>}
              {site.nginx_custom && <span className="badge ok">{t('Custom Nginx')}</span>}
              {site.waf_enabled && <span className="badge ok">WAF</span>}
              {site.http_flood_enabled && <span className="badge ok">{t('HTTP Flood')}</span>}
              {(site.aliases || []).length > 0 && <span>{t('Domains {value}', { value: <strong>{(site.aliases || []).length + 1}</strong> })}</span>}
            </div>
            <div className="site-actions" aria-label={t('Website actions for {domain}', { domain: site.domain })}>
              <div className="site-feature-actions">
                <button className="site-icon-button secondary-light" data-tooltip={t('Files')} title={t('Files')} aria-label={t('Open file manager for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => openWebsiteFileManager(site)}><FolderOpen size={15}/></button>
                <button className="site-icon-button secondary-light" data-tooltip={t('Logs')} title={t('Logs')} aria-label={t('View logs for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => openWebsiteLogs(site)}><FileText size={15}/></button>
                <button className="site-icon-button secondary-light" data-tooltip={t('Terminal')} title={t('Terminal')} aria-label={t('Open terminal for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => openWebsiteTerminal(site)}><TerminalIcon size={15}/></button>
                {site.wordpress_installed ? <>
                  <button className="site-icon-button secondary-light" data-tooltip={t('Update WordPress')} title={t('Update WordPress (core + plugins + themes)')} aria-label={t('Update WordPress for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => updateWordPressAll(site)}><RefreshCw size={15}/></button>
                </> : <button className="site-icon-button secondary-light" data-tooltip={t('Install WP')} title={t('Install WordPress')} aria-label={t('Install WordPress for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => openWordPressInstaller(site)}><WordPressIcon size={15}/></button>}
                <button className="site-icon-button secondary-light" data-tooltip={t('Settings')} title={t('Settings')} aria-label={t('Edit settings for {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => openNginxCustom(site)}><SettingsIcon size={15}/></button>
                <button className="site-icon-button danger" data-tooltip={t('Delete')} title={t('Delete')} aria-label={t('Delete {domain}', { domain: site.domain })} disabled={!!loading} onClick={() => deleteWebsite(site.id)}><Trash2 size={15}/></button>
              </div>
            </div>
          </article>
          {String(wordpressInstaller?.website_id || '') === String(site.id) && renderWordPressInstaller()}
          {nginxCustomEditing?.id === site.id && renderNginxEditor()}
          {logViewer?.id === site.id && renderWebsiteLogViewer()}
          {terminalViewer?.id === site.id && renderWebsiteTerminal()}
          </div>)}
        </div>
      </section>
    </>;
  }

  return renderWebsites();
}
