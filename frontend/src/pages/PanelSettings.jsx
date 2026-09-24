import { useEffect, useState } from 'react';
import { Copy, Image, KeyRound, Lock, Plus, RefreshCw, Settings as SettingsIcon, SlidersHorizontal, Trash2, Upload, UserCog } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './PanelSettings.css';

// One page, four tabs. API tokens were a page of their own; they live here
// now, and the addresses that opened that page - /api-tokens, /api-token -
// open this one on the tokens tab, so a WHMCS guide that links there still
// lands in the right place.
// Year first, 24-hour, local time: read the same way in either language.
function when(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const TABS = [
  ['general', msg('General'), SlidersHorizontal],
  ['account', msg('Admin account'), UserCog],
  ['branding', msg('Branding'), Image],
  ['tokens', msg('API tokens'), KeyRound],
];

export default function PanelSettingsPage() {
  const {
    adminAccountForm,
    apiTokens,
    copyApiToken,
    createApiToken,
    createdApiToken,
    isAdmin,
    loadApiTokens,
    loadPanelSettings,
    loading,
    navigateToPage,
    newApiToken,
    page,
    panelFaviconFile,
    panelLogoFile,
    panelSettings,
    panelSettingsForm,
    renderBrandMark,
    revokeApiToken,
    saveAdminAccount,
    savePanelSettings,
    setAdminAccountForm,
    setCreatedApiToken,
    setNewApiToken,
    setPanelFaviconFile,
    setPanelLogoFile,
    setPanelSettingsForm,
    toggleIpv6,
    uploadPanelAsset,
  } = usePanel();
  const t = useT();
  const [tab, setTab] = useState(page === 'api-tokens' ? 'tokens' : 'general');

  // Arriving at /api-tokens while this page is already open.
  useEffect(() => { if (page === 'api-tokens') setTab('tokens'); }, [page]);

  if (!isAdmin) return <section className="section"><h2>{t('Panel settings')}</h2><p className="hint">{t('No permission.')}</p></section>;

  const busy = !!loading;
  function choose(next) {
    setTab(next);
    // The tokens tab keeps its old address; the others share the page's.
    navigateToPage(next === 'tokens' ? 'api-tokens' : 'settings', { replace: true });
  }

  return <div className="settings-page">
    <div className="segmented-control settings-tabs" role="tablist" aria-label={t('Panel settings')}>
      {TABS.map(([id, label, Icon]) => <button key={id} type="button" role="tab" id={`settings-tab-${id}`}
        aria-selected={tab === id} aria-controls={`settings-panel-${id}`} className={tab === id ? 'active' : ''}
        onClick={() => choose(id)}><Icon size={15} aria-hidden="true"/>{t(label)}</button>)}
    </div>

    {tab === 'general' && <section className="section" role="tabpanel" id="settings-panel-general" aria-labelledby="settings-tab-general">
      <div className="section-title">
        <div><h2>{t('Name and address')}</h2><p className="hint">{t('What the panel is called, and the hostname it answers on.')}</p></div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={loadPanelSettings} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      <div className="panel-settings-grid panel-settings-compact">
        <label><span>{t('Panel name')}</span><input value={panelSettingsForm.app_name} onChange={e => setPanelSettingsForm(prev => ({ ...prev, app_name: e.target.value }))} placeholder="SNPanel" /></label>
        <label><span>{t('Panel hostname')}</span><input value={panelSettingsForm.panel_hostname} onChange={e => setPanelSettingsForm(prev => ({ ...prev, panel_hostname: e.target.value }))} placeholder="panel.domain.com" /></label>
        <label className="check-line panel-ssl-status"><input type="checkbox" checked={!!panelSettingsForm.ssl_enabled} onChange={e => setPanelSettingsForm(prev => ({ ...prev, ssl_enabled: e.target.checked }))} /> {t('Panel SSL')}</label>
        <button disabled={busy || !panelSettingsForm.app_name || !panelSettingsForm.panel_hostname} onClick={savePanelSettings}><SettingsIcon size={14} aria-hidden="true"/> {t('Save settings')}</button>
      </div>
      <div className="panel-net-strip">
        <div className="panel-net-row">
          <span className="panel-net-label">IPv4</span>
          <div className="panel-net-value">
            {panelSettings.server_ipv4?.length > 0
              ? panelSettings.server_ipv4.map(address => <span key={address} className="badge">{address}</span>)
              : <span className="hint">{t("Could not read the server's IPv4 address.")}</span>}
          </div>
        </div>
        <div className="panel-net-row">
          <span className="panel-net-label">IPv6</span>
          <div className="panel-net-value">
            {panelSettings.ipv6?.addresses?.length > 0
              ? panelSettings.ipv6.addresses.map(address => <span key={address} className="badge">{address}</span>)
              : <span className="badge">{t('None')}</span>}
            <span className={`badge ${panelSettings.ipv6?.enabled ? 'ok' : ''}`}>
              {panelSettings.ipv6?.enabled ? t('On') : t('Off')}
            </span>
          </div>
          {panelSettings.ipv6?.enabled
            ? <button className="secondary-light" disabled={busy} onClick={() => toggleIpv6(false)}>{t('Turn off IPv6')}</button>
            : <button className="secondary-light" disabled={busy || !panelSettings.ipv6?.available} onClick={() => toggleIpv6(true)}>{t('Turn on IPv6')}</button>}
        </div>
        <span className="hint">{panelSettings.ipv6?.detail}</span>
      </div>
    </section>}

    {tab === 'account' && <section className="section" role="tabpanel" id="settings-panel-account" aria-labelledby="settings-tab-account">
      <div className="section-title">
        <div><h2>{t('Admin account')}</h2><p className="hint">{t('The email and password this administrator signs in with.')}</p></div>
      </div>
      <div className="panel-settings-grid admin-account-grid">
        <label><span>{t('Email')}</span><input type="email" value={adminAccountForm.email} onChange={e => setAdminAccountForm(prev => ({ ...prev, email: e.target.value }))} placeholder="admin@domain.com" /></label>
        <label><span>{t('Current password')}</span><input type="password" value={adminAccountForm.current_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, current_password: e.target.value }))} placeholder={t('Current password')} autoComplete="current-password" /></label>
        <label><span>{t('New password')}</span><input type="password" value={adminAccountForm.password} onChange={e => setAdminAccountForm(prev => ({ ...prev, password: e.target.value }))} placeholder={t('New password')} autoComplete="new-password" /></label>
        <label><span>{t('Confirm password')}</span><input type="password" value={adminAccountForm.confirm_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, confirm_password: e.target.value }))} placeholder={t('Repeat new password')} autoComplete="new-password" /></label>
        <label><span>{t('Authenticator code')}</span><input value={adminAccountForm.code} onChange={e => setAdminAccountForm(prev => ({ ...prev, code: e.target.value }))} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" /></label>
        <button disabled={busy || !adminAccountForm.email.trim() || (!!adminAccountForm.password && adminAccountForm.password !== adminAccountForm.confirm_password)} onClick={saveAdminAccount}><Lock size={14} aria-hidden="true"/> {t('Save account')}</button>
      </div>
    </section>}

    {tab === 'branding' && <section className="section" role="tabpanel" id="settings-panel-branding" aria-labelledby="settings-tab-branding">
      <div className="section-title">
        <div><h2>{t('Brand assets')}</h2><p className="hint">{t('Upload PNG, JPG, WEBP, or ICO files up to 1 MB.')}</p></div>
      </div>
      <div className="brand-asset-grid">
        <div className="brand-asset-card">
          <div className="brand-preview">{renderBrandMark('settings-brand-mark')}</div>
          <label><span>{t('Logo')}</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelLogoFile(e.target.files?.[0] || null)} /></label>
          <button disabled={busy || !panelLogoFile} onClick={() => uploadPanelAsset('logo')}><Upload size={14} aria-hidden="true"/> {t('Upload logo')}</button>
        </div>
        <div className="brand-asset-card">
          <div className="brand-preview favicon-preview">{panelSettings.favicon_url ? <img src={panelSettings.favicon_url} alt="" /> : <Image size={28} aria-hidden="true"/>}</div>
          <label><span>{t('Favicon')}</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelFaviconFile(e.target.files?.[0] || null)} /></label>
          <button disabled={busy || !panelFaviconFile} onClick={() => uploadPanelAsset('favicon')}><Upload size={14} aria-hidden="true"/> {t('Upload favicon')}</button>
        </div>
      </div>
    </section>}

    {tab === 'tokens' && <section className="section" role="tabpanel" id="settings-panel-tokens" aria-labelledby="settings-tab-tokens">
      <div className="section-title">
        <div><h2>{t('API tokens')}</h2><p className="hint">{t('For WHMCS: create a token, then paste it into the WHMCS server’s Access Hash field.')}</p></div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={loadApiTokens} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      {createdApiToken && <div className="token-reveal" role="status">
        <label><span>{t('Your new token. Copy it now: it will not be shown again.')}</span>
          <input id="created-api-token" readOnly value={createdApiToken} onFocus={e => e.target.select()} spellCheck="false" /></label>
        <button type="button" disabled={busy} onClick={copyApiToken}><Copy size={14} aria-hidden="true"/> {t('Copy')}</button>
        <button type="button" className="secondary" onClick={() => setCreatedApiToken('')}>{t('Done')}</button>
      </div>}
      <form className="token-form" onSubmit={e => { e.preventDefault(); if (newApiToken.name.trim()) createApiToken(); }}>
        <label><span>{t('Name')}</span><input value={newApiToken.name} onChange={e => setNewApiToken(prev => ({ ...prev, name: e.target.value }))} placeholder="WHMCS" autoComplete="off" /></label>
        <label><span>{t('Allowed IPs')}</span><input value={newApiToken.allowed_ips} onChange={e => setNewApiToken(prev => ({ ...prev, allowed_ips: e.target.value }))} placeholder={t('Any IP')} spellCheck="false" autoComplete="off" /></label>
        <button type="submit" disabled={busy || !newApiToken.name.trim()}><Plus size={14} aria-hidden="true"/> {t('Create token')}</button>
      </form>
      <p className="hint">{t('Leave Allowed IPs empty to accept requests from any address. Separate several with commas: 203.0.113.4, 198.51.100.7')}</p>
      {apiTokens.length === 0
        ? <p className="empty-note">{t('No API tokens yet.')}</p>
        : <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr>
              <th scope="col">{t('Name')}</th>
              <th scope="col">{t('Allowed IPs')}</th>
              <th scope="col">{t('Status')}</th>
              <th scope="col">{t('Last used')}</th>
              <th scope="col"><span className="sr-only">{t('Revoke')}</span></th>
            </tr></thead>
            <tbody>
              {apiTokens.map(token => <tr key={token.id}>
                <td><strong>{token.name}</strong></td>
                <td>{token.allowed_ips ? <code>{token.allowed_ips}</code> : <span className="data-table-muted">{t('Any IP')}</span>}</td>
                <td><span className={`badge ${token.is_active ? 'ok' : ''}`}>{token.is_active ? t('Active') : t('Revoked')}</span></td>
                <td>{token.last_used_at ? when(token.last_used_at) : <span className="data-table-muted">{t('Never')}</span>}</td>
                <td className="data-table-actions">
                  {token.is_active && <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => revokeApiToken(token)}
                    aria-label={t('Revoke {name}', { name: token.name })} title={t('Revoke {name}', { name: token.name })}><Trash2 size={15} aria-hidden="true"/></button>}
                </td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </section>}
  </div>;
}
