import { Image, Lock, RefreshCw, Settings as SettingsIcon, Upload } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function PanelSettingsPage() {
  const {
    adminAccountForm,
    isAdmin,
    loadPanelSettings,
    loading,
    panelFaviconFile,
    panelLogoFile,
    panelSettings,
    panelSettingsForm,
    renderBrandMark,
    saveAdminAccount,
    savePanelSettings,
    setAdminAccountForm,
    setPanelFaviconFile,
    setPanelLogoFile,
    setPanelSettingsForm,
    toggleIpv6,
    uploadPanelAsset,
  } = usePanel();
  const t = useT();

  function renderPanelSettings() {
    if (!isAdmin) return <section className="section"><h2>Settings</h2><p className="hint">No permission.</p></section>;
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Panel settings</h2><p className="hint">Branding and hostname.</p></div>
          <button disabled={!!loading} onClick={loadPanelSettings}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="panel-settings-grid panel-settings-compact">
          <label><span>Panel name</span><input value={panelSettingsForm.app_name} onChange={e => setPanelSettingsForm(prev => ({ ...prev, app_name: e.target.value }))} placeholder="SNPanel" /></label>
          <label><span>Panel hostname</span><input value={panelSettingsForm.panel_hostname} onChange={e => setPanelSettingsForm(prev => ({ ...prev, panel_hostname: e.target.value }))} placeholder="panel.domain.com" /></label>
          <label className="check-line panel-ssl-status"><input type="checkbox" checked={!!panelSettingsForm.ssl_enabled} onChange={e => setPanelSettingsForm(prev => ({ ...prev, ssl_enabled: e.target.checked }))} /> Panel SSL</label>
          <button disabled={!!loading || !panelSettingsForm.app_name || !panelSettingsForm.panel_hostname} onClick={savePanelSettings}><SettingsIcon size={14}/> Save settings</button>
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
              ? <button className="secondary-light" disabled={!!loading} onClick={() => toggleIpv6(false)}>{t('Turn off IPv6')}</button>
              : <button className="secondary-light" disabled={!!loading || !panelSettings.ipv6?.available} onClick={() => toggleIpv6(true)}>{t('Turn on IPv6')}</button>}
          </div>
          <span className="hint">{panelSettings.ipv6?.detail}</span>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>Admin account</h2></div>
        </div>
        <div className="panel-settings-grid admin-account-grid">
          <label><span>Email</span><input type="email" value={adminAccountForm.email} onChange={e => setAdminAccountForm(prev => ({ ...prev, email: e.target.value }))} placeholder="admin@domain.com" /></label>
          <label><span>Current password</span><input type="password" value={adminAccountForm.current_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, current_password: e.target.value }))} placeholder="Current password" autoComplete="current-password" /></label>
          <label><span>New password</span><input type="password" value={adminAccountForm.password} onChange={e => setAdminAccountForm(prev => ({ ...prev, password: e.target.value }))} placeholder="New password" autoComplete="new-password" /></label>
          <label><span>Confirm password</span><input type="password" value={adminAccountForm.confirm_password} onChange={e => setAdminAccountForm(prev => ({ ...prev, confirm_password: e.target.value }))} placeholder="Repeat new password" autoComplete="new-password" /></label>
          <label><span>Authenticator code</span><input value={adminAccountForm.code} onChange={e => setAdminAccountForm(prev => ({ ...prev, code: e.target.value }))} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" /></label>
          <button disabled={!!loading || !adminAccountForm.email.trim() || (!!adminAccountForm.password && adminAccountForm.password !== adminAccountForm.confirm_password)} onClick={saveAdminAccount}><Lock size={14}/> Save account</button>
        </div>
      </section>
      <section className="section">
        <div className="section-title">
          <div><h2>Brand assets</h2><p className="hint">Upload PNG, JPG, WEBP, or ICO files up to 1 MB.</p></div>
        </div>
        <div className="brand-asset-grid">
          <div className="brand-asset-card">
            <div className="brand-preview">{renderBrandMark('settings-brand-mark')}</div>
            <label><span>Logo</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelLogoFile(e.target.files?.[0] || null)} /></label>
            <button disabled={!!loading || !panelLogoFile} onClick={() => uploadPanelAsset('logo')}><Upload size={14}/> Upload logo</button>
          </div>
          <div className="brand-asset-card">
            <div className="brand-preview favicon-preview">{panelSettings.favicon_url ? <img src={panelSettings.favicon_url} alt="" /> : <Image size={28}/>}</div>
            <label><span>Favicon</span><input type="file" accept="image/png,image/jpeg,image/webp,image/x-icon" onChange={e => setPanelFaviconFile(e.target.files?.[0] || null)} /></label>
            <button disabled={!!loading || !panelFaviconFile} onClick={() => uploadPanelAsset('favicon')}><Upload size={14}/> Upload favicon</button>
          </div>
        </div>
      </section>
    </>;
  }

  return renderPanelSettings();
}
