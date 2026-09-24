import { Lock, RefreshCw, Shield } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function SecurityPage() {
  const {
    currentUser,
    disableTwoFactorAuth,
    enableTwoFactorAuth,
    loadTwoFactorStatus,
    loading,
    setTwoFactorCode,
    setupTwoFactorAuth,
    twoFactorCode,
    twoFactorSetup,
    twoFactorStatus,
  } = usePanel();

  function renderSecurity() {
    const enabled = Boolean(twoFactorStatus?.enabled || currentUser?.totp_enabled);
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Google Authenticator 2FA</h2><p className="hint">Current status: <strong>{enabled ? 'Enabled' : 'Disabled'}</strong></p></div>
          <button disabled={!!loading} onClick={loadTwoFactorStatus}><RefreshCw size={14}/> Refresh</button>
        </div>
        {!enabled && <div className="security-grid">
          <div className="info-box">
            <strong>Setup</strong>
            {twoFactorSetup?.qr_data_url ? <img className="qr-code" src={twoFactorSetup.qr_data_url} alt="2FA QR code" /> : <p className="hint">No setup code generated.</p>}
            {twoFactorSetup?.secret && <code className="secret-text">{twoFactorSetup.secret}</code>}
            <div className="actions">
              <button disabled={!!loading} onClick={setupTwoFactorAuth}><Shield size={14}/> Generate QR</button>
            </div>
          </div>
          <div className="info-box">
            <strong>Verify</strong>
            <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" />
            <button disabled={!!loading || !twoFactorSetup || !twoFactorCode} onClick={enableTwoFactorAuth}><Lock size={14}/> Enable 2FA</button>
          </div>
        </div>}
        {enabled && <div className="security-grid one">
          <div className="info-box">
            <strong>Disable 2FA</strong>
            <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" />
            <button className="danger" disabled={!!loading || !twoFactorCode} onClick={disableTwoFactorAuth}>Disable 2FA</button>
          </div>
        </div>}
      </section>

    </>;
  }

  return renderSecurity();
}
