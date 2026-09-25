import { useState } from 'react';
import { Fingerprint, KeyRound, Lock, Plus, RefreshCw, Shield, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { passkeysSupported } from '../lib/webauthn.js';
import { useT } from '../i18n/index.jsx';
import SftpAccess from '../components/SftpAccess.jsx';
import './Security.css';

export default function SecurityPage() {
  const {
    addPasskey,
    currentUser,
    disableTwoFactorAuth,
    enableTwoFactorAuth,
    loadPasskeys,
    loadTwoFactorStatus,
    loading,
    passkeys,
    removePasskey,
    setTwoFactorCode,
    setupTwoFactorAuth,
    twoFactorCode,
    twoFactorSetup,
    twoFactorStatus,
  } = usePanel();
  const t = useT();
  const [passkeyName, setPasskeyName] = useState('');
  const [passkeyCode, setPasskeyCode] = useState('');

  const busy = !!loading;
  const enabled = Boolean(twoFactorStatus?.enabled || currentUser?.totp_enabled);
  const supported = passkeysSupported();
  const items = passkeys.items || [];
  const full = items.length >= (passkeys.limit || 10);
  // Why a passkey cannot be added here, if it cannot.
  const blocked = !enabled
    ? t('Turn on the authenticator app first. A passkey is added beside it, so the code is always there to fall back on.')
    : !supported
      ? t('This browser cannot use passkeys.')
      : passkeys.loaded && !passkeys.available
        ? t('Passkeys need the panel to be opened by its hostname over HTTPS, not by an IP address. This page is at {host}.', { host: window.location.host })
        : full
          ? t('This account has the most passkeys it can have. Remove one to add another.')
          : '';

  async function submitPasskey(event) {
    event.preventDefault();
    const added = await addPasskey(passkeyName.trim() || t('Passkey'), passkeyCode.trim());
    if (added) { setPasskeyName(''); setPasskeyCode(''); }
  }

  return <div className="security-page">
    <section className="section">
      <div className="security-head">
        <span className={`security-icon ${enabled ? 'on' : 'off'}`}>{enabled ? <ShieldCheck size={22} aria-hidden="true"/> : <ShieldOff size={22} aria-hidden="true"/>}</span>
        <div className="security-head-text">
          <h2>{t('Authenticator app')} <span className={`badge ${enabled ? 'ok' : ''}`}>{enabled ? t('On') : t('Off')}</span></h2>
          <p className="hint">{t('A six-digit code from Google Authenticator or any TOTP app, asked for at every sign-in.')}</p>
        </div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={() => { loadTwoFactorStatus(); loadPasskeys(); }}
          aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      {!enabled && <div className="security-grid">
        <div className="info-box">
          <strong>{t('1. Scan the code')}</strong>
          {twoFactorSetup?.qr_data_url
            ? <img className="qr-code" src={twoFactorSetup.qr_data_url} alt={t('QR code for the authenticator app')} />
            : <p className="hint">{t('Generate a code, then scan it with the app.')}</p>}
          {twoFactorSetup?.secret && <code className="secret-text">{twoFactorSetup.secret}</code>}
          <div className="actions">
            <button disabled={busy} onClick={setupTwoFactorAuth}><Shield size={14} aria-hidden="true"/> {t('Generate QR code')}</button>
          </div>
        </div>
        <div className="info-box">
          <strong>{t('2. Enter the code it shows')}</strong>
          <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" aria-label={t('Authentication code')} />
          <button disabled={busy || !twoFactorSetup || !twoFactorCode} onClick={enableTwoFactorAuth}><Lock size={14} aria-hidden="true"/> {t('Turn on')}</button>
        </div>
      </div>}
      {enabled && <div className="security-grid one">
        <div className="info-box">
          <strong>{t('Turn off')}</strong>
          <p className="hint">{t('Asks for your password and a current code. Your passkeys are removed with it.')}</p>
          <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" aria-label={t('Authentication code')} />
          <button className="danger" disabled={busy || !twoFactorCode} onClick={disableTwoFactorAuth}>{t('Turn off two-step verification')}</button>
        </div>
      </div>}
    </section>

    <section className="section">
      <div className="security-head">
        <span className={`security-icon ${items.length > 0 ? 'on' : 'off'}`}><Fingerprint size={22} aria-hidden="true"/></span>
        <div className="security-head-text">
          <h2>{t('Passkeys')} {items.length > 0 && <span className="badge ok">{items.length}</span>}</h2>
          <p className="hint">{t('Sign in with your fingerprint, face, screen lock or security key instead of typing the code. If a passkey does not work, the authenticator app is asked for instead.')}</p>
        </div>
      </div>

      {items.length > 0 && <div className="data-table-wrap">
        <table className="data-table passkey-table">
          <thead><tr>
            <th scope="col">{t('Name')}</th>
            <th scope="col">{t('Added')}</th>
            <th scope="col">{t('Last used')}</th>
            <th scope="col"><span className="sr-only">{t('Remove')}</span></th>
          </tr></thead>
          <tbody>
            {items.map(item => <tr key={item.id}>
              <td><strong>{item.name}</strong>{!item.usable_here && <small className="passkey-elsewhere">{t('Works at {host}', { host: item.rp_id })}</small>}</td>
              <td>{formatWhen(item.created_at)}</td>
              <td>{item.last_used_at ? formatWhen(item.last_used_at) : <span className="data-table-muted">{t('Never')}</span>}</td>
              <td className="data-table-actions">
                <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => removePasskey(item)}
                  aria-label={t('Remove {name}', { name: item.name })} title={t('Remove {name}', { name: item.name })}><Trash2 size={15} aria-hidden="true"/></button>
              </td>
            </tr>)}
          </tbody>
        </table>
      </div>}

      {blocked
        ? <p className="empty-note">{blocked}</p>
        : <form className="passkey-form" onSubmit={submitPasskey}>
          <label><span>{t('Name')}</span>
            <input value={passkeyName} onChange={e => setPasskeyName(e.target.value)} placeholder={t('For example: Work laptop')} maxLength={64} autoComplete="off" />
          </label>
          <label><span>{t('Authentication code')}</span>
            <input value={passkeyCode} onChange={e => setPasskeyCode(e.target.value)} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" />
          </label>
          <button type="submit" disabled={busy || passkeyCode.trim().length < 6}><Plus size={14} aria-hidden="true"/> {t('Add a passkey')}</button>
        </form>}
      {!blocked && items.length === 0 && <p className="hint passkey-first"><KeyRound size={14} aria-hidden="true"/> {t('Your device will ask you to confirm with your fingerprint, face or screen lock.')}</p>}
    </section>

    {currentUser && <section className="section">
      <SftpAccess user={currentUser} self page />
    </section>}
  </div>;
}
