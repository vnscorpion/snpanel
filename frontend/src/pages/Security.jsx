import { useState } from 'react';
import { Fingerprint, KeyRound, Lock, Plus, RefreshCw, Shield, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { passkeysSupported } from '../lib/webauthn.js';
import { useT } from '../i18n/index.jsx';
import './Security.css';

export default function SecurityPage() {
  const {
    addPasskey,
    changeOwnPassword,
    currentUser,
    disableTwoFactorAuth,
    enableTwoFactorAuth,
    isAdmin,
    loadPasskeys,
    loadTwoFactorStatus,
    loading,
    panelSettings,
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
  const [passkeyPassword, setPasskeyPassword] = useState('');
  const [passkeyCode, setPasskeyCode] = useState('');
  // The passkey being removed, and the password that confirms it.
  const [removing, setRemoving] = useState(null);
  const [removePassword, setRemovePassword] = useState('');
  const [pw, setPw] = useState({ current: '', next: '', again: '', code: '' });

  const busy = !!loading;
  const enabled = Boolean(twoFactorStatus?.enabled || currentUser?.totp_enabled);
  const supported = passkeysSupported();
  const items = passkeys.items || [];
  const full = items.length >= (passkeys.limit || 10);
  // The panel's own name, when it has one other than the address in use:
  // where a passkey can be made instead.
  const panelHost = String(panelSettings?.panel_hostname || '').trim();
  const panelName = /[a-z]/i.test(panelHost) && !/^\[|^\d+(\.\d+){3}$/.test(panelHost) && panelHost !== window.location.hostname ? panelHost : '';
  const panelAt = panelName ? `https://${panelName}${window.location.port ? `:${window.location.port}` : ''}/security` : '';
  // Why a passkey cannot be added here, if it cannot.
  const blocked = !supported
    ? t('This browser cannot use passkeys.')
    : passkeys.loaded && !passkeys.available
      ? t('Passkeys work only when the panel is opened by its domain name over HTTPS with a valid certificate - a browser never makes one for an IP address. This page is at {host}.', { host: window.location.host })
      : full
        ? t('This account has the most passkeys it can have. Remove one to add another.')
        : '';
  const passkeyReady = passkeyPassword && (!enabled || passkeyCode.trim().length >= 6);

  const pwField = (key) => ({ value: pw[key], onChange: (e) => setPw((prev) => ({ ...prev, [key]: e.target.value })) });
  const pwBadChar = /[:\r\n]/.test(pw.next);
  const pwMismatch = pw.again !== '' && pw.again !== pw.next;
  const pwReady = pw.current && pw.next.length >= 12 && !pwBadChar && pw.next === pw.again && (!enabled || pw.code.trim().length >= 6);

  async function submitPassword(event) {
    event.preventDefault();
    const body = { current_password: pw.current, password: pw.next, ...(enabled ? { code: pw.code.trim() } : {}) };
    if (!(await changeOwnPassword(body))) setPw((prev) => ({ ...prev, current: '', code: '' }));
  }

  async function submitPasskey(event) {
    event.preventDefault();
    const added = await addPasskey(passkeyName.trim() || t('Passkey'), passkeyPassword, enabled ? passkeyCode.trim() : '');
    if (added) setPasskeyName('');
    // The proof is asked for again either way: it was used, or it was wrong.
    setPasskeyPassword('');
    setPasskeyCode('');
  }

  async function submitRemove(event) {
    event.preventDefault();
    if (await removePasskey(removing, removePassword)) setRemoving(null);
    setRemovePassword('');
  }

  return <div className="security-page">
    <section className="section" aria-labelledby="security-password-title">
      <div className="security-head">
        <span className="security-icon off"><KeyRound size={22} aria-hidden="true"/></span>
        <div className="security-head-text">
          <h2 id="security-password-title">{t('Login password')}</h2>
          <p className="hint">{t('The password you sign in to the panel with. When it changes, every session ends - this one too.')}</p>
        </div>
      </div>
      <form className="security-password-form" onSubmit={submitPassword}>
        <div className="security-field">
          <label htmlFor="pw-current">{t('Current password')}</label>
          <input id="pw-current" type="password" autoComplete="current-password" {...pwField('current')} />
        </div>
        <div className="security-field">
          <label htmlFor="pw-next">{t('New password')}</label>
          <input id="pw-next" type="password" autoComplete="new-password" placeholder={t('At least 12 characters')} {...pwField('next')}
            aria-invalid={pwBadChar ? 'true' : undefined} />
        </div>
        <div className="security-field">
          <label htmlFor="pw-again">{t('New password again')}</label>
          <input id="pw-again" type="password" autoComplete="new-password" {...pwField('again')} aria-invalid={pwMismatch ? 'true' : undefined} />
        </div>
        {enabled && <div className="security-field">
          <label htmlFor="pw-code">{t('Authenticator code')}</label>
          <input id="pw-code" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" {...pwField('code')} />
        </div>}
        <div className="security-password-go">
          {pwBadChar && <small className="security-bad">{t("The password cannot contain ':'.")}</small>}
          {pwMismatch && <small className="security-bad">{t('The two new passwords differ.')}</small>}
          {!pwBadChar && !pwMismatch && <small className="hint">{t('An SFTP login that signs in with the panel password follows it.')}</small>}
          <button type="submit" disabled={busy || !pwReady}><KeyRound size={14} aria-hidden="true"/> {t('Change password')}</button>
        </div>
      </form>
    </section>

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
          <p className="hint">{t('Asks for your password and a current code.')} {items.length > 0
            ? t('Your passkeys stay, and sign-in goes on asking for one of them.')
            : t('Sign-in will then ask only for your password.')}</p>
          <input value={twoFactorCode} onChange={e => setTwoFactorCode(e.target.value)} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" aria-label={t('Authentication code')} />
          <button className="danger" disabled={busy || !twoFactorCode} onClick={disableTwoFactorAuth}>{t('Turn off two-step verification')}</button>
        </div>
      </div>}
    </section>

    <section className="section" aria-labelledby="security-passkeys-title">
      <div className="security-head">
        <span className={`security-icon ${items.length > 0 ? 'on' : 'off'}`}><Fingerprint size={22} aria-hidden="true"/></span>
        <div className="security-head-text">
          <h2 id="security-passkeys-title">{t('Passkeys')} {items.length > 0 && <span className="badge ok">{items.length}</span>}</h2>
          <p className="hint">{t('After the password, your fingerprint, face, screen lock or security key confirms it is you - nothing to type. A passkey works on its own, or beside the authenticator app.')}</p>
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
                <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => { setRemoving(item); setRemovePassword(''); }}
                  aria-label={t('Remove {name}', { name: item.name })} title={t('Remove {name}', { name: item.name })}><Trash2 size={15} aria-hidden="true"/></button>
              </td>
            </tr>)}
          </tbody>
        </table>
      </div>}

      {removing && <form className="passkey-remove" onSubmit={submitRemove} aria-label={t('Remove {name}', { name: removing.name })}>
        <p>
          <strong>{t('Remove the passkey {name}?', { name: removing.name })}</strong>{' '}
          {enabled
            ? t('You can still sign in with the authenticator app.')
            : items.length <= 1
              ? t('It is your last one: sign-in will then ask only for your password.')
              : t('Your other passkeys go on working.')}
        </p>
        <div className="security-field">
          <label htmlFor="passkey-remove-password">{t('Current password')}</label>
          <input id="passkey-remove-password" type="password" autoComplete="current-password" value={removePassword} onChange={e => setRemovePassword(e.target.value)} autoFocus />
        </div>
        <div className="passkey-remove-go">
          <button type="button" className="secondary" disabled={busy} onClick={() => { setRemoving(null); setRemovePassword(''); }}>{t('Cancel')}</button>
          <button type="submit" className="danger" disabled={busy || !removePassword}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>
        </div>
      </form>}

      {blocked
        ? <div className="empty-note passkey-blocked">
          <p>{blocked}</p>
          {passkeys.loaded && !passkeys.available && supported && (panelAt
            ? <p><a href={panelAt}>{t('Open the panel at {host}', { host: panelName })}</a></p>
            : isAdmin && <p>{t('Give the panel a domain name and its certificate under Panel settings, then open it by that name.')}</p>)}
        </div>
        : <form className="passkey-form" onSubmit={submitPasskey}>
          <div className="security-field">
            <label htmlFor="passkey-name">{t('Name')}</label>
            <input id="passkey-name" value={passkeyName} onChange={e => setPasskeyName(e.target.value)} placeholder={t('For example: Work laptop')} maxLength={64} autoComplete="off" />
          </div>
          <div className="security-field">
            <label htmlFor="passkey-password">{t('Current password')}</label>
            <input id="passkey-password" type="password" autoComplete="current-password" value={passkeyPassword} onChange={e => setPasskeyPassword(e.target.value)} />
          </div>
          {enabled && <div className="security-field">
            <label htmlFor="passkey-code">{t('Authenticator code')}</label>
            <input id="passkey-code" value={passkeyCode} onChange={e => setPasskeyCode(e.target.value)} placeholder="123456" inputMode="numeric" autoComplete="one-time-code" />
          </div>}
          <button type="submit" disabled={busy || !passkeyReady}><Plus size={14} aria-hidden="true"/> {t('Add a passkey')}</button>
        </form>}
      {!blocked && items.length === 0 && <p className="hint passkey-first"><KeyRound size={14} aria-hidden="true"/> {t('Your device will ask you to confirm with your fingerprint, face or screen lock.')}</p>}
      {/* With passkeys alone, a lost device is a locked account until someone
          resets it: say who, and how to keep a way back. */}
      {!enabled && (items.length > 0 || !blocked) && <p className="hint passkey-backup">
        {t('Keep a way back: if the device holding your passkey is lost, two-step sign-in has to be reset for you. Turning on the authenticator app as well keeps a code to fall back on.')}{' '}
        {/* The rescue command resets the account named admin; another
            administrator is reset by a colleague, like any user. */}
        {isAdmin && currentUser?.username === 'admin'
          ? <>{t('For this administrator account, run this on the server as root:')} <code>snpanel reset-admin-2fa</code></>
          : t('An administrator can reset it from the Users page.')}
      </p>}
    </section>

  </div>;
}
