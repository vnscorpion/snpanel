import { useEffect, useState } from 'react';
import { Copy, KeyRound, Power, PowerOff, RefreshCw } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './SftpAccess.css';

// A panel user's SFTP login: whether it is on, what to connect with, and its
// password. On the Users page for an administrator, on the Security page for
// the user themself.
//
// Changing one's own SFTP password asks for the panel password and the
// authenticator code first, as a panel password change does: an SFTP password
// opens every file the account has.
export default function SftpAccess({ user, self = false, page = false }) {
  const { isAdmin, loadSftpAccess, loading, setSftpPassword, switchSftpAccess } = usePanel();
  const t = useT();
  const [info, setInfo] = useState(null);
  const [typed, setTyped] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [code, setCode] = useState('');
  const [shown, setShown] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let live = true;
    setInfo(null);
    setShown('');
    loadSftpAccess(user.id).then((data) => { if (live && data) setInfo(data); });
    return () => { live = false; };
  }, [user.id]);

  const busy = !!loading;
  const stepUp = self ? { current_password: currentPassword, code } : {};
  const stepUpReady = !self || (currentPassword && (!user.totp_enabled || code.trim().length >= 6));
  const typedOk = typed.length >= 12 && !/[:\r\n]/.test(typed);

  // The answer to any change: what the page shows next, and the password
  // when the server made one - which it shows this once.
  function took(data) {
    if (!data) return;
    setInfo(data);
    setTyped('');
    setCurrentPassword('');
    setCode('');
    setCopied(false);
    setShown(data.password || '');
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(shown);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  // A heading of the page's own on the Account security page; a label in the
  // Users page's editor, like the sections around it.
  const Title = page ? 'h2' : 'strong';

  if (!info) {
    return <div className="sftp-access" aria-busy="true">
      <div className="sftp-head"><Title>{t('SFTP access')}</Title></div>
      <p className="hint">{t('Loading…')}</p>
    </div>;
  }

  const host = window.location.hostname;
  const ports = info.ports?.length ? info.ports.join(', ') : '22';
  const state = !info.enabled ? t('Off. This account cannot sign in over SFTP.')
    : info.own_password ? t('On, with a password of its own.')
      : t('On. It signs in with the panel password, and follows it when that changes.');

  return <div className="sftp-access">
    <div className="sftp-head">
      <div>
        <Title>{t('SFTP access')}</Title>
        <small>{state}</small>
      </div>
      <span className={`badge ${info.enabled ? 'ok' : ''}`}>{info.enabled ? t('On') : t('Off')}</span>
    </div>

    {info.enabled && <dl className="sftp-details">
      <div><dt>{t('Host')}</dt><dd><code>{host}</code></dd></div>
      <div><dt>{t('Port')}</dt><dd><code>{ports}</code></dd></div>
      <div><dt>{t('Username')}</dt><dd><code>{info.username}</code></dd></div>
      <div><dt>{t('Folder')}</dt><dd><code>/</code> <span className="hint">{t('({home} on the server)', { home: info.home })}</span></dd></div>
    </dl>}

    {shown && <div className="sftp-shown" role="status">
      <span>{t('New SFTP password:')}</span>
      <code>{shown}</code>
      <button type="button" className="mini secondary-light" onClick={copy}><Copy size={13} aria-hidden="true"/> {copied ? t('Copied') : t('Copy')}</button>
      <small>{t('Shown this once. Copy it now.')}</small>
    </div>}

    {!info.active && <p className="hint">{t('The account is suspended: SFTP stays locked until it is let back in.')}</p>}
    {info.active && !info.enabled && !isAdmin && <p className="hint">{t('Ask an administrator to turn it on.')}</p>}

    {info.active && (info.enabled || isAdmin) && <div className="sftp-password">
      <div className="sftp-field">
        <label htmlFor={`sftp-typed-${user.id}`}>{info.enabled ? t('New SFTP password') : t('SFTP password')}</label>
        <input id={`sftp-typed-${user.id}`} type="password" autoComplete="new-password" value={typed}
          placeholder={t('At least 12 characters')} onChange={(event) => setTyped(event.target.value)} />
      </div>
      {self && info.enabled && <>
        <div className="sftp-field">
          <label htmlFor={`sftp-current-${user.id}`}>{t('Current panel password')}</label>
          <input id={`sftp-current-${user.id}`} type="password" autoComplete="current-password" value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)} />
        </div>
        {user.totp_enabled && <div className="sftp-field">
          <label htmlFor={`sftp-code-${user.id}`}>{t('Authenticator code')}</label>
          <input id={`sftp-code-${user.id}`} inputMode="numeric" autoComplete="one-time-code" value={code}
            onChange={(event) => setCode(event.target.value)} />
        </div>}
      </>}
      <div className="sftp-actions">
        {info.enabled
          ? <>
            <button type="button" className="secondary" disabled={busy || !stepUpReady}
              onClick={async () => took(await setSftpPassword(user, { generate: true, ...stepUp }))}>
              <RefreshCw size={14} aria-hidden="true"/> {t('Generate a new password')}
            </button>
            <button type="button" disabled={busy || !typedOk || !stepUpReady}
              onClick={async () => took(await setSftpPassword(user, { password: typed, ...stepUp }))}>
              <KeyRound size={14} aria-hidden="true"/> {t('Set this password')}
            </button>
            {isAdmin && <button type="button" className="secondary danger-hover" disabled={busy}
              onClick={async () => took(await switchSftpAccess(user, false))}>
              <PowerOff size={14} aria-hidden="true"/> {t('Turn SFTP off')}
            </button>}
          </>
          : <>
            <button type="button" disabled={busy}
              onClick={async () => took(await switchSftpAccess(user, true, { generate: true }))}>
              <Power size={14} aria-hidden="true"/> {t('Turn on with a generated password')}
            </button>
            <button type="button" className="secondary" disabled={busy || !typedOk}
              onClick={async () => took(await switchSftpAccess(user, true, { password: typed }))}>
              {t('Turn on with this password')}
            </button>
          </>}
      </div>
    </div>}
  </div>;
}
