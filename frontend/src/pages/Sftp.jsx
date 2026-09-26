import { useEffect, useMemo, useState } from 'react';
import { Copy, FolderKey, KeyRound, Plus, Trash2 } from 'lucide-react';
import SftpAccess from '../components/SftpAccess.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import '../components/SftpAccess.css';
import './Sftp.css';

const HOME = '.';
const CUSTOM = 'custom';

// SFTP, a page of its own: the account's own login, and the SFTP accounts
// it made - extra logins, each shut into one folder of its home, the way
// DirectAdmin's FTP accounts are. An administrator picks whose.
export default function SftpPage() {
  const { currentUser, isAdmin, loading, request, users, websites } = usePanel();
  const t = useT();
  const [ownerId, setOwnerId] = useState('');
  const owner = (isAdmin && ownerId ? users.find((u) => String(u.id) === String(ownerId)) : null) || currentUser;
  const self = owner?.id === currentUser?.id;
  const [data, setData] = useState(null);
  const [form, setForm] = useState({ name: '', folder: HOME, custom: '', password: '' });
  const [stepUp, setStepUp] = useState({ current_password: '', code: '' });
  const [shown, setShown] = useState(null);
  const [copied, setCopied] = useState(false);
  const busy = !!loading;

  async function load() {
    setData(await request(`/users/${owner.id}/sftp/accounts`, { silent: true }));
  }

  useEffect(() => {
    if (!owner?.id) return;
    setData(null);
    setShown(null);
    load();
  }, [owner?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // The folders offered: the whole home, and each of the owner's sites and
  // its web folder, as paths below the home.
  const linux = data?.owner || '';
  const folders = useMemo(() => {
    const prefix = `/home/${linux}/`;
    const theirs = websites.filter((site) => site.owner_id === owner?.id && String(site.root_path || '').startsWith(prefix));
    return theirs.flatMap((site) => {
      const folder = site.root_path.slice(prefix.length).replace(/\/+$/, '');
      return [
        { value: folder, label: t('{domain} - the whole site', { domain: site.domain }) },
        { value: `${folder}/public_html`, label: t('{domain} - its web folder (public_html)', { domain: site.domain }) },
      ];
    });
  }, [websites, owner?.id, linux, t]);

  const directory = form.folder === CUSTOM ? form.custom.trim().replace(/^\/+|\/+$/g, '') : form.folder;
  const nameOk = /^[a-z0-9]{1,16}$/.test(form.name);
  const passwordOk = !form.password || (form.password.length >= 12 && !/[:\r\n]/.test(form.password));
  const stepUpReady = !self || (stepUp.current_password && (!owner?.totp_enabled || stepUp.code.trim().length >= 6));
  const proof = self ? stepUp : {};

  function took(answer) {
    if (!answer) return;
    setStepUp({ current_password: '', code: '' });
    setCopied(false);
    if (answer.password) setShown({ username: answer.username, password: answer.password });
    load();
  }

  async function create(event) {
    event.preventDefault();
    const body = { name: form.name, directory, ...(form.password ? { password: form.password } : { generate: true }), ...proof };
    const answer = await request(`/users/${owner.id}/sftp/accounts`, { method: 'POST', body: JSON.stringify(body) }, t('Creating the SFTP account...'));
    if (answer) setForm({ name: '', folder: HOME, custom: '', password: '' });
    took(answer);
  }

  async function renew(account) {
    const answer = await request(`/users/${owner.id}/sftp/accounts/${account.id}/password`,
      { method: 'POST', body: JSON.stringify({ generate: true, ...proof }) }, t('Setting a new password...'));
    took(answer);
  }

  async function remove(account) {
    if (!confirm(t('Delete the SFTP account {name}? It can no longer sign in; the files stay.', { name: account.username }))) return;
    if (await request(`/users/${owner.id}/sftp/accounts/${account.id}`, { method: 'DELETE' }, t('Deleting the SFTP account...'))) {
      if (shown?.username === account.username) setShown(null);
      load();
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(shown.password);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  if (!owner) return <section className="section"><p className="hint">{t('Loading…')}</p></section>;
  const items = data?.items || [];
  const host = window.location.hostname;
  const ports = data?.ports?.length ? data.ports.join(', ') : '22';
  const full = data && items.length >= data.max;

  return <div className="sftp-page">
    {isAdmin && users.length > 1 && <section className="section sftp-owner">
      <label htmlFor="sftp-owner">{t('Account')}</label>
      <select id="sftp-owner" value={owner.id} onChange={(e) => setOwnerId(e.target.value)}>
        {users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
      </select>
    </section>}

    <section className="section">
      <SftpAccess user={owner} self={self} page />
    </section>

    <section className="section sftp-accounts" aria-labelledby="sftp-accounts-title">
      <div className="section-title">
        <div>
          <h2 id="sftp-accounts-title">{t('SFTP accounts')}</h2>
          <p className="hint">{t('Extra logins, each shut into one folder - a developer gets one site, not the whole account. What they upload belongs to {owner}.', { owner: linux || owner.username })}</p>
        </div>
      </div>

      {self && owner.is_active !== false && <div className="sftp-proof">
        <p className="hint">{t('Your current password proves it is you - for a new account and for a new password.')}</p>
        <div className="sftp-field">
          <label htmlFor="sftp-proof-current">{t('Current panel password')}</label>
          <input id="sftp-proof-current" type="password" autoComplete="current-password" value={stepUp.current_password}
            onChange={(e) => setStepUp((prev) => ({ ...prev, current_password: e.target.value }))} />
        </div>
        {owner.totp_enabled && <div className="sftp-field">
          <label htmlFor="sftp-proof-code">{t('Authenticator code')}</label>
          <input id="sftp-proof-code" inputMode="numeric" autoComplete="one-time-code" value={stepUp.code}
            onChange={(e) => setStepUp((prev) => ({ ...prev, code: e.target.value }))} />
        </div>}
      </div>}

      {shown && <div className="sftp-shown" role="status">
        <span>{t('Password of {name}:', { name: shown.username })}</span>
        <code>{shown.password}</code>
        <button type="button" className="mini secondary-light" onClick={copy}><Copy size={13} aria-hidden="true"/> {copied ? t('Copied') : t('Copy')}</button>
        <small>{t('Shown this once. Copy it now.')}</small>
      </div>}

      {data === null ? <p className="hint">{t('Loading…')}</p>
        : items.length === 0 ? <p className="empty-note">{t('No SFTP account yet.')}</p>
          : <ul className="sftp-account-list">
            {items.map((account) => <li key={account.id}>
              <FolderKey size={16} aria-hidden="true"/>
              <div className="sftp-account-text">
                <strong><code>{account.username}</code></strong>
                <small>{account.directory === HOME
                  ? t('The whole home, seen as {home}', { home: account.home })
                  : t('{folder}, seen as {home}', { folder: account.directory, home: account.home })}
                {' · '}{host}:{ports}</small>
              </div>
              <div className="sftp-account-actions">
                <button type="button" className="secondary-light" disabled={busy || !stepUpReady} onClick={() => renew(account)}
                  title={!stepUpReady ? t('Fill in your current password first.') : undefined}><KeyRound size={14} aria-hidden="true"/> {t('New password')}</button>
                <button type="button" className="danger" disabled={busy} onClick={() => remove(account)}
                  aria-label={t('Delete {name}', { name: account.username })} title={t('Delete {name}', { name: account.username })}><Trash2 size={14} aria-hidden="true"/></button>
              </div>
            </li>)}
          </ul>}

      {!owner.is_active && owner.is_active !== undefined
        ? <p className="hint">{t('The account is suspended: its SFTP accounts stay locked until it is let back in.')}</p>
        : <form className="sftp-account-form" onSubmit={create} aria-label={t('New SFTP account')}>
          <h3>{t('New SFTP account')}</h3>
          <div className="sftp-field">
            <label htmlFor="sftp-new-name">{t('Name')}</label>
            <div className="sftp-name">
              <span>{linux || owner.username}_</span>
              <input id="sftp-new-name" value={form.name} maxLength={16} autoComplete="off" spellCheck={false} placeholder="dev"
                onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '') }))} />
            </div>
          </div>
          <div className="sftp-field">
            <label htmlFor="sftp-new-folder">{t('Folder')}</label>
            <select id="sftp-new-folder" value={form.folder} onChange={(e) => setForm((prev) => ({ ...prev, folder: e.target.value }))}>
              <option value={HOME}>{t('The whole home')}</option>
              {folders.map((folder) => <option key={folder.value} value={folder.value}>{folder.label}</option>)}
              <option value={CUSTOM}>{t('Another folder…')}</option>
            </select>
          </div>
          {form.folder === CUSTOM && <div className="sftp-field">
            <label htmlFor="sftp-new-custom">{t('Folder below the home')}</label>
            <input id="sftp-new-custom" value={form.custom} placeholder="example.com/public_html/uploads" spellCheck={false} autoComplete="off"
              onChange={(e) => setForm((prev) => ({ ...prev, custom: e.target.value }))} />
          </div>}
          <div className="sftp-field">
            <label htmlFor="sftp-new-password">{t('Password')}</label>
            <input id="sftp-new-password" type="password" autoComplete="new-password" value={form.password}
              placeholder={t('Empty: one is generated')} onChange={(e) => setForm((prev) => ({ ...prev, password: e.target.value }))} />
          </div>
          <div className="sftp-account-go">
            <button type="submit" disabled={busy || full || !nameOk || !passwordOk || !directory || !stepUpReady}>
              <Plus size={14} aria-hidden="true"/> {t('Create account')}
            </button>
          </div>
          {full && <p className="hint">{t('This account has {count} SFTP accounts, the most it may have.', { count: data.max })}</p>}
        </form>}
    </section>
  </div>;
}
