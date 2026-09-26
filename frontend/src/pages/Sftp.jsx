import { useEffect, useMemo, useState } from 'react';
import { Copy, FolderKey, KeyRound, Plus, Power, PowerOff, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Sftp.css';

const HOME = '.';
const CUSTOM = 'custom';
const MAIN = 'main';

// SFTP: every login the account has, in one list - its own first, marked
// Main, then the ones it made, each shut into one folder the way
// DirectAdmin's FTP accounts are. One way to change a password, one button
// to add a login; the current panel password is asked for only when it is
// needed. An administrator picks whose.
export default function SftpPage() {
  const { currentUser, isAdmin, loadSftpAccess, loading, request, setSftpPassword, switchSftpAccess, users, websites } = usePanel();
  const t = useT();
  const [ownerId, setOwnerId] = useState('');
  const owner = (isAdmin && ownerId ? users.find((u) => String(u.id) === String(ownerId)) : null) || currentUser;
  const self = owner?.id === currentUser?.id;
  const [main, setMain] = useState(null);
  const [subs, setSubs] = useState(null);
  const [open, setOpen] = useState(null);
  const [password, setPassword] = useState('');
  const [proof, setProof] = useState({ current_password: '', code: '' });
  const [form, setForm] = useState({ name: '', folder: HOME, custom: '' });
  const [shown, setShown] = useState(null);
  const [copied, setCopied] = useState(false);
  const busy = !!loading;

  async function load() {
    const [own, made] = await Promise.all([
      loadSftpAccess(owner.id),
      request(`/users/${owner.id}/sftp/accounts`, { silent: true }),
    ]);
    setMain(own);
    setSubs(made);
  }

  useEffect(() => {
    if (!owner?.id) return;
    setMain(null);
    setSubs(null);
    setShown(null);
    close();
    load();
  }, [owner?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  function close() {
    setOpen(null);
    setPassword('');
    setProof({ current_password: '', code: '' });
    setForm({ name: '', folder: HOME, custom: '' });
  }

  function toggle(which) {
    const next = open === which ? null : which;
    close();
    setOpen(next);
  }

  // What the server made is shown once; the list is read again either way.
  function took(answer, username) {
    if (!answer) return;
    setCopied(false);
    setShown(answer.password ? { username: answer.username || username, password: answer.password } : null);
    close();
    load();
  }

  const linux = subs?.owner || main?.username || owner?.username || '';
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

  const passwordOk = !password || (password.length >= 12 && !/[:\r\n]/.test(password));
  const proofOk = !self || (proof.current_password && (!owner?.totp_enabled || proof.code.trim().length >= 6));
  const asked = () => ({ ...(password ? { password } : { generate: true }), ...(self ? proof : {}) });

  async function changePassword(row) {
    if (row === MAIN) {
      took(await setSftpPassword(owner, asked()), main?.username);
    } else {
      took(await request(`/users/${owner.id}/sftp/accounts/${row.id}/password`,
        { method: 'POST', body: JSON.stringify(asked()) }, t('Setting a new password...')), row.username);
    }
  }

  async function add() {
    const directory = form.folder === CUSTOM ? form.custom.trim().replace(/^\/+|\/+$/g, '') : form.folder;
    took(await request(`/users/${owner.id}/sftp/accounts`,
      { method: 'POST', body: JSON.stringify({ name: form.name, directory, ...asked() }) }, t('Creating the SFTP account...')));
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

  if (!owner || !main) return <section className="section"><p className="hint">{t('Loading…')}</p></section>;
  const items = subs?.items || [];
  const active = main.active !== false;
  const host = window.location.hostname;
  const ports = (main.ports?.length ? main.ports : subs?.ports || []).join(', ') || '22';
  const full = subs && items.length >= subs.max;

  // The current panel password (and code) - asked for inside the form that
  // needs it, only when the account is the viewer's own.
  const proofFields = self && <>
    <div className="sftp-field">
      <label htmlFor="sftp-proof-password">{t('Current panel password')}</label>
      <input id="sftp-proof-password" type="password" autoComplete="current-password" value={proof.current_password}
        onChange={(e) => setProof((prev) => ({ ...prev, current_password: e.target.value }))} />
    </div>
    {owner.totp_enabled && <div className="sftp-field">
      <label htmlFor="sftp-proof-code">{t('Authenticator code')}</label>
      <input id="sftp-proof-code" inputMode="numeric" autoComplete="one-time-code" value={proof.code}
        onChange={(e) => setProof((prev) => ({ ...prev, code: e.target.value }))} />
    </div>}
  </>;

  const passwordForm = (row) => <form className="sftp-inline" aria-label={t('Change password')}
    onSubmit={(e) => { e.preventDefault(); changePassword(row); }}>
    <div className="sftp-field">
      <label htmlFor="sftp-new-password">{t('New password')}</label>
      <input id="sftp-new-password" type="password" autoComplete="new-password" value={password} placeholder={t('Empty: one is generated')}
        onChange={(e) => setPassword(e.target.value)} autoFocus />
    </div>
    {proofFields}
    <div className="sftp-inline-actions">
      <button type="submit" disabled={busy || !passwordOk || !proofOk}>{t('Save')}</button>
      <button type="button" className="secondary" onClick={close}>{t('Cancel')}</button>
    </div>
  </form>;

  return <section className="section sftp-page" aria-labelledby="sftp-title">
    <div className="section-title">
      <div>
        <h2 id="sftp-title">{t('SFTP accounts')}</h2>
        <p className="hint">{t('Connect with FileZilla, WinSCP or any SFTP app - host {host}, port {port}. Each account sees only its own folder.', { host, port: ports })}</p>
      </div>
      {isAdmin && users.length > 1 && <div className="sftp-owner">
        <label htmlFor="sftp-owner">{t('Account')}</label>
        <select id="sftp-owner" value={owner.id} onChange={(e) => setOwnerId(e.target.value)}>
          {users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
        </select>
      </div>}
    </div>

    {shown && <div className="sftp-shown" role="status">
      <span>{t('Password of {name}:', { name: shown.username })}</span>
      <code>{shown.password}</code>
      <button type="button" className="mini secondary-light" onClick={copy}><Copy size={13} aria-hidden="true"/> {copied ? t('Copied') : t('Copy')}</button>
      <small>{t('Shown this once. Copy it now.')}</small>
    </div>}
    {!active && <p className="hint">{t('The account is suspended: SFTP stays locked until it is let back in.')}</p>}

    <ul className="sftp-list">
      <li className={main.enabled ? '' : 'off'}>
        <FolderKey size={16} aria-hidden="true"/>
        <div className="sftp-row-text">
          <strong><code>{main.username}</code> <span className="badge">{t('Main')}</span>{!main.enabled && <> <span className="badge">{t('Off')}</span></>}</strong>
          <small>{main.own_password ? t('The whole home · a password of its own') : t('The whole home · the panel password')}</small>
        </div>
        <div className="sftp-row-actions">
          {main.enabled && active && <button type="button" className="secondary-light" disabled={busy} onClick={() => toggle(MAIN)}
            aria-expanded={open === MAIN}><KeyRound size={14} aria-hidden="true"/> {t('Change password')}</button>}
          {!main.enabled && isAdmin && active && <button type="button" disabled={busy}
            onClick={async () => took(await switchSftpAccess(owner, true, { generate: true }), main.username)}><Power size={14} aria-hidden="true"/> {t('Turn on')}</button>}
          {main.enabled && isAdmin && <button type="button" className="secondary-light icon-button danger-hover" disabled={busy}
            onClick={async () => { const data = await switchSftpAccess(owner, false); if (data) load(); }}
            aria-label={t('Turn SFTP off')} title={t('Turn SFTP off')}><PowerOff size={14} aria-hidden="true"/></button>}
          {!main.enabled && !isAdmin && <small className="hint">{t('Ask an administrator to turn it on.')}</small>}
        </div>
        {open === MAIN && passwordForm(MAIN)}
      </li>
      {items.map((account) => <li key={account.id}>
        <FolderKey size={16} aria-hidden="true"/>
        <div className="sftp-row-text">
          <strong><code>{account.username}</code></strong>
          <small>{account.directory === HOME ? t('The whole home') : t('Folder: {folder}', { folder: account.directory })}</small>
        </div>
        <div className="sftp-row-actions">
          {active && <button type="button" className="secondary-light" disabled={busy} onClick={() => toggle(account.id)}
            aria-expanded={open === account.id}><KeyRound size={14} aria-hidden="true"/> {t('Change password')}</button>}
          <button type="button" className="danger icon-button" disabled={busy} onClick={() => remove(account)}
            aria-label={t('Delete {name}', { name: account.username })} title={t('Delete {name}', { name: account.username })}><Trash2 size={14} aria-hidden="true"/></button>
        </div>
        {open === account.id && passwordForm(account)}
      </li>)}
    </ul>

    {active && open !== 'add' && <div className="sftp-add">
      <button type="button" className="secondary" disabled={busy || full} onClick={() => toggle('add')}><Plus size={14} aria-hidden="true"/> {t('Add an SFTP account')}</button>
      {full && <small className="hint">{t('This account has {count} SFTP accounts, the most it may have.', { count: subs.max })}</small>}
    </div>}
    {active && open === 'add' && <form className="sftp-inline sftp-add-form" aria-label={t('New SFTP account')}
      onSubmit={(e) => { e.preventDefault(); add(); }}>
      <div className="sftp-field">
        <label htmlFor="sftp-add-name">{t('Name')}</label>
        <span className="sftp-name"><span aria-hidden="true">{linux}_</span>
          <input id="sftp-add-name" value={form.name} maxLength={16} autoComplete="off" spellCheck={false} placeholder="dev" autoFocus
            aria-describedby="sftp-add-name-hint"
            onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '') }))} />
        </span>
        <small id="sftp-add-name-hint" className="hint">{t('Signs in as {name}', { name: `${linux}_${form.name || '…'}` })}</small>
      </div>
      <div className="sftp-field">
        <label htmlFor="sftp-add-folder">{t('Folder')}</label>
        <select id="sftp-add-folder" value={form.folder} onChange={(e) => setForm((prev) => ({ ...prev, folder: e.target.value }))}>
          <option value={HOME}>{t('The whole home')}</option>
          {folders.map((folder) => <option key={folder.value} value={folder.value}>{folder.label}</option>)}
          <option value={CUSTOM}>{t('Another folder…')}</option>
        </select>
      </div>
      {form.folder === CUSTOM && <div className="sftp-field">
        <label htmlFor="sftp-add-custom">{t('Folder below the home')}</label>
        <input id="sftp-add-custom" value={form.custom} placeholder="example.com/public_html/uploads" spellCheck={false} autoComplete="off"
          onChange={(e) => setForm((prev) => ({ ...prev, custom: e.target.value }))} />
      </div>}
      <div className="sftp-field">
        <label htmlFor="sftp-add-password">{t('Password')}</label>
        <input id="sftp-add-password" type="password" autoComplete="new-password" value={password} placeholder={t('Empty: one is generated')}
          onChange={(e) => setPassword(e.target.value)} />
      </div>
      {proofFields}
      <div className="sftp-inline-actions">
        <button type="submit" disabled={busy || !/^[a-z0-9]{1,16}$/.test(form.name) || !passwordOk || !proofOk
          || (form.folder === CUSTOM && !form.custom.trim())}><Plus size={14} aria-hidden="true"/> {t('Create account')}</button>
        <button type="button" className="secondary" onClick={close}>{t('Cancel')}</button>
      </div>
    </form>}
  </section>;
}
