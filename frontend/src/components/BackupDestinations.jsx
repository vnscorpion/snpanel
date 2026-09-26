import { useState } from 'react';
import { CloudUpload, KeyRound, Network, Pencil, Plus, ShieldAlert, Trash2, Wifi, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './BackupDestinations.css';

const EMPTY = {
  sftp: { name: '', host: '', port: '22', username: '', password: '', private_key: '', remote_path: '/backups/snpanel' },
  s3: { name: '', endpoint: '', region: '', bucket: '', prefix: '', access_key: '', secret_key: '', path_style: false },
};

// Where backups are copied off this server - SFTP servers and S3 buckets in
// one list, added and edited in one form whose fields follow the type. The
// secrets never come back from the server: an edit that leaves them blank
// keeps the saved ones.
export default function BackupDestinations() {
  const {
    EmptyState,
    deleteS3Target,
    deleteSftpTarget,
    loading,
    s3Targets,
    saveS3Target,
    saveSftpTarget,
    sftpTargets,
    testS3Target,
    testSftpTarget,
  } = usePanel();
  const t = useT();
  const [kind, setKind] = useState('sftp');
  const [form, setForm] = useState(EMPTY.sftp);
  const [editing, setEditing] = useState(null);
  const busy = !!loading;
  const field = (key) => ({
    value: form[key],
    onChange: (e) => setForm((prev) => ({ ...prev, [key]: e.target.value })),
  });

  function pick(next) {
    if (editing || next === kind) return;
    setKind(next);
    setForm(EMPTY[next]);
  }

  function edit(type, target) {
    setKind(type);
    setEditing(target.id);
    setForm(type === 'sftp'
      ? { ...EMPTY.sftp, ...target, port: String(target.port || 22), password: '', private_key: '' }
      : { ...EMPTY.s3, ...target, secret_key: '' });
    document.getElementById('bk-dest-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function reset() {
    setEditing(null);
    setForm(EMPTY[kind]);
  }

  async function save(event) {
    event.preventDefault();
    const wasNew = !editing;
    const saved = kind === 'sftp'
      ? await saveSftpTarget(editing, {
        name: form.name.trim(),
        host: form.host.trim(),
        port: Number(form.port || 22),
        username: form.username.trim(),
        password: form.password || null,
        private_key: form.private_key || null,
        remote_path: form.remote_path.trim() || '/backups/snpanel',
      })
      : await saveS3Target(editing, form);
    if (!saved) return;
    reset();
    // A new destination is tried at once: a mistyped password is better
    // found now than by the first night's backup.
    if (wasNew) await (kind === 'sftp' ? testSftpTarget(saved) : testS3Target(saved));
  }

  const ready = kind === 'sftp'
    ? form.name.trim() && form.host.trim() && form.username.trim() && (editing || form.password || form.private_key.trim())
    : form.name.trim() && form.endpoint.trim() && form.bucket.trim() && form.access_key.trim() && (editing || form.secret_key.trim());
  const insecure = kind === 's3' && /^http:\/\//i.test(form.endpoint.trim());
  const keepHint = editing ? t('Leave blank to keep the saved one') : '';
  const rows = [
    ...sftpTargets.map((target) => ({ type: 'sftp', target })),
    ...s3Targets.map((target) => ({ type: 's3', target })),
  ];
  const editingName = editing ? rows.find((row) => row.type === kind && row.target.id === editing)?.target.name : '';

  return <div className="bk-dest">
    {rows.length === 0
      ? <EmptyState icon={CloudUpload} message={t('No destination yet. Add an SFTP server or an S3 bucket below.')} />
      : <ul className="bk-dest-list" aria-label={t('Destinations')}>
        {rows.map(({ type, target }) => <li key={`${type}-${target.id}`} className={editing === target.id && kind === type ? 'editing' : ''}>
          <span className={`bk-dest-type ${type}`}>{type === 'sftp' ? 'SFTP' : 'S3'}</span>
          <span className="bk-dest-text">
            <strong>{target.name}</strong>
            <small>{type === 'sftp'
              ? `${target.username}@${target.host}${Number(target.port) === 22 ? '' : `:${target.port}`} · ${target.remote_path}`
              : `s3://${target.bucket}${target.prefix ? `/${target.prefix}` : ''} · ${target.endpoint}${target.endpoint.startsWith('http://') ? ` · ${t('unencrypted')}` : ''}`}</small>
            {type === 'sftp' && target.host_key_fingerprint && <small className="bk-dest-key" title={target.host_key_fingerprint}>
              <KeyRound size={12} aria-hidden="true" /> {t('Host key saved: {type}', { type: target.host_key_type || 'ssh' })}
            </small>}
          </span>
          <span className="bk-dest-actions">
            <button type="button" className="secondary-light" disabled={busy} onClick={() => (type === 'sftp' ? testSftpTarget(target) : testS3Target(target))}
              aria-label={t('Test {name}', { name: target.name })}><Wifi size={14} /> {t('Test')}</button>
            <button type="button" className="secondary-light" disabled={busy} onClick={() => edit(type, target)}
              aria-label={t('Edit {name}', { name: target.name })}><Pencil size={14} /> {t('Edit')}</button>
            <button type="button" className="danger" disabled={busy} onClick={() => (type === 'sftp' ? deleteSftpTarget(target.id) : deleteS3Target(target.id))}
              aria-label={t('Delete {name}', { name: target.name })} title={t('Delete {name}', { name: target.name })}><Trash2 size={14} /></button>
          </span>
        </li>)}
      </ul>}

    <form id="bk-dest-form" className="bk-form bk-dest-form" onSubmit={save} aria-label={editing ? t('Edit {name}', { name: editingName }) : t('Add a destination')}>
      <div className="bk-dest-head bk-span-all">
        <h4>{editing ? t('Edit {name}', { name: editingName }) : t('Add a destination')}</h4>
        <div className="segmented-control bk-dest-kind" role="radiogroup" aria-label={t('Type')}>
          {[['sftp', t('SFTP server'), Network], ['s3', t('S3 bucket'), CloudUpload]].map(([id, label, Icon]) => <button
            key={id} type="button" role="radio" aria-checked={kind === id} className={kind === id ? 'active' : ''}
            disabled={!!editing && kind !== id} onClick={() => pick(id)}><Icon size={14} aria-hidden="true" />{label}</button>)}
        </div>
      </div>
      <div className="bk-field">
        <label htmlFor="bk-dest-name">{t('Name')}</label>
        <input id="bk-dest-name" {...field('name')} placeholder={t('Offsite')} autoComplete="off" />
      </div>

      {kind === 'sftp' && <>
        <div className="bk-field bk-span-2">
          <label htmlFor="bk-dest-host">{t('Host')}</label>
          <input id="bk-dest-host" {...field('host')} placeholder="backup.example.com" autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-port">{t('Port')}</label>
          <input id="bk-dest-port" {...field('port')} placeholder="22" inputMode="numeric" autoComplete="off" />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-user">{t('Username')}</label>
          <input id="bk-dest-user" {...field('username')} autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-password">{t('Password')}</label>
          <input id="bk-dest-password" type="password" {...field('password')} autoComplete="new-password" placeholder={keepHint} />
        </div>
        <div className="bk-field bk-span-2">
          <label htmlFor="bk-dest-path">{t('Remote folder')}</label>
          <input id="bk-dest-path" {...field('remote_path')} placeholder="/backups/snpanel" spellCheck={false} />
        </div>
        <div className="bk-field bk-span-all">
          <label htmlFor="bk-dest-key">{t('Private key (optional)')}</label>
          <textarea id="bk-dest-key" {...field('private_key')} rows={3} spellCheck={false} placeholder={keepHint} aria-describedby="bk-dest-key-hint" />
          <p className="hint" id="bk-dest-key-hint">{t('Sign in with a password, a private key, or both.')}</p>
        </div>
      </>}

      {kind === 's3' && <>
        <div className="bk-field bk-span-2">
          <label htmlFor="bk-dest-endpoint">{t('Endpoint')}</label>
          <input id="bk-dest-endpoint" {...field('endpoint')} placeholder="https://s3.amazonaws.com" autoComplete="off" spellCheck={false} aria-describedby="bk-dest-endpoint-hint" />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-region">{t('Region')}</label>
          <input id="bk-dest-region" {...field('region')} placeholder="us-east-1" autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-bucket">{t('Bucket')}</label>
          <input id="bk-dest-bucket" {...field('bucket')} placeholder="my-backups" autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-prefix">{t('Folder (optional)')}</label>
          <input id="bk-dest-prefix" {...field('prefix')} placeholder="snpanel" autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-access">{t('Access key')}</label>
          <input id="bk-dest-access" {...field('access_key')} autoComplete="off" spellCheck={false} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-dest-secret">{t('Secret key')}</label>
          <input id="bk-dest-secret" type="password" {...field('secret_key')} autoComplete="new-password" placeholder={keepHint} />
        </div>
        <label className="bk-check bk-span-all">
          <input type="checkbox" checked={!!form.path_style} onChange={(e) => setForm((prev) => ({ ...prev, path_style: e.target.checked }))} />
          <span>{t('Path-style addressing')}<small>{t('For MinIO, Ceph and most self-hosted stores, and any endpoint given as an IP address.')}</small></span>
        </label>
        <p className="hint bk-span-all" id="bk-dest-endpoint-hint">{t('AWS: https://s3.<region>.amazonaws.com · Cloudflare R2: https://<account>.r2.cloudflarestorage.com, region auto · MinIO: http://host:9000, path-style.')}</p>
        {insecure && <p className="bk-warn bk-span-all" role="note"><ShieldAlert size={15} /> {t('Plain HTTP sends backups unencrypted. Use it only on a network you trust.')}</p>}
      </>}

      <div className="bk-actions bk-span-all">
        {editing && <button type="button" className="secondary" disabled={busy} onClick={reset}><X size={14} /> {t('Cancel')}</button>}
        <button type="submit" disabled={busy || !ready}><Plus size={14} /> {editing ? t('Save changes') : t('Add destination')}</button>
      </div>
    </form>
  </div>;
}
