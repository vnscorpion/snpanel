import { useState } from 'react';
import { CloudUpload, Pencil, Plus, ShieldAlert, Trash2, Wifi, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

const EMPTY = { name: '', endpoint: '', region: '', bucket: '', prefix: '', access_key: '', secret_key: '', path_style: false };

// S3 backup destinations: AWS, Cloudflare R2, Backblaze B2, Wasabi, MinIO and
// anything else that speaks S3. The secret key never comes back from the
// server; editing a destination and leaving it blank keeps the saved one.
export default function S3Destinations() {
  const { EmptyState, deleteS3Target, loading, s3Targets, saveS3Target, testS3Target } = usePanel();
  const t = useT();
  const [form, setForm] = useState(EMPTY);
  const [editing, setEditing] = useState(null);
  const busy = !!loading;
  const field = (key) => ({
    value: form[key],
    onChange: (e) => setForm((prev) => ({ ...prev, [key]: e.target.value })),
  });

  function edit(target) {
    setEditing(target.id);
    setForm({ ...EMPTY, ...target, secret_key: '' });
  }

  function reset() {
    setEditing(null);
    setForm(EMPTY);
  }

  async function save(event) {
    event.preventDefault();
    const wasNew = !editing;
    const saved = await saveS3Target(editing, form);
    if (!saved) return;
    reset();
    // A new destination is tried at once: a mistyped key is better found
    // now than by the first night's backup.
    if (wasNew) await testS3Target(saved);
  }

  const insecure = /^http:\/\//i.test(form.endpoint.trim());
  const ready = form.name.trim() && form.endpoint.trim() && form.bucket.trim()
    && form.access_key.trim() && (editing || form.secret_key.trim());

  return <div className="bk-s3">
    <form className="bk-form bk-s3-form" onSubmit={save} aria-label={editing ? t('Edit S3 destination') : t('Add S3 destination')}>
      <div className="bk-field">
        <label htmlFor="s3-name">{t('Name')}</label>
        <input id="s3-name" {...field('name')} placeholder={t('Offsite')} autoComplete="off" />
      </div>
      <div className="bk-field bk-span-2">
        <label htmlFor="s3-endpoint">{t('Endpoint')}</label>
        <input id="s3-endpoint" {...field('endpoint')} placeholder="https://s3.amazonaws.com" autoComplete="off" spellCheck={false} aria-describedby="s3-endpoint-hint" />
      </div>
      <div className="bk-field">
        <label htmlFor="s3-region">{t('Region')}</label>
        <input id="s3-region" {...field('region')} placeholder="us-east-1" autoComplete="off" spellCheck={false} />
      </div>
      <div className="bk-field">
        <label htmlFor="s3-bucket">{t('Bucket')}</label>
        <input id="s3-bucket" {...field('bucket')} placeholder="my-backups" autoComplete="off" spellCheck={false} />
      </div>
      <div className="bk-field">
        <label htmlFor="s3-prefix">{t('Folder (optional)')}</label>
        <input id="s3-prefix" {...field('prefix')} placeholder="snpanel" autoComplete="off" spellCheck={false} />
      </div>
      <div className="bk-field">
        <label htmlFor="s3-access">{t('Access key')}</label>
        <input id="s3-access" {...field('access_key')} autoComplete="off" spellCheck={false} />
      </div>
      <div className="bk-field">
        <label htmlFor="s3-secret">{t('Secret key')}</label>
        <input id="s3-secret" type="password" {...field('secret_key')} autoComplete="new-password"
          placeholder={editing ? t('Leave blank to keep the saved key') : ''} />
      </div>
      <label className="bk-check bk-span-2">
        <input type="checkbox" checked={!!form.path_style} onChange={(e) => setForm((prev) => ({ ...prev, path_style: e.target.checked }))} />
        <span>{t('Path-style addressing')}<small>{t('For MinIO, Ceph and most self-hosted stores, and any endpoint given as an IP address.')}</small></span>
      </label>
      <p className="hint bk-span-all" id="s3-endpoint-hint">{t('AWS: https://s3.<region>.amazonaws.com · Cloudflare R2: https://<account>.r2.cloudflarestorage.com, region auto · MinIO: http://host:9000, path-style.')}</p>
      {insecure && <p className="bk-warn bk-span-all" role="note"><ShieldAlert size={15} /> {t('Plain HTTP sends backups unencrypted. Use it only on a network you trust.')}</p>}
      <div className="bk-actions bk-span-all">
        {editing && <button type="button" className="secondary" disabled={busy} onClick={reset}><X size={14} /> {t('Cancel')}</button>}
        <button type="submit" disabled={busy || !ready}><Plus size={14} /> {editing ? t('Save changes') : t('Add S3 destination')}</button>
      </div>
    </form>
    {s3Targets.length === 0 && <EmptyState icon={CloudUpload} message={t('No S3 destinations yet.')} />}
    <div className="backup-list">
      {s3Targets.map((target) => <div className="backup-item" key={target.id}>
        <span>{target.name}<small>
          s3://{target.bucket}{target.prefix ? `/${target.prefix}` : ''} · {target.endpoint}
          {target.endpoint.startsWith('http://') ? ` · ${t('unencrypted')}` : ''}
        </small></span>
        <div className="actions">
          <button disabled={busy} onClick={() => testS3Target(target)}><Wifi size={14} /> {t('Test')}</button>
          <button disabled={busy} onClick={() => edit(target)}><Pencil size={14} /> {t('Edit')}</button>
          <button className="danger" disabled={busy} onClick={() => deleteS3Target(target.id)}
            aria-label={t('Delete {name}', { name: target.name })} title={t('Delete {name}', { name: target.name })}><Trash2 size={14} /></button>
        </div>
      </div>)}
    </div>
  </div>;
}
