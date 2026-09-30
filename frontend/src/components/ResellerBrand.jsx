import { useEffect, useState } from 'react';
import { ExternalLink, ImageUp, Save, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

// A reseller's white label: the name and logo its customers see, and the
// hostname (one of its own domains) they sign in at.
export default function ResellerBrand() {
  const t = useT();
  const { request, loading, setNotice, loadCurrentUser } = usePanel();
  const [brand, setBrand] = useState(null);
  const [form, setForm] = useState({ app_name: '', panel_host: '' });
  const [file, setFile] = useState(null);
  const busy = !!loading;

  function take(d) {
    setBrand(d);
    setForm({ app_name: d.app_name || '', panel_host: d.panel_host || '' });
  }
  useEffect(() => { request('/reseller/brand', { silent: true }).then(d => d && take(d)); }, []);
  if (!brand) return null;

  async function save(event) {
    event.preventDefault();
    const d = await request('/reseller/brand', { method: 'PUT', body: JSON.stringify({ app_name: form.app_name, panel_host: form.panel_host || null }) }, t('Saving the brand...'));
    if (d) { take(d); await loadCurrentUser?.({ clearOnUnauthorized: false }); }
  }
  async function upload() {
    if (!file) return;
    const body = new FormData();
    body.append('file', file);
    const d = await request('/reseller/brand/logo', { method: 'POST', body }, t('Uploading the logo...'));
    if (d) { take(d); setFile(null); setNotice(t('Logo saved.')); await loadCurrentUser?.({ clearOnUnauthorized: false }); }
  }
  async function removeLogo() {
    const d = await request('/reseller/brand/logo', { method: 'DELETE' }, t('Removing the logo...'));
    if (d) { take(d); await loadCurrentUser?.({ clearOnUnauthorized: false }); }
  }
  const certified = new Set(brand.domains_with_certificate || []);

  return <div className="user-tab-panel reseller-brand">
    <div className="section-title user-panel-title">
      <div><h2>{t('Branding')}</h2><p className="hint">{t('Your customers see your name and logo, and can sign in at a hostname of yours. The server\'s name is not shown to them.')}</p></div>
    </div>
    <form className="reseller-brand-form" onSubmit={save}>
      <label><span>{t('Panel name')}</span><input value={form.app_name} onChange={e => setForm({ ...form, app_name: e.target.value })} placeholder="My Hosting" maxLength={60} /></label>
      <label><span>{t('Panel hostname')}</span>
        <select value={form.panel_host} onChange={e => setForm({ ...form, panel_host: e.target.value })}>
          <option value="">{t('None (the server\'s)')}</option>
          {(brand.domains || []).map(d => <option key={d} value={d}>{d}{certified.has(d) ? '' : ` (${t('no SSL yet')})`}</option>)}
        </select>
      </label>
      <button type="submit" disabled={busy}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
    </form>
    {brand.panel_url && <p className="hint">{t('Your customers sign in at')} <a href={brand.panel_url} target="_blank" rel="noreferrer noopener">{brand.panel_url} <ExternalLink size={12} aria-hidden="true"/></a>
      {!certified.has(brand.panel_host) && ` · ${t('Issue an SSL certificate for this domain on the SSL page, or browsers will warn.')}`}</p>}
    <div className="reseller-logo">
      <div className="brand-preview">{brand.logo_url ? <img src={brand.logo_url} alt="" /> : <span className="hint">{t('No logo')}</span>}</div>
      <label><span>{t('Logo')}</span><input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml" onChange={e => setFile(e.target.files?.[0] || null)} /></label>
      <button type="button" disabled={busy || !file} onClick={upload}><ImageUp size={14} aria-hidden="true"/> {t('Upload logo')}</button>
      {brand.logo_url && <button type="button" className="secondary" disabled={busy} onClick={removeLogo}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>}
    </div>
  </div>;
}
