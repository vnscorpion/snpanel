import { useEffect, useState } from 'react';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './CloudLinux.css';

// CloudLinux's own UI (LVE Manager, Resource Usage, PHP Selector), served by
// the server at /cloudlinux/ and shown here in a frame. The panel asks for a
// one-view token; CloudLinux keeps it in its own cookie from then on.
export default function CloudLinuxPage({ plugin, title, about }) {
  const t = useT();
  const { request } = usePanel();
  const [url, setUrl] = useState('');
  const [failed, setFailed] = useState(false);

  async function open() {
    setFailed(false);
    setUrl('');
    const d = await request('/hosting/cloudlinux/session', { method: 'POST', body: JSON.stringify({ plugin }) });
    if (d?.url) setUrl(d.url);
    else setFailed(true);
  }

  useEffect(() => { open(); }, [plugin]);

  return <section className="section cloudlinux-page">
    <div className="section-title">
      <div><h2>{title}</h2>{about && <p className="hint">{about}</p>}</div>
      <div className="cloudlinux-actions">
        <button className="secondary-light" onClick={open}><RefreshCw size={15}/> {t('Reload')}</button>
        {url && <a className="button secondary-light" href={url} target="_blank" rel="noopener noreferrer" onClick={() => setTimeout(open, 500)}><ExternalLink size={15}/> {t('Open in a new tab')}</a>}
      </div>
    </div>
    {failed && <p className="hint">{t('CloudLinux Manager could not be opened.')}</p>}
    {url && <iframe className="cloudlinux-frame" title={title} src={url}/>}
  </section>;
}
