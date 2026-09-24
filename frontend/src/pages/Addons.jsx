import { AlertCircle, Boxes, Download, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function AddonsPage() {
  const {
    EmptyState,
    addons,
    loadAddons,
    loading,
    navigateToPage,
    setAddonInstalled,
  } = usePanel();

  function renderAddons() {
    return <section className="section">
      <div className="section-title">
        <div>
          <h2>Addons</h2>
          <p className="hint">
            Những phần không nằm trong bản cài mặc định. Cài khi cần, gỡ lúc không dùng —
            gỡ chỉ tắt tính năng, không xoá dữ liệu đã tạo.
          </p>
        </div>
        <button className="secondary-light" disabled={!!loading} onClick={loadAddons}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="addon-list">
        {addons.items.map(addon => <div className={`addon-card ${addon.installed ? 'installed' : ''}`} key={addon.slug}>
          <div className="addon-head">
            <strong>{addon.name}</strong>
            <code>v{addon.installed ? (addon.installed_version || addon.version) : addon.version}</code>
            <span className={`badge ${addon.installed ? 'ok' : ''}`}>{addon.installed ? 'Đã cài' : 'Chưa cài'}</span>
            {addon.installed && addon.installed_version && addon.installed_version !== addon.version
              && <span className="badge">Có bản v{addon.version}</span>}
          </div>
          <p className="addon-summary">{addon.summary}</p>
          {addon.details?.length > 0 && <ul className="addon-details">
            {addon.details.map((line, index) => <li key={index}>{line}</li>)}
          </ul>}
          {addon.notes?.length > 0 && <div className="addon-notes">
            <strong><AlertCircle size={13}/> Cần biết trước khi bật</strong>
            <ul>{addon.notes.map((line, index) => <li key={index}>{line}</li>)}</ul>
          </div>}
          {addons.can_manage && <div className="addon-actions">
            {addon.installed
              ? <>
                  {addon.slug === 'application' && <button className="secondary-light" disabled={!!loading} onClick={() => navigateToPage('applications')}>Mở {addon.name}</button>}
                  <button className="danger" disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, false)}><Trash2 size={14}/> Gỡ</button>
                </>
              : <button disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, true)}><Download size={14}/> Cài</button>}
          </div>}
        </div>)}
        {addons.loaded && addons.items.length === 0 && <EmptyState icon={Boxes} message="Chưa có addon nào." />}
      </div>
    </section>;
  }

  return renderAddons();
}
