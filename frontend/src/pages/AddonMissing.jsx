import { Boxes } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function AddonMissingPage() {
  const {
    EmptyState,
    applicationAddonInstalled,
    isAdmin,
    loading,
    navigateToPage,
  } = usePanel();

  function renderAddonMissing() {
    return <section className="section">
      <div className="section-title"><div><h2>Applications</h2></div></div>
      <EmptyState
        icon={Boxes}
        message={applicationAddonInstalled
          ? 'Gói của bạn chưa có tính năng Application. Liên hệ quản trị để nâng cấp.'
          : 'Addon Application chưa được cài trên server này.'}
      />
      {isAdmin && !applicationAddonInstalled && <div className="site-app-form-actions">
        <button disabled={!!loading} onClick={() => navigateToPage('addons')}><Boxes size={14}/> Đi tới Addons</button>
      </div>}
    </section>;
  }

  return renderAddonMissing();
}
