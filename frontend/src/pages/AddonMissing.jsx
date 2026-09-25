import { Boxes } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function AddonMissingPage() {
  const {
    EmptyState,
    applicationAddonInstalled,
    isAdmin,
    loading,
    navigateToPage,
  } = usePanel();
  const t = useT();

  function renderAddonMissing() {
    return <section className="section">
      <div className="section-title"><div><h2>{t('Applications')}</h2></div></div>
      <EmptyState
        icon={Boxes}
        message={applicationAddonInstalled
          ? t('Your package does not include Applications. Contact the administrator to upgrade.')
          : t('The Application addon is not installed on this server.')}
      />
      {isAdmin && !applicationAddonInstalled && <div className="site-app-form-actions">
        <button disabled={!!loading} onClick={() => navigateToPage('addons')}><Boxes size={14}/> {t('Go to Addons')}</button>
      </div>}
    </section>;
  }

  return renderAddonMissing();
}
