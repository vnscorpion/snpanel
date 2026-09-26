import { followInPanel, routeForPage } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Settings.css';

// Settings: a tile for each settings page this account may open - its icon
// and its name - in place of a submenu in the sidebar. Each page's header
// leads back here.
export default function SettingsPage() {
  const { navigateToPage, settingsNavItems } = usePanel();
  const t = useT();
  return <section className="settings-home" aria-label={t('Settings')}>
    <ul className="settings-grid">
      {(settingsNavItems || []).map(([key, label, Icon]) => <li key={key}>
        <a className="settings-tile" href={routeForPage(key)} onClick={(event) => followInPanel(event, () => navigateToPage(key))}>
          <span className="settings-tile-icon"><Icon size={19} aria-hidden="true"/></span>
          <span className="settings-tile-label">{label}</span>
        </a>
      </li>)}
    </ul>
  </section>;
}
