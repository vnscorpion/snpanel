import { followInPanel, routeForPage } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './Settings.css';

// What keeps the account and the sites safe comes first; the rest is how
// the server and the panel are run.
const SECURITY_KEYS = ['firewall', 'waf', 'access-logs', 'security'];
const GROUPS = [
  ['security', msg('Security'), (key) => SECURITY_KEYS.includes(key)],
  ['system', msg('System'), (key) => !SECURITY_KEYS.includes(key)],
];

// Settings: a tile for each settings page this account may open - its icon
// on the left, its name and a line about it beside - in place of a submenu
// in the sidebar, grouped as OPanel groups them. Each page's header leads
// back here.
export default function SettingsPage() {
  const { navigateToPage, settingsNavItems } = usePanel();
  const t = useT();
  const items = settingsNavItems || [];
  return <section className="section settings-home" aria-labelledby="settings-home-title">
    <div className="settings-home-head">
      <h2 id="settings-home-title">{t('Settings')}</h2>
      <p className="hint">{t('Security, server and panel configuration.')}</p>
    </div>
    {GROUPS.map(([id, title, belongs]) => {
      const tiles = items.filter(([key]) => belongs(key));
      if (tiles.length === 0) return null;
      return <div className="settings-group" key={id}>
        <h3 className="settings-group-title">{t(title)}</h3>
        <ul className="settings-grid">
          {tiles.map(([key, label, Icon, about]) => <li key={key}>
            {/* Named by its name alone; the line under it describes it. */}
            <a className="settings-tile" href={routeForPage(key)} onClick={(event) => followInPanel(event, () => navigateToPage(key))}
              aria-labelledby={`settings-${key}-name`} aria-describedby={about ? `settings-${key}-about` : undefined}>
              <span className="settings-tile-icon"><Icon size={18} aria-hidden="true"/></span>
              <span className="settings-tile-text">
                <span className="settings-tile-label" id={`settings-${key}-name`}>{label}</span>
                {about && <small className="settings-tile-about" id={`settings-${key}-about`}>{about}</small>}
              </span>
            </a>
          </li>)}
        </ul>
      </div>;
    })}
  </section>;
}
