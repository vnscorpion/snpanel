import { AlertCircle, Boxes, Download, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';

// The page each addon opens, when it has one.
const ADDON_PAGE = { application: 'applications', fail2ban: 'fail2ban' };

// The catalogue's text comes from the API. Fail2ban's is English, marked here
// so the translation check knows it; the Application addon's is still the
// Python's Vietnamese and passes through t() as it is.
// eslint-disable-next-line no-unused-vars
const CATALOGUE_TEXT = [
  msg('Bans addresses that keep failing to sign in - to SSH, to the panel and to WordPress sites - in the server\'s firewall.'),
  msg('Installs fail2ban and runs it with jails for SSH, panel sign-ins, WordPress sign-ins and repeat offenders.'),
  msg('Bans are nftables rules beside the panel\'s firewall, and they lift by themselves when they expire.'),
  msg('The Fail2ban page sets how long a ban lasts, which jails run and which addresses are never banned.'),
  msg('The address you install it from is never banned. Add the other addresses you manage the server from on the Fail2ban page.'),
  msg('Cloudflare\'s addresses are never banned from a site\'s log: a site behind Cloudflare logs Cloudflare, not its visitors.'),
  msg('Open the Fail2ban page to choose the jails and the addresses that are never banned.'),
];

export default function AddonsPage() {
  const {
    EmptyState,
    addons,
    loadAddons,
    loading,
    navigateToPage,
    setAddonInstalled,
  } = usePanel();
  const t = useT();

  function renderAddons() {
    return <section className="section">
      <div className="section-title">
        <div>
          <h2>Addons</h2>
          <p className="hint">
            {t('Features that are not part of the default install. Install one when you need it and uninstall it when you do not - uninstalling only turns the feature off, it does not delete what it created.')}
          </p>
        </div>
        <button className="secondary-light" disabled={!!loading} onClick={loadAddons}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="addon-list">
        {addons.items.map(addon => <div className={`addon-card ${addon.installed ? 'installed' : ''}`} key={addon.slug}>
          <div className="addon-head">
            <strong>{addon.name}</strong>
            <code>v{addon.installed ? (addon.installed_version || addon.version) : addon.version}</code>
            <span className={`badge ${addon.installed ? 'ok' : ''}`}>{addon.installed ? t('Installed') : t('Not installed')}</span>
            {addon.installed && addon.installed_version && addon.installed_version !== addon.version
              && <span className="badge">{t('v{version} available', { version: addon.version })}</span>}
          </div>
          <p className="addon-summary">{t(addon.summary)}</p>
          {addon.details?.length > 0 && <ul className="addon-details">
            {addon.details.map((line, index) => <li key={index}>{t(line)}</li>)}
          </ul>}
          {addon.notes?.length > 0 && <div className="addon-notes">
            <strong><AlertCircle size={13}/> {t('Before you turn it on')}</strong>
            <ul>{addon.notes.map((line, index) => <li key={index}>{t(line)}</li>)}</ul>
          </div>}
          {addons.can_manage && <div className="addon-actions">
            {addon.installed
              ? <>
                  {ADDON_PAGE[addon.slug] && <button className="secondary-light" disabled={!!loading} onClick={() => navigateToPage(ADDON_PAGE[addon.slug])}>{t('Open {name}', { name: addon.name })}</button>}
                  <button className="danger" disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, false)}><Trash2 size={14}/> {t('Uninstall')}</button>
                </>
              : <button disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, true)}><Download size={14}/> {t('Install')}</button>}
          </div>}
        </div>)}
        {addons.loaded && addons.items.length === 0 && <EmptyState icon={Boxes} message={t('No addons yet.')} />}
      </div>
    </section>;
  }

  return renderAddons();
}
