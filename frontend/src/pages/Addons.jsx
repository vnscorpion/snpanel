import { AlertCircle, Boxes, Download, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { serverText, useT } from '../i18n/index.jsx';
import { ADDON_META, addonIcon } from '../lib/addons.jsx';
import McpTokens from '../components/McpTokens.jsx';
import './Addons.css';

// One row per addon: what it is, whether it is on, and the button that
// changes that. What it does in detail, and what to know first, is one click
// further down rather than the whole page.
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

  return <section className="section">
    <div className="section-title">
      <div>
        <h2>{t('Addons')}</h2>
        <p className="hint">{t('Optional features. Uninstalling one turns it off and keeps what it made.')}</p>
      </div>
      <button className="secondary-light" disabled={!!loading} onClick={loadAddons}><RefreshCw size={14}/> {t('Refresh')}</button>
    </div>
    <div className="addon-rows">
      {addons.items.map(addon => {
        const Icon = addonIcon(addon.slug);
        const version = addon.installed ? (addon.installed_version || addon.version) : addon.version;
        const hasMore = addon.details?.length > 0 || addon.notes?.length > 0 || (addons.can_manage && addon.slug === 'mcp' && addon.installed);
        return <article className={`addon-row ${addon.installed ? 'installed' : ''}`} key={addon.slug}>
          <div className="addon-row-main">
            <span className="addon-row-icon"><Icon size={20} aria-hidden="true"/></span>
            <div className="addon-row-text">
              <div className="addon-row-head">
                <strong>{addon.name}</strong>
                <code>v{version}</code>
                <span className={`badge ${addon.installed ? 'ok' : ''}`}>{addon.installed ? t('Installed') : t('Not installed')}</span>
                {addon.installed && addon.installed_version && addon.installed_version !== addon.version
                  && <span className="badge">{t('v{version} available', { version: addon.version })}</span>}
              </div>
              <p className="addon-row-summary">{serverText(addon.summary)}</p>
            </div>
            {addons.can_manage && <div className="addon-row-actions">
              {addon.installed
                ? <>
                  {ADDON_META[addon.slug] && <button className="secondary-light" disabled={!!loading} onClick={() => navigateToPage(ADDON_META[addon.slug].page)}>{t('Open')}</button>}
                  <button className="secondary-light danger-hover" disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, false)}
                    aria-label={t('Uninstall {name}', { name: addon.name })} title={t('Uninstall {name}', { name: addon.name })}><Trash2 size={14} aria-hidden="true"/> <span className="addon-row-label">{t('Uninstall')}</span></button>
                </>
                : <button disabled={!!loading} onClick={() => setAddonInstalled(addon.slug, true)}><Download size={14} aria-hidden="true"/> {t('Install')}</button>}
            </div>}
          </div>
          {hasMore && <details className="addon-row-more">
            <summary>{addon.installed ? t('Details') : t('Details and what to know first')}</summary>
            {addon.details?.length > 0 && <ul className="addon-details">
              {addon.details.map((line, index) => <li key={index}>{serverText(line)}</li>)}
            </ul>}
            {addon.notes?.length > 0 && <div className="addon-notes">
              <strong><AlertCircle size={13} aria-hidden="true"/> {addon.installed ? t('Keep in mind') : t('Before you turn it on')}</strong>
              <ul>{addon.notes.map((line, index) => <li key={index}>{serverText(line)}</li>)}</ul>
            </div>}
            {addons.can_manage && addon.slug === 'mcp' && addon.installed && <McpTokens />}
          </details>}
        </article>;
      })}
      {addons.loaded && addons.items.length === 0 && <EmptyState icon={Boxes} message={t('No addons yet.')} />}
    </div>
  </section>;
}
