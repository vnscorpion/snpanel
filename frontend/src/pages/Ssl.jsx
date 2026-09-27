import { Copy, Globe, KeyRound, Lock, Upload } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function SslPage() {
  const t = useT();
  const {
    WebsiteSelect,
    cfZone,
    currentSite,
    enableSsl,
    installManualSsl,
    installSharedSsl,
    installWildcardSsl,
    loading,
    manualSslFiles,
    manualSslForm,
    selectedWebsiteId,
    setManualSslFiles,
    setManualSslForm,
    setSharedSource,
    setSslMode,
    setWildcardToken,
    sharedSource,
    sslMode,
    sslSources,
    wildcardToken,
  } = usePanel();

  function renderSsl() {
    const sslLabels = {
      manual: t('Manual SSL'), cloudflare: t('Wildcard (Cloudflare)'), shared: t('Using {domain}', { domain: currentSite?.ssl_source_domain || '' }),
    };
    const sslLabel = currentSite?.ssl_enabled
      ? (sslLabels[currentSite?.ssl_mode] || t('SSL Enabled'))
      : t('SSL Disabled');
    const sslUpdated = currentSite?.ssl_updated_at ? new Date(currentSite.ssl_updated_at).toLocaleString() : '';
    return <section className="section">
      <h2>{t('SSL Certificate')}</h2>
      <WebsiteSelect />
      {currentSite && <div className="info-box" style={{marginTop:8}}>
        <strong>{currentSite.domain}</strong>
        <span className={currentSite.ssl_enabled ? 'badge ok' : 'badge'} style={{justifySelf:'start'}}>{sslLabel}</span>
        {sslUpdated && <span className="hint">{t('Updated {when}', { when: sslUpdated })}</span>}
        {currentSite.ssl_mode === 'manual' && currentSite.ssl_has_ca && <span className="badge ok" style={{justifySelf:'start'}}>{t('CA Bundle')}</span>}
      </div>}
      <div className="segmented ssl-mode-tabs">
        <button className={sslMode === 'letsencrypt' ? 'active' : ''} onClick={() => setSslMode('letsencrypt')}><Lock size={14}/> {t('Let\'s Encrypt')}</button>
        <button className={sslMode === 'manual' ? 'active' : ''} onClick={() => setSslMode('manual')}><KeyRound size={14}/> {t('Manual')}</button>
        <button className={sslMode === 'wildcard' ? 'active' : ''} onClick={() => setSslMode('wildcard')}><Globe size={14}/> {t('Wildcard (Cloudflare)')}</button>
        <button className={sslMode === 'shared' ? 'active' : ''} onClick={() => setSslMode('shared')}><Copy size={14}/> {t('Use existing')}</button>
      </div>
      {sslMode === 'letsencrypt' && <div className="ssl-le">
        <p className="hint">{t('The domain must point to the correct VPS IP before issuing SSL.')}</p>
        {/* One short verb for what it will do to this site, not both. */}
        <button className="ssl-issue" disabled={!selectedWebsiteId || !!loading} onClick={() => enableSsl(selectedWebsiteId)}>
          <Lock size={14} aria-hidden="true"/> {currentSite?.ssl_enabled && (!currentSite.ssl_mode || currentSite.ssl_mode === 'letsencrypt') ? t('Renew SSL') : t('Install SSL')}
        </button>
      </div>}
      {sslMode === 'wildcard' && <div className="ssl-sub-form">
        <p className="hint">
          {t('Issues {names} over Cloudflare DNS. Needs an API token with {permission} for the zone.', { names: <code>{cfZone.zone ? `${cfZone.zone} + *.${cfZone.zone}` : 'zone + *.zone'}</code>, permission: <strong>{t('Zone → DNS → Edit')}</strong> })}
        </p>
        {cfZone.has_token
          ? <p className="hint">✓ {t('Token saved for {zone}. Leave the field blank to reuse it.', { zone: <strong>{cfZone.zone}</strong> })}</p>
          : null}
        <input type="password" autoComplete="off" placeholder={t('Cloudflare API token')}
          value={wildcardToken} onChange={e => setWildcardToken(e.target.value)} />
        <button disabled={!selectedWebsiteId || !!loading} onClick={installWildcardSsl}>
          <Globe size={15}/> {t('Issue wildcard certificate')}
        </button>
      </div>}
      {sslMode === 'shared' && <div className="ssl-sub-form">
        <p className="hint">{t('Point this site at another SNPanel website\'s certificate (e.g. a wildcard). No new certificate is issued.')}</p>
        {sslSources.length === 0
          ? <p className="hint">{t('No other website has a certificate that covers {domain}.', { domain: <strong>{currentSite?.domain}</strong> })}</p>
          : <>
            <select value={sharedSource} onChange={e => setSharedSource(e.target.value)}>
              <option value="">{t('Select a source website…')}</option>
              {sslSources.map(s => <option key={s.domain} value={s.domain}>
                {s.domain}{s.wildcard ? t(' (wildcard)') : ''}{s.not_after ? t(' — expires {not_after}', { not_after: s.not_after }) : ''}
              </option>)}
            </select>
            <button disabled={!selectedWebsiteId || !sharedSource || !!loading} onClick={installSharedSsl}>
              <Copy size={15}/> {t('Use this certificate')}
            </button>
          </>}
      </div>}
      {sslMode === 'manual' && <div className="manual-ssl-grid">
        <label>
          {t('Certificate (.crt/.pem)')}
          <input type="file" accept=".crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, certificate: e.target.files?.[0] || null }))} />
        </label>
        <label>
          {t('Private key (.key/.pem)')}
          <input type="file" accept=".key,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, private_key: e.target.files?.[0] || null }))} />
        </label>
        <label>
          {t('CA bundle (.ca/.crt/.pem)')}
          <input type="file" accept=".ca,.crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, ca_bundle: e.target.files?.[0] || null }))} />
        </label>
        <textarea rows={7} disabled={!!manualSslFiles.certificate} value={manualSslForm.certificate} onChange={e => setManualSslForm(prev => ({ ...prev, certificate: e.target.value }))} placeholder="-----BEGIN CERTIFICATE-----" />
        <textarea rows={7} disabled={!!manualSslFiles.private_key} value={manualSslForm.private_key} onChange={e => setManualSslForm(prev => ({ ...prev, private_key: e.target.value }))} placeholder="-----BEGIN PRIVATE KEY-----" />
        <textarea rows={7} disabled={!!manualSslFiles.ca_bundle} value={manualSslForm.ca_bundle} onChange={e => setManualSslForm(prev => ({ ...prev, ca_bundle: e.target.value }))} placeholder={t('Optional CA bundle')} />
        <button className="manual-ssl-submit" disabled={!selectedWebsiteId || !!loading} onClick={installManualSsl}><Upload size={15}/> {t('Install Manual SSL')}</button>
      </div>}
    </section>;
  }

  return renderSsl();
}
