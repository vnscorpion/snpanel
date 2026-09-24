import { Copy, Globe, KeyRound, Lock, Upload } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function SslPage() {
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
      manual: 'Manual SSL', cloudflare: 'Wildcard (Cloudflare)', shared: `Using ${currentSite?.ssl_source_domain || ''}`,
    };
    const sslLabel = currentSite?.ssl_enabled
      ? (sslLabels[currentSite?.ssl_mode] || 'SSL Enabled')
      : 'SSL Disabled';
    const sslUpdated = currentSite?.ssl_updated_at ? new Date(currentSite.ssl_updated_at).toLocaleString() : '';
    return <section className="section">
      <h2>SSL Certificate</h2>
      <WebsiteSelect />
      {currentSite && <div className="info-box" style={{marginTop:8}}>
        <strong>{currentSite.domain}</strong>
        <span className={currentSite.ssl_enabled ? 'badge ok' : 'badge'} style={{justifySelf:'start'}}>{sslLabel}</span>
        {sslUpdated && <span className="hint">Updated {sslUpdated}</span>}
        {currentSite.ssl_mode === 'manual' && currentSite.ssl_has_ca && <span className="badge ok" style={{justifySelf:'start'}}>CA Bundle</span>}
      </div>}
      <div className="segmented ssl-mode-tabs">
        <button className={sslMode === 'letsencrypt' ? 'active' : ''} onClick={() => setSslMode('letsencrypt')}><Lock size={14}/> Let's Encrypt</button>
        <button className={sslMode === 'manual' ? 'active' : ''} onClick={() => setSslMode('manual')}><KeyRound size={14}/> Manual</button>
        <button className={sslMode === 'wildcard' ? 'active' : ''} onClick={() => setSslMode('wildcard')}><Globe size={14}/> Wildcard (Cloudflare)</button>
        <button className={sslMode === 'shared' ? 'active' : ''} onClick={() => setSslMode('shared')}><Copy size={14}/> Use existing</button>
      </div>
      {sslMode === 'letsencrypt' && <>
        <button disabled={!selectedWebsiteId || !!loading} onClick={() => enableSsl(selectedWebsiteId)} style={{marginTop:8}}><Lock size={15}/> Install / Renew SSL</button>
        <p className="hint">The domain must point to the correct VPS IP before issuing SSL.</p>
      </>}
      {sslMode === 'wildcard' && <div className="ssl-sub-form">
        <p className="hint">
          Issues <code>{cfZone.zone ? `${cfZone.zone} + *.${cfZone.zone}` : 'zone + *.zone'}</code> over
          Cloudflare DNS. Needs an API token with <strong>Zone → DNS → Edit</strong> for the zone.
        </p>
        {cfZone.has_token
          ? <p className="hint">✓ Token saved for <strong>{cfZone.zone}</strong>. Leave the field blank to reuse it.</p>
          : null}
        <input type="password" autoComplete="off" placeholder="Cloudflare API token"
          value={wildcardToken} onChange={e => setWildcardToken(e.target.value)} />
        <button disabled={!selectedWebsiteId || !!loading} onClick={installWildcardSsl}>
          <Globe size={15}/> Issue wildcard certificate
        </button>
      </div>}
      {sslMode === 'shared' && <div className="ssl-sub-form">
        <p className="hint">Point this site at another SNPanel website's certificate (e.g. a wildcard). No new certificate is issued.</p>
        {sslSources.length === 0
          ? <p className="hint">No other website has a certificate that covers <strong>{currentSite?.domain}</strong>.</p>
          : <>
            <select value={sharedSource} onChange={e => setSharedSource(e.target.value)}>
              <option value="">Select a source website…</option>
              {sslSources.map(s => <option key={s.domain} value={s.domain}>
                {s.domain}{s.wildcard ? ' (wildcard)' : ''}{s.not_after ? ` — expires ${s.not_after}` : ''}
              </option>)}
            </select>
            <button disabled={!selectedWebsiteId || !sharedSource || !!loading} onClick={installSharedSsl}>
              <Copy size={15}/> Use this certificate
            </button>
          </>}
      </div>}
      {sslMode === 'manual' && <div className="manual-ssl-grid">
        <label>
          Certificate (.crt/.pem)
          <input type="file" accept=".crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, certificate: e.target.files?.[0] || null }))} />
        </label>
        <label>
          Private key (.key/.pem)
          <input type="file" accept=".key,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, private_key: e.target.files?.[0] || null }))} />
        </label>
        <label>
          CA bundle (.ca/.crt/.pem)
          <input type="file" accept=".ca,.crt,.pem" onChange={e => setManualSslFiles(prev => ({ ...prev, ca_bundle: e.target.files?.[0] || null }))} />
        </label>
        <textarea rows={7} disabled={!!manualSslFiles.certificate} value={manualSslForm.certificate} onChange={e => setManualSslForm(prev => ({ ...prev, certificate: e.target.value }))} placeholder="-----BEGIN CERTIFICATE-----" />
        <textarea rows={7} disabled={!!manualSslFiles.private_key} value={manualSslForm.private_key} onChange={e => setManualSslForm(prev => ({ ...prev, private_key: e.target.value }))} placeholder="-----BEGIN PRIVATE KEY-----" />
        <textarea rows={7} disabled={!!manualSslFiles.ca_bundle} value={manualSslForm.ca_bundle} onChange={e => setManualSslForm(prev => ({ ...prev, ca_bundle: e.target.value }))} placeholder="Optional CA bundle" />
        <button className="manual-ssl-submit" disabled={!selectedWebsiteId || !!loading} onClick={installManualSsl}><Upload size={15}/> Install Manual SSL</button>
      </div>}
    </section>;
  }

  return renderSsl();
}
