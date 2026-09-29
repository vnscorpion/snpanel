import { useEffect } from 'react';
import { Copy, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import '../pages/PanelSettings.css';

// A reseller's provisioning tokens: its own WHMCS reaches its customers and
// packages only (the administrator's are on Panel settings).
export default function ApiTokensPanel() {
  const t = useT();
  const {
    apiTokens, copyApiToken, createApiToken, createdApiToken, loadApiTokens, loading,
    newApiToken, revokeApiToken, setCreatedApiToken, setNewApiToken,
  } = usePanel();
  const busy = !!loading;
  useEffect(() => { loadApiTokens(); }, []);

  return <div className="user-tab-panel api-tokens-panel">
    <div className="section-title user-panel-title">
      <div><h2>{t('WHMCS')}</h2><p className="hint">{t('Make a token for your own WHMCS and paste it into its server’s Access Hash field. It reaches your customers and packages only.')}</p></div>
      <button type="button" className="secondary icon-button" disabled={busy} onClick={loadApiTokens} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
    </div>
    {createdApiToken && <div className="token-reveal" role="status">
      <label><span>{t('Your new token. Copy it now: it will not be shown again.')}</span>
        <input id="created-api-token" readOnly value={createdApiToken} onFocus={e => e.target.select()} spellCheck="false" /></label>
      <button type="button" disabled={busy} onClick={copyApiToken}><Copy size={14} aria-hidden="true"/> {t('Copy')}</button>
      <button type="button" className="secondary" onClick={() => setCreatedApiToken('')}>{t('Done')}</button>
    </div>}
    <form className="token-form" onSubmit={e => { e.preventDefault(); if (newApiToken.name.trim()) createApiToken(); }}>
      <label><span>{t('Name')}</span><input value={newApiToken.name} onChange={e => setNewApiToken(prev => ({ ...prev, name: e.target.value }))} placeholder="WHMCS" autoComplete="off" /></label>
      <label><span>{t('Allowed IPs')}</span><input value={newApiToken.allowed_ips} onChange={e => setNewApiToken(prev => ({ ...prev, allowed_ips: e.target.value }))} placeholder={t('Any IP')} spellCheck="false" autoComplete="off" /></label>
      <button type="submit" disabled={busy || !newApiToken.name.trim()}><Plus size={14} aria-hidden="true"/> {t('Create token')}</button>
    </form>
    <p className="hint">{t('Leave Allowed IPs empty to accept requests from any address. Separate several with commas: 203.0.113.4, 198.51.100.7')}</p>
    {apiTokens.length === 0
      ? <p className="empty-note">{t('No API tokens yet.')}</p>
      : <div className="data-table-wrap">
        <table className="data-table">
          <thead><tr>
            <th scope="col">{t('Name')}</th>
            <th scope="col">{t('Allowed IPs')}</th>
            <th scope="col">{t('Status')}</th>
            <th scope="col">{t('Last used')}</th>
            <th scope="col"><span className="sr-only">{t('Revoke')}</span></th>
          </tr></thead>
          <tbody>
            {apiTokens.map(token => <tr key={token.id}>
              <td><strong>{token.name}</strong></td>
              <td>{token.allowed_ips ? <code>{token.allowed_ips}</code> : <span className="data-table-muted">{t('Any IP')}</span>}</td>
              <td><span className={`badge ${token.is_active ? 'ok' : ''}`}>{token.is_active ? t('Active') : t('Revoked')}</span></td>
              <td>{token.last_used_at ? formatWhen(token.last_used_at) : <span className="data-table-muted">{t('Never')}</span>}</td>
              <td className="data-table-actions">
                {token.is_active && <button type="button" className="secondary icon-button danger-hover" disabled={busy} onClick={() => revokeApiToken(token)}
                  aria-label={t('Revoke {name}', { name: token.name })} title={t('Revoke {name}', { name: token.name })}><Trash2 size={15} aria-hidden="true"/></button>}
              </td>
            </tr>)}
          </tbody>
        </table>
      </div>}
  </div>;
}
