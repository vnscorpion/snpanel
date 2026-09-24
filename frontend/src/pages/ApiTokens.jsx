import { Clock, Copy, KeyRound, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function ApiTokensPage() {
  const {
    EmptyState,
    apiTokens,
    copyApiToken,
    createApiToken,
    createdApiToken,
    isAdmin,
    loadApiTokens,
    loading,
    newApiToken,
    revokeApiToken,
    setCreatedApiToken,
    setNewApiToken,
  } = usePanel();

  function renderApiTokens() {
    if (!isAdmin) return <section className="section"><h2>API Tokens</h2><p className="hint">No permission.</p></section>;
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>API Tokens</h2><p className="hint">Create one token for WHMCS. Paste it into WHMCS Server → Access Hash.</p></div>
          <button disabled={!!loading} onClick={loadApiTokens}><RefreshCw size={14}/> Refresh</button>
        </div>
        {createdApiToken && <div className="user-create-card">
          <label><span>New token (copy now)</span><input id="created-api-token" readOnly value={createdApiToken} onFocus={e => e.target.select()} /></label>
          <button disabled={!!loading} onClick={copyApiToken}><Copy size={14}/> Copy token</button>
          <button className="secondary-light" onClick={() => setCreatedApiToken('')}>Hide</button>
        </div>}
        <div className="user-create-card">
          <label><span>Name</span><input value={newApiToken.name} onChange={e => setNewApiToken(prev => ({ ...prev, name: e.target.value }))} placeholder="WHMCS" /></label>
          <label><span>WHMCS server IP</span><input value={newApiToken.allowed_ips} onChange={e => setNewApiToken(prev => ({ ...prev, allowed_ips: e.target.value }))} placeholder="optional: 1.2.3.4 or 1.2.3.4, 5.6.7.8" /></label>
          <button disabled={!!loading || !newApiToken.name.trim()} onClick={createApiToken}><Plus size={14}/> Create token</button>
        </div>
        <p className="hint">Leave WHMCS server IP empty to allow all IPs. Multiple IPs: separate with comma.</p>
        <div className="package-list">
          {apiTokens.length === 0 && <EmptyState icon={KeyRound} message="No API tokens found." />}
          {apiTokens.map(token => <div className="package-row" key={token.id}>
            <div className="user-main"><strong>{token.name}</strong><small>{token.allowed_ips ? `Allowed IPs: ${token.allowed_ips}` : 'Allowed IPs: all'}</small></div>
            <span className="user-metric"><KeyRound size={13}/>{token.is_active ? 'Active' : 'Revoked'}</span>
            <span className="user-metric"><Clock size={13}/>{token.last_used_at ? new Date(token.last_used_at).toLocaleString() : 'Never used'}</span>
            <div className="row-actions">
              <button className="mini danger" disabled={!!loading || !token.is_active} onClick={() => revokeApiToken(token)}><Trash2 size={14}/> Revoke</button>
            </div>
          </div>)}
        </div>
      </section>
    </>;
  }

  return renderApiTokens();
}
