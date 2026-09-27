import { useEffect } from 'react';
import { KeyRound, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import '../pages/Mcp.css';

// The MCP addon's card on the Addons page: every account's tokens, for an
// administrator to see who has one and to revoke any - or all of them.
export default function McpTokens() {
  const { loadAllMcpTokens, loading, mcpAllTokens, revokeAllMcpTokens, revokeMcpToken } = usePanel();
  const t = useT();
  const busy = !!loading;
  useEffect(() => { loadAllMcpTokens(); }, []);
  const tokens = mcpAllTokens || [];

  return <div className="mcp-panel">
    <div className="mcp-panel-head">
      <strong>{t('Tokens on this panel ({count})', { count: tokens.length })}</strong>
      {tokens.length > 0 && <button className="danger" disabled={busy} onClick={revokeAllMcpTokens}><Trash2 size={14}/> {t('Revoke all')}</button>}
    </div>
    {tokens.length === 0 && <p className="hint">{t('Nobody has made a token yet.')}</p>}
    <div className="backup-list mcp-tokens">
      {tokens.map((token) => <div className={`backup-item${token.expired ? ' mcp-expired' : ''}`} key={token.id}>
        <span><KeyRound size={13}/> {token.owner} · {token.name} <code>{token.prefix}…</code>
          <small>
            {token.can_write ? <span className="badge warn">{t('Actions allowed')}</span> : <span className="badge">{t('Read only')}</span>}
            {' '}{token.expired ? t('Expired {date}', { date: token.expires_at.slice(0, 10) }) : t('Expires {date}', { date: token.expires_at.slice(0, 10) })}
            {' · '}{token.last_used_at ? t('Last used {date}', { date: token.last_used_at.replace('T', ' ').slice(0, 16) }) : t('Never used')}
          </small>
        </span>
        <button className="danger" disabled={busy} onClick={() => revokeMcpToken(token, true)} aria-label={t('Revoke {name}', { name: token.name })} title={t('Revoke {name}', { name: token.name })}><Trash2 size={14}/></button>
      </div>)}
    </div>
  </div>;
}
