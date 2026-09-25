import { useEffect, useState } from 'react';
import { Bot, Boxes, Check, Copy, KeyRound, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';
import './Mcp.css';

const LIFETIMES = [30, 90, 180, 365];

// A text with a button that copies it.
function CopyBlock({ id, label, text }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {}
  }
  return <div className="mcp-copy">
    <div className="mcp-copy-head">
      <span id={id}>{label}</span>
      <button type="button" className="secondary-light mini" onClick={copy} aria-describedby={id}>
        {copied ? <Check size={14}/> : <Copy size={14}/>} {copied ? t('Copied') : t('Copy')}
      </button>
    </div>
    <pre aria-labelledby={id}>{text}</pre>
  </div>;
}

// Settings, AI assistants (MCP): the endpoint, making a token, and this
// account's tokens. A new token is shown once, with the configuration each
// assistant takes - it is not stored anywhere it could be shown again.
export default function McpPage() {
  const { EmptyState, createMcpToken, isAdmin, loadMcp, loading, mcpInfo, mcpTokens, navigateToPage, revokeMcpToken } = usePanel();
  const t = useT();
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [canWrite, setCanWrite] = useState(false);
  const [made, setMade] = useState(null);
  const busy = !!loading;

  useEffect(() => { setMade(null); }, []);

  const endpoint = `${window.location.origin}${mcpInfo?.endpoint_path || '/api/mcp'}`;
  const full = (mcpTokens || []).length >= (mcpInfo?.max_tokens || 10);

  async function create(event) {
    event.preventDefault();
    const data = await createMcpToken({ name: name.trim(), can_write: canWrite, expires_days: Number(days) });
    if (data?.token) {
      setMade(data);
      setName('');
      setCanWrite(false);
    }
  }

  if (mcpInfo && !mcpInfo.enabled) {
    return <section className="section mcp-page">
      <h2>{t('AI assistants (MCP)')}</h2>
      <EmptyState icon={Bot} message={t('The MCP addon is not installed on this panel.')} />
      {isAdmin && <div className="addon-missing-actions"><button type="button" onClick={() => navigateToPage('addons')}><Boxes size={14} aria-hidden="true"/> {t('Go to Addons')}</button></div>}
    </section>;
  }

  const header = `Authorization: Bearer ${made?.token || '<token>'}`;
  const configs = made ? [
    ['mcp-claude', t('Claude Code'), `claude mcp add --transport http snpanel ${endpoint} \\\n  --header "${header}"`],
    ['mcp-cursor', t('Cursor - ~/.cursor/mcp.json'), JSON.stringify({ mcpServers: { snpanel: { url: endpoint, headers: { Authorization: `Bearer ${made.token}` } } } }, null, 2)],
    ['mcp-vscode', t('VS Code - .vscode/mcp.json'), JSON.stringify({ servers: { snpanel: { type: 'http', url: endpoint, headers: { Authorization: `Bearer ${made.token}` } } } }, null, 2)],
  ] : [];

  return <section className="section mcp-page">
    <div className="mcp-head">
      <div>
        <h2>{t('AI assistants (MCP)')}</h2>
        <p className="hint">{isAdmin
          ? t('Claude Code, Cursor, VS Code and other assistants can read and work this panel through the Model Context Protocol. A token acts as your account: as an administrator, on the whole server.')
          : t('Claude Code, Cursor, VS Code and other assistants can read and work your websites, databases, files and backups through the Model Context Protocol. A token acts as your account.')}</p>
      </div>
    </div>

    <CopyBlock id="mcp-endpoint" label={t('Endpoint')} text={endpoint} />
    {window.location.protocol !== 'https:' && <p className="mcp-warn" role="note"><ShieldAlert size={15}/> {t('This panel is not on HTTPS. Assistants only connect over HTTPS with a certificate they trust - give the panel a real one first.')}</p>}

    {made && <div className="mcp-made" role="status">
      <h3><KeyRound size={16}/> {t('Token {name} is ready', { name: made.name })}</h3>
      <p className="hint">{t('Copy it now: it is shown this once. Anyone who has it can act as your account until it expires or is revoked.')}</p>
      <CopyBlock id="mcp-token" label={t('Token')} text={made.token} />
      {configs.map(([id, label, text]) => <CopyBlock key={id} id={id} label={label} text={text} />)}
      <div className="mcp-actions"><button type="button" className="secondary-light" onClick={() => setMade(null)}>{t('Done')}</button></div>
    </div>}

    <form className="mcp-form" onSubmit={create} aria-label={t('New token')}>
      <div className="mcp-field">
        <label htmlFor="mcp-name">{t('Name')}</label>
        <input id="mcp-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} placeholder={t('My laptop')} autoComplete="off" />
      </div>
      <div className="mcp-field">
        <label htmlFor="mcp-days">{t('Expires after')}</label>
        <select id="mcp-days" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {LIFETIMES.map((d) => <option key={d} value={d}>{t('{count} days', { count: d })}</option>)}
        </select>
      </div>
      <label className="mcp-check">
        <input type="checkbox" checked={canWrite} onChange={(e) => setCanWrite(e.target.checked)} />
        <span>{t('Allow actions')}<small>{t('Without it the assistant can only read. With it, it can write files, issue certificates and more - everything is in the audit log.')}</small></span>
      </label>
      <div className="mcp-actions">
        <button type="submit" disabled={busy || !name.trim() || full}><Plus size={14}/> {t('Create token')}</button>
      </div>
      {full && <p className="hint mcp-full">{t('An account has at most {count} tokens; revoke one to make another.', { count: mcpInfo?.max_tokens || 10 })}</p>}
    </form>

    <h3 className="mcp-list-title">{t('Your tokens')}</h3>
    {(mcpTokens || []).length === 0 && <EmptyState icon={KeyRound} message={t('No tokens yet.')} />}
    <div className="backup-list mcp-tokens">
      {(mcpTokens || []).map((token) => <div className={`backup-item${token.expired ? ' mcp-expired' : ''}`} key={token.id}>
        <span>{token.name} <code>{token.prefix}…</code>
          <small>
            {token.can_write ? <span className="badge warn">{t('Actions allowed')}</span> : <span className="badge">{t('Read only')}</span>}
            {' '}{token.expired ? t('Expired {date}', { date: token.expires_at.slice(0, 10) }) : t('Expires {date}', { date: token.expires_at.slice(0, 10) })}
            {' · '}{token.last_used_at ? t('Last used {date}', { date: token.last_used_at.replace('T', ' ').slice(0, 16) }) : t('Never used')}
          </small>
        </span>
        <button className="danger" disabled={busy} onClick={() => revokeMcpToken(token)} aria-label={t('Revoke {name}', { name: token.name })} title={t('Revoke {name}', { name: token.name })}><Trash2 size={14}/></button>
      </div>)}
    </div>
    <div className="mcp-actions"><button type="button" className="secondary-light" disabled={busy} onClick={loadMcp}>{t('Refresh')}</button></div>
  </section>;
}
