import { useEffect, useMemo, useState } from 'react';
import { Bot, Boxes, Check, Copy, KeyRound, Plus, Search, ShieldAlert, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useLocale, useT } from '../i18n/index.jsx';
import './Mcp.css';

const LIFETIMES = [30, 90, 180, 365];

// Where the reference files each tool, in this order. The API names a tool's
// group; one this page does not know goes under "Other".
const GROUPS = ['account', 'websites', 'traffic', 'files', 'databases', 'backups', 'server', 'security', 'other'];

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

// The MCP tools' own words in the viewer's language: vi-mcp.js, loaded when
// the page is shown in Vietnamese. English until it arrives, and for any
// word it does not have.
function useToolWords() {
  const { locale } = useLocale();
  const [words, setWords] = useState(null);
  useEffect(() => {
    if (locale !== 'vi') { setWords(null); return undefined; }
    let live = true;
    import('../i18n/vi-mcp.js').then((m) => { if (live) setWords(m.default); }).catch(() => {});
    return () => { live = false; };
  }, [locale]);
  return (text) => (words && words[text]) || text;
}

// AI assistants (MCP): the endpoint, this account's tokens, how
// to connect an assistant, and everything an assistant can do with a token
// of this account - every tool its role may call, with its arguments. A new
// token is shown once; the connection snippets carry it until "Done", and a
// placeholder otherwise.
export default function McpPage() {
  const { EmptyState, createMcpToken, isAdmin, loadMcp, loadMcpTools, loading, mcpInfo, mcpTokens, mcpTools, navigateToPage, revokeMcpToken } = usePanel();
  const t = useT();
  const words = useToolWords();
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [canWrite, setCanWrite] = useState(false);
  const [made, setMade] = useState(null);
  const [find, setFind] = useState('');
  const busy = !!loading;

  useEffect(() => { setMade(null); }, []);
  useEffect(() => { loadMcpTools(); }, []);

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

  const tools = mcpTools?.tools || [];
  const groupLabels = {
    account: t('Account'),
    websites: t('Websites'),
    traffic: t('Logs and traffic'),
    files: t('Files'),
    databases: t('Databases'),
    backups: t('Backups'),
    server: t('Server'),
    security: t('Firewall and WAF'),
    other: t('Other'),
  };
  const needle = find.trim().toLowerCase();
  const shown = useMemo(() => tools.filter((tool) => !needle
    || [tool.name, tool.title, tool.description, words(tool.title), words(tool.description)]
      .some((text) => String(text).toLowerCase().includes(needle))), [tools, needle, words]);
  const grouped = GROUPS
    .map((group) => [group, shown.filter((tool) => (GROUPS.includes(tool.group) ? tool.group : 'other') === group)])
    .filter(([, list]) => list.length > 0);
  const counts = {
    reads: tools.filter((tool) => !tool.writes).length,
    writes: tools.filter((tool) => tool.writes).length,
    adminOnly: tools.filter((tool) => tool.admin_only).length,
  };

  if (mcpInfo && !mcpInfo.enabled) {
    return <section className="section mcp-page">
      <h2>{t('AI assistants (MCP)')}</h2>
      <EmptyState icon={Bot} message={t('The MCP addon is not installed on this panel.')} />
      {isAdmin && <div className="addon-missing-actions"><button type="button" onClick={() => navigateToPage('addons')}><Boxes size={14} aria-hidden="true"/> {t('Go to Addons')}</button></div>}
    </section>;
  }

  const token = made?.token || '<token>';
  const configs = [
    ['mcp-claude', t('Claude Code - in a terminal'), `claude mcp add --transport http snpanel ${endpoint} \\\n  --header "Authorization: Bearer ${token}"`],
    ['mcp-desktop', t('Claude Desktop - claude_desktop_config.json (needs Node.js)'), JSON.stringify({ mcpServers: { snpanel: { command: 'npx', args: ['-y', 'mcp-remote', endpoint, '--header', 'Authorization:${SNPANEL_AUTH}'], env: { SNPANEL_AUTH: `Bearer ${token}` } } } }, null, 2)],
    ['mcp-cursor', t('Cursor - ~/.cursor/mcp.json'), JSON.stringify({ mcpServers: { snpanel: { url: endpoint, headers: { Authorization: `Bearer ${token}` } } } }, null, 2)],
    ['mcp-vscode', t('VS Code - .vscode/mcp.json'), JSON.stringify({ servers: { snpanel: { type: 'http', url: endpoint, headers: { Authorization: `Bearer ${token}` } } } }, null, 2)],
    ['mcp-other', t('Any other client - Streamable HTTP'), `URL: ${endpoint}\nAuthorization: Bearer ${token}`],
  ];

  const kindOf = (param) => (param.type === 'integer' ? t('number') : param.type === 'boolean' ? t('true or false') : t('text'));
  const limitsOf = (param) => [
    param.choices?.length ? t('one of: {values}', { values: param.choices.join(', ') }) : '',
    param.minimum != null && param.maximum != null ? t('from {min} to {max}', { min: param.minimum, max: param.maximum }) : '',
  ].filter(Boolean).join(' · ');

  return <div className="mcp-page">
    <section className="section mcp-tokens-section">
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
        <p className="hint">{t('Copy it now: it is shown this once. Anyone who has it can act as your account until it expires or is revoked. The connection examples below carry it until you press Done.')}</p>
        <CopyBlock id="mcp-token" label={t('Token')} text={made.token} />
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
        {(mcpTokens || []).map((item) => <div className={`backup-item${item.expired ? ' mcp-expired' : ''}`} key={item.id}>
          <span>{item.name} <code>{item.prefix}…</code>
            <small>
              {item.can_write ? <span className="badge warn">{t('Actions allowed')}</span> : <span className="badge">{t('Read only')}</span>}
              {' '}{item.expired ? t('Expired {date}', { date: item.expires_at.slice(0, 10) }) : t('Expires {date}', { date: item.expires_at.slice(0, 10) })}
              {' · '}{item.last_used_at ? t('Last used {date}', { date: item.last_used_at.replace('T', ' ').slice(0, 16) }) : t('Never used')}
            </small>
          </span>
          <button className="danger" disabled={busy} onClick={() => revokeMcpToken(item)} aria-label={t('Revoke {name}', { name: item.name })} title={t('Revoke {name}', { name: item.name })}><Trash2 size={14}/></button>
        </div>)}
      </div>
      <div className="mcp-actions"><button type="button" className="secondary-light" disabled={busy} onClick={loadMcp}>{t('Refresh')}</button></div>
    </section>

    <section className="section mcp-connect" aria-labelledby="mcp-connect-title">
      <h2 id="mcp-connect-title">{t('Connect an assistant')}</h2>
      <p className="hint">{made
        ? t('These carry the token you just made.')
        : t('Make a token above, then put it in place of <token>. Each assistant is set up once; the token is what it signs in with.')}</p>
      <div className="mcp-connect-grid">
        {configs.map(([id, label, text]) => <CopyBlock key={id} id={id} label={label} text={text} />)}
      </div>
    </section>

    <section className="section mcp-docs" aria-labelledby="mcp-docs-title">
      <div className="mcp-docs-head">
        <div>
          <h2 id="mcp-docs-title">{t('What an assistant can do')}</h2>
          <p className="hint">{isAdmin
            ? t('Every tool a token of this account offers: {total}, of which {admin} only administrators have. As an administrator an assistant works on every account; a customer\'s token sees only that customer\'s websites.', { total: tools.length, admin: counts.adminOnly })
            : t('Every tool a token of this account offers: {total}. Each works only on this account\'s own websites, databases, files and backups.', { total: tools.length })}
          {' '}{t('A token without "Allow actions" is offered the {reads} that read; the {writes} that change something need it, and every change is in the audit log.', { reads: counts.reads, writes: counts.writes })}</p>
        </div>
        <label className="mcp-find">
          <Search size={15} aria-hidden="true"/>
          <input type="search" value={find} onChange={(e) => setFind(e.target.value)} placeholder={t('Find a tool')} aria-label={t('Find a tool')} />
        </label>
      </div>

      {tools.length > 0 && <nav className="mcp-groups" aria-label={t('Tool groups')}>
        {grouped.map(([group, list]) => <a key={group} href={`#mcp-group-${group}`}>{groupLabels[group]} <span>{list.length}</span></a>)}
      </nav>}
      {mcpTools?.loaded && tools.length === 0 && <EmptyState icon={Bot} message={t('No tools could be listed.')} />}
      {tools.length > 0 && shown.length === 0 && <EmptyState icon={Search} message={t('No tool matches {text}.', { text: find.trim() })} />}

      {grouped.map(([group, list]) => <section key={group} className="mcp-group" id={`mcp-group-${group}`} aria-labelledby={`mcp-group-${group}-title`}>
        <h3 id={`mcp-group-${group}-title`}>{groupLabels[group]}</h3>
        <div className="mcp-tool-grid">
          {list.map((tool) => <article key={tool.name} className="mcp-tool" id={`mcp-tool-${tool.name}`} aria-labelledby={`mcp-tool-${tool.name}-title`}>
            <header>
              <h4 id={`mcp-tool-${tool.name}-title`}>{words(tool.title)}</h4>
              <code>{tool.name}</code>
            </header>
            <div className="mcp-tool-badges">
              {tool.writes
                ? <span className="badge warn">{t('Changes something - needs "Allow actions"')}</span>
                : <span className="badge">{t('Reads only')}</span>}
              {tool.destructive && <span className="badge danger">{t('The assistant asks before it runs')}</span>}
              {tool.admin_only && <span className="badge mcp-admin">{t('Administrators only')}</span>}
            </div>
            <p>{words(tool.description)}</p>
            {tool.params.length === 0
              ? <p className="hint mcp-no-args">{t('Takes no arguments.')}</p>
              : <dl className="mcp-params">
                {tool.params.map((param) => <div key={param.name} className="mcp-param">
                  <dt>
                    <code>{param.name}</code>
                    <span className="mcp-param-kind">{kindOf(param)}</span>
                    {param.required && <span className="badge warn mcp-required">{t('required')}</span>}
                  </dt>
                  <dd>
                    {words(param.description)}
                    {limitsOf(param) && <small>{limitsOf(param)}</small>}
                  </dd>
                </div>)}
              </dl>}
          </article>)}
        </div>
      </section>)}
    </section>
  </div>;
}
