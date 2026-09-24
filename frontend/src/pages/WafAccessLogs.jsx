import { Download, ExternalLink, FileText, RefreshCw, Search, Trash2 } from 'lucide-react';
import { accessLogBadgeClass, accessLogCountryLabel, accessLogVerdictLabel, formatAccessLogTime } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';

export default function WafAccessLogsPage() {
  const {
    EmptyState,
    applyWafAccessLogFilters,
    clearWafAccessLogs,
    exportWafAccessLogs,
    loadWafAccessLogs,
    loading,
    updateWafAccessLogFilters,
    wafAccessLogFilters,
    wafAccessLogs,
    websiteUrl,
    websites,
  } = usePanel();

  function renderWafAccessLogs() {
    const rows = wafAccessLogs.items || [];
    const selectedSite = websites.find(site => String(site.id) === String(wafAccessLogFilters.websiteId));
    const entryLabel = wafAccessLogs.total >= 1000 ? `${(wafAccessLogs.total / 1000).toFixed(1)}k entries` : `${wafAccessLogs.total || 0} entries`;
    return <section className="section access-logs-section">
      <div className="section-title access-logs-title">
        <div><h2>Access Logs</h2><p className="hint">Protected Nginx traffic across all websites.</p></div>
        <div className="access-log-icon-actions">
          <button className="secondary-light icon-button" disabled={!!loading} onClick={() => loadWafAccessLogs(wafAccessLogFilters, true)} aria-label="Refresh access logs" title="Refresh access logs"><RefreshCw size={15}/></button>
          <button className="secondary-light icon-button" onClick={() => selectedSite && window.open(websiteUrl(selectedSite), '_blank', 'noopener,noreferrer')} disabled={!selectedSite} aria-label="Open website" title="Open website"><ExternalLink size={15}/></button>
        </div>
      </div>
      <div className="access-log-panel">
        <div className="access-log-toolbar">
          <div className="access-log-toolbar-label"><strong>Access Logs</strong><span>{entryLabel}</span></div>
          <button className="secondary-light" disabled={rows.length === 0} onClick={exportWafAccessLogs}><Download size={14}/> Export</button>
          <button className="danger light" disabled={!!loading || websites.length === 0} onClick={clearWafAccessLogs}><Trash2 size={14}/> Clear</button>
          <select value={wafAccessLogFilters.websiteId} onChange={e => updateWafAccessLogFilters({ websiteId: e.target.value }, true)}>
            <option value="">All websites</option>
            {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
          </select>
          <select value={wafAccessLogFilters.verdict} onChange={e => updateWafAccessLogFilters({ verdict: e.target.value }, true)}>
            <option value="all">All verdicts</option>
            <option value="block">Blocked</option>
            <option value="allow">Allowed</option>
            <option value="error">Errors</option>
          </select>
          <input value={wafAccessLogFilters.query} onChange={e => updateWafAccessLogFilters({ query: e.target.value })} onKeyDown={e => { if (e.key === 'Enter') applyWafAccessLogFilters(); }} placeholder="Filter logs" />
          <select value={wafAccessLogFilters.limit} onChange={e => updateWafAccessLogFilters({ limit: Number(e.target.value) }, true)}>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
            <option value={200}>200 / page</option>
            <option value={500}>500 / page</option>
          </select>
          <select value={wafAccessLogFilters.refresh} onChange={e => updateWafAccessLogFilters({ refresh: Number(e.target.value) })}>
            <option value={0}>Manual refresh</option>
            <option value={5}>Refresh 5s</option>
            <option value={10}>Refresh 10s</option>
            <option value={30}>Refresh 30s</option>
          </select>
          <button disabled={!!loading} onClick={applyWafAccessLogFilters}><Search size={14}/> Apply</button>
        </div>
        <div className="access-log-table-wrap">
          <table className="access-log-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Time</th>
                <th>Site</th>
                <th>Method</th>
                <th>Path</th>
                <th>IP</th>
                <th>Country</th>
                <th>Reason</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(item => <tr key={item.id}>
                <td data-label="Verdict"><span className={accessLogBadgeClass(item.verdict)}>{accessLogVerdictLabel(item.verdict)}</span></td>
                <td data-label="Time"><span className="access-log-time">{formatAccessLogTime(item.timestamp)}</span><small>{item.duration_ms || 0} ms</small></td>
                <td data-label="Site"><span className="access-log-site">{item.domain}</span></td>
                <td data-label="Method">{item.method || '-'}</td>
                <td data-label="Path"><code>{item.path || '-'}</code></td>
                <td data-label="IP"><span className="access-log-ip">{item.ip || '-'}</span></td>
                <td data-label="Country">{accessLogCountryLabel(item)}</td>
                <td data-label="Reason">{item.reason || '-'}</td>
                <td data-label="Status">{item.status || '-'}</td>
              </tr>)}
            </tbody>
          </table>
          {rows.length === 0 && <EmptyState icon={FileText} message="No access log entries match these filters." />}
        </div>
        {(wafAccessLogs.missing || []).length > 0 && <p className="hint">Missing log files: {wafAccessLogs.missing.join(', ')}</p>}
      </div>
    </section>;
  }

  return renderWafAccessLogs();
}
