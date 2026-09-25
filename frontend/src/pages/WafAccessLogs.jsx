import { Download, ExternalLink, FileText, RefreshCw, Search, Trash2 } from 'lucide-react';
import { accessLogBadgeClass, accessLogCountryLabel, accessLogVerdictLabel, formatAccessLogTime } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { serverText, useT } from '../i18n/index.jsx';

export default function WafAccessLogsPage() {
  const t = useT();
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
        <div><h2>{t('Access Logs')}</h2><p className="hint">{t('Protected Nginx traffic across all websites.')}</p></div>
        <div className="access-log-icon-actions">
          <button className="secondary-light icon-button" disabled={!!loading} onClick={() => loadWafAccessLogs(wafAccessLogFilters, true)} aria-label={t('Refresh access logs')} title={t('Refresh access logs')}><RefreshCw size={15}/></button>
          <button className="secondary-light icon-button" onClick={() => selectedSite && window.open(websiteUrl(selectedSite), '_blank', 'noopener,noreferrer')} disabled={!selectedSite} aria-label={t('Open website')} title={t('Open website')}><ExternalLink size={15}/></button>
        </div>
      </div>
      <div className="access-log-panel">
        <div className="access-log-toolbar">
          <div className="access-log-toolbar-label"><strong>{t('Access Logs')}</strong><span>{entryLabel}</span></div>
          <button className="secondary-light" disabled={rows.length === 0} onClick={exportWafAccessLogs}><Download size={14}/> {t('Export')}</button>
          <button className="danger light" disabled={!!loading || websites.length === 0} onClick={clearWafAccessLogs}><Trash2 size={14}/> {t('Clear')}</button>
          <select value={wafAccessLogFilters.websiteId} onChange={e => updateWafAccessLogFilters({ websiteId: e.target.value }, true)}>
            <option value="">{t('All websites')}</option>
            {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
          </select>
          <select value={wafAccessLogFilters.verdict} onChange={e => updateWafAccessLogFilters({ verdict: e.target.value }, true)}>
            <option value="all">{t('All verdicts')}</option>
            <option value="block">{t('Blocked')}</option>
            <option value="allow">{t('Allowed')}</option>
            <option value="error">{t('Errors')}</option>
          </select>
          <input value={wafAccessLogFilters.query} onChange={e => updateWafAccessLogFilters({ query: e.target.value })} onKeyDown={e => { if (e.key === 'Enter') applyWafAccessLogFilters(); }} placeholder={t('Filter logs')} />
          <select value={wafAccessLogFilters.limit} onChange={e => updateWafAccessLogFilters({ limit: Number(e.target.value) }, true)}>
            <option value={50}>{t('50 / page')}</option>
            <option value={100}>{t('100 / page')}</option>
            <option value={200}>{t('200 / page')}</option>
            <option value={500}>{t('500 / page')}</option>
          </select>
          <select value={wafAccessLogFilters.refresh} onChange={e => updateWafAccessLogFilters({ refresh: Number(e.target.value) })}>
            <option value={0}>{t('Manual refresh')}</option>
            <option value={5}>{t('Refresh 5s')}</option>
            <option value={10}>{t('Refresh 10s')}</option>
            <option value={30}>{t('Refresh 30s')}</option>
          </select>
          <button disabled={!!loading} onClick={applyWafAccessLogFilters}><Search size={14}/> {t('Apply')}</button>
        </div>
        <div className="access-log-table-wrap">
          <table className="access-log-table">
            <thead>
              <tr>
                <th>{t('Verdict')}</th>
                <th>{t('Time')}</th>
                <th>{t('Site')}</th>
                <th>{t('Method')}</th>
                <th>{t('Path')}</th>
                <th>IP</th>
                <th>{t('Country')}</th>
                <th>{t('Reason')}</th>
                <th>{t('Status')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(item => <tr key={item.id}>
                <td data-label={t('Verdict')}><span className={accessLogBadgeClass(item.verdict)}>{t(accessLogVerdictLabel(item.verdict))}</span></td>
                <td data-label={t('Time')}><span className="access-log-time">{formatAccessLogTime(item.timestamp)}</span><small>{item.duration_ms || 0} ms</small></td>
                <td data-label={t('Site')}><span className="access-log-site">{item.domain}</span></td>
                <td data-label={t('Method')}>{item.method || '-'}</td>
                <td data-label={t('Path')}><code>{item.path || '-'}</code></td>
                <td data-label="IP"><span className="access-log-ip">{item.ip || '-'}</span></td>
                <td data-label={t('Country')}>{accessLogCountryLabel(item)}</td>
                <td data-label={t('Reason')}>{serverText(item.reason) || '-'}</td>
                <td data-label={t('Status')}>{item.status || '-'}</td>
              </tr>)}
            </tbody>
          </table>
          {rows.length === 0 && <EmptyState icon={FileText} message={t('No access log entries match these filters.')} />}
        </div>
        {(wafAccessLogs.missing || []).length > 0 && <p className="hint">{t('Missing log files: {list}', { list: wafAccessLogs.missing.join(', ') })}</p>}
      </div>
    </section>;
  }

  return renderWafAccessLogs();
}
