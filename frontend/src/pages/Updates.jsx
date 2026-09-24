import { FileText, RefreshCw, RotateCcw, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function UpdatesPage() {
  const {
    appVersion,
    isAdmin,
    loadUpdates,
    loading,
    osAutoUpdate,
    osUpdating,
    panelUpdateLog,
    panelUpdating,
    runOsUpdate,
    runPanelUpdate,
    saveOsAutoUpdate,
    setOsAutoUpdate,
    showUpdateLog,
    toggleUpdateLog,
    updatesStatus,
  } = usePanel();

  function renderUpdates() {
    if (!isAdmin) return <section className="section"><h2>Updates</h2><p className="hint">No permission.</p></section>;
    const statusText = updatesStatus?.stdout || updatesStatus?.stderr || 'Click View logs to load update logs.';
    const panelUpdate = updatesStatus?.panel || {};
    const updateKnown = typeof panelUpdate.update_available === 'boolean';
    const updateAvailable = panelUpdate.update_available === true;
    const panelBadge = updateAvailable ? 'Update available' : updateKnown ? 'Up to date' : 'Unknown';
    const panelBadgeClass = updateAvailable ? 'badge bad' : updateKnown ? 'badge ok' : 'badge';
    const currentPanelVersion = panelUpdate.current_version || appVersion || 'unknown';
    const latestPanelVersion = panelUpdate.latest_version || 'unknown';
    return <>
      <section className="section">
        <div className="section-title">
          <div><h2>Updates</h2><p className="hint">OS packages use apt; panel updates use <code>snpanel-update</code>.</p></div>
          <button className="secondary-light" disabled={!!loading} onClick={toggleUpdateLog}>{showUpdateLog ? <X size={14}/> : <FileText size={14}/>} {showUpdateLog ? 'Hide logs' : 'View logs'}</button>
        </div>
        <div className="info-box update-version-box">
          <div className="update-version-head"><strong>Panel release</strong><span className={panelBadgeClass}>{panelBadge}</span></div>
          <div className="update-version-grid">
            <span>Current <strong>v{currentPanelVersion}</strong></span>
            <span>Latest <strong>{latestPanelVersion === 'unknown' ? 'unknown' : `v${latestPanelVersion}`}</strong></span>
            <span>Checked <strong>{panelUpdate.last_checked_at || 'never'}</strong></span>
            <span>State file <strong>{panelUpdate.state_file || '/var/lib/snpanel/update-status.json'}</strong></span>
          </div>
          {panelUpdate.check_error && <p className="hint">Release check failed: {panelUpdate.check_error}</p>}
          {panelUpdate.last_update_status && <p className="hint">Last update: {panelUpdate.last_update_status}{panelUpdate.last_update_ref ? ` (${panelUpdate.last_update_ref})` : ''}{panelUpdate.last_update_finished_at ? ` at ${panelUpdate.last_update_finished_at}` : ''}</p>}
        </div>
        <div className="actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => loadUpdates(true)}><RefreshCw size={14}/> Check releases</button>
          <button disabled={!!loading || osUpdating} onClick={runOsUpdate}><RefreshCw size={14} className={osUpdating ? 'spin' : ''}/> {osUpdating ? 'Updating OS...' : 'Update OS now'}</button>
          <button disabled={!!loading || panelUpdating || !updateAvailable} onClick={runPanelUpdate}><RotateCcw size={14} className={panelUpdating ? 'spin' : ''}/> {panelUpdating ? 'Updating panel...' : 'Update panel now'}</button>
        </div>
        {showUpdateLog && <div className="info-box firewall-status update-log-box">
          <div className="update-log-head"><strong>Update logs</strong><button className="secondary-light" disabled={!!loading} onClick={() => loadUpdates(true)}><RefreshCw size={13}/> Refresh</button></div>
          <pre>{statusText}</pre>
        </div>}
        {(panelUpdating || (panelUpdate.progress_percent && panelUpdate.last_update_status && panelUpdate.last_update_status !== 'completed' && panelUpdate.last_update_status !== 'failed')) && (
          <div className="info-box firewall-status update-progress-box">
            <div className="update-progress-row">
              <span className={panelUpdate.last_update_status === 'failed' ? 'badge bad' : 'badge ok'}>
                {panelUpdating ? 'Running' : (panelUpdate.last_update_status === 'failed' ? 'Failed' : (panelUpdate.last_update_status || 'Idle'))}
              </span>
              <span className="update-progress-phase">{panelUpdate.progress_phase || ''}</span>
              <span className="update-progress-pct">{Number(panelUpdate.progress_percent) || 0}%</span>
            </div>
            <div className="progress-bar"><div className="progress-bar-fill" style={{ width: `${Number(panelUpdate.progress_percent) || 0}%` }} /></div>
            {panelUpdate.progress_message && <p className="hint update-progress-msg">{panelUpdate.progress_message}</p>}
            {panelUpdateLog.length > 0 && (
              <pre className="update-progress-log">{panelUpdateLog.join('\n')}</pre>
            )}
          </div>
        )}
      </section>
      <section className="section">
        <h2>Auto Update OS</h2>
        <div className="firewall-form updates-os-form">
          <label><span>Enabled</span><select value={osAutoUpdate.enabled ? 'on' : 'off'} onChange={e => setOsAutoUpdate(prev => ({ ...prev, enabled: e.target.value === 'on' }))}><option value="on">On</option><option value="off">Off</option></select></label>
          <label><span>Mode</span><select value={osAutoUpdate.mode} onChange={e => setOsAutoUpdate(prev => ({ ...prev, mode: e.target.value }))}><option value="security">Security</option><option value="all">All packages</option></select></label>
          <label><span>Auto reboot</span><select value={osAutoUpdate.auto_reboot ? 'on' : 'off'} onChange={e => setOsAutoUpdate(prev => ({ ...prev, auto_reboot: e.target.value === 'on' }))}><option value="off">Off</option><option value="on">On</option></select></label>
          <button disabled={!!loading} onClick={saveOsAutoUpdate}>Save OS auto update</button>
        </div>
      </section>
    </>;
  }

  return renderUpdates();
}
