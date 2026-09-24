import { Archive, ArchiveRestore, Check, Clock, Database, Download, Globe, Network, Plus, RefreshCw, RotateCcw, Search, Trash2, Upload, Users, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function BackupsPage() {
  const {
    EmptyState,
    WebsiteSelect,
    backupJobs,
    backupSchedules,
    backupTab,
    backups,
    bulkDeleteDaBackups,
    bulkImportDaBackups,
    createBackup,
    createBackupSchedule,
    createSftpTarget,
    createUserBackup,
    daBackups,
    daBulkImportJob,
    daFileInputRef,
    daImportJob,
    daReplaceExisting,
    daScanResult,
    deleteBackup,
    deleteBackupSchedule,
    deleteDaBackup,
    deleteRestoreBackup,
    deleteSftpTarget,
    deleteUserBackup,
    downloadBackup,
    downloadUserBackup,
    importDaBackup,
    isAdmin,
    listDaBackups,
    listUserBackups,
    loadRestoreBackups,
    loadSftpTargets,
    loading,
    newBackupSchedule,
    newSftpTarget,
    refreshBackupArea,
    refreshScheduledBackupArea,
    refreshUserBackupArea,
    restoreBackup,
    restoreBackupDir,
    restoreBackups,
    restoreUserBackup,
    scanDaBackup,
    selectedBackupUserId,
    selectedDaBackups,
    selectedSftpTargetId,
    selectedWebsiteId,
    setBackupTab,
    setDaReplaceExisting,
    setNewBackupSchedule,
    setNewSftpTarget,
    setSelectedBackupUserId,
    setSelectedSftpTargetId,
    sftpTargets,
    toggleDaBackupSelect,
    toggleSelectAllDaBackups,
    uploadBackup,
    uploadDaBackup,
    uploadUserBackups,
    userBackups,
    users,
  } = usePanel();

  function renderBackups() {
    const selectedBackupUser = users.find(user => String(user.id) === String(selectedBackupUserId));
    const userNameById = id => users.find(user => String(user.id) === String(id))?.username || `User #${id}`;
    const scheduleUserLabel = item => {
      if (item.all_users) return 'All users';
      const ids = (item.user_ids && item.user_ids.length > 0) ? item.user_ids : (item.user_id ? [item.user_id] : []);
      return ids.length ? ids.map(userNameById).join(', ') : 'No users';
    };
    const jobTitle = job => ({ site_backup: 'Website backup', user_backup: 'Full user backup', sftp_backup: 'SFTP backup' }[job.kind] || 'Backup task');
    const jobDetail = job => job.error || job.remote_file || job.backup_file || job.message || job.status;
    const backupTabs = isAdmin
      ? [
        ['website', 'Backup website', Globe],
        ['user', 'Backup user', Users],
        ['schedule', 'Scheduled backups', Clock],
        ['destination', 'Backup Destination', Network],
        ['da-import', 'DA Import', ArchiveRestore],
      ]
      : [['website', 'Backup website', Globe]];
    const activeBackupTab = backupTabs.some(([id]) => id === backupTab) ? backupTab : 'website';
    const visibleBackupJobs = backupJobs.filter(job => job.status !== 'done');

    return <section className="section backups-page">
      <h2>Backups</h2>
      <div className="segmented-control backup-tabs" role="tablist" aria-label="Backup sections">
        {backupTabs.map(([id, label, Icon]) => <button
          key={id}
          type="button"
          role="tab"
          aria-selected={activeBackupTab === id}
          className={activeBackupTab === id ? 'active' : ''}
          onClick={() => setBackupTab(id)}
        ><Icon size={14}/>{label}</button>)}
      </div>
      {visibleBackupJobs.length > 0 && <div className="backup-job-list">
        {visibleBackupJobs.map(job => <div className={`backup-job ${job.status}`} key={job.job_id}>
          <Clock size={14}/>
          <span><strong>{jobTitle(job)}</strong><small>{jobDetail(job)}</small></span>
          <span className={job.status === 'done' ? 'badge ok' : job.status === 'error' ? 'badge bad' : 'badge'}>{job.status}</span>
        </div>)}
      </div>}

      {activeBackupTab === 'website' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup website</h3><p className="hint">Backups include website source files and a database SQL export.</p></div>
        </div>
        <WebsiteSelect />
        <div className="actions backup-toolbar">
          <button disabled={!selectedWebsiteId || !!loading} onClick={createBackup}><Plus size={14}/> Create backup</button>
          <button disabled={!selectedWebsiteId || !!loading} onClick={refreshBackupArea}><RefreshCw size={14}/> Refresh</button>
          <label className="upload-button">
            <Upload size={14}/> Upload backup
            <input type="file" accept=".tar.gz,application/gzip" onChange={e => { uploadBackup(e.target.files?.[0]); e.target.value = ''; }} />
          </label>
        </div>
        {backups.length === 0 && selectedWebsiteId && <EmptyState icon={Archive} message="No backups found for this website." />}
        <div className="backup-list">
          {backups.map(file => <div className="backup-item" key={file}>
            <span>{file.split('/').pop()}</span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadBackup(file)}><Download size={14}/> Download</button>
              <button disabled={!!loading} onClick={() => restoreBackup(file)}><RotateCcw size={14}/> Restore</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteBackup(file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'user' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup user</h3><p className="hint">Includes the panel user, all owned websites, source files, database dumps, and restore metadata.</p></div>
          <button disabled={!!loading} onClick={refreshUserBackupArea}><RefreshCw size={14}/> Reload</button>
        </div>
        <div className="sftp-run-row user-backup-row backup-run-row">
          <select value={selectedBackupUserId} onChange={e => setSelectedBackupUserId(e.target.value)}>
            <option value="">Select user</option>
            {users.map(user => <option key={user.id} value={user.id}>{user.username}</option>)}
          </select>
          <select value={selectedSftpTargetId} onChange={e => setSelectedSftpTargetId(e.target.value)}>
            <option value="">Local only</option>
            {sftpTargets.map(target => <option key={target.id} value={target.id}>{target.name}</option>)}
          </select>
          <button disabled={!selectedBackupUserId || !!loading} onClick={createUserBackup}><Archive size={14}/> Create backup</button>
        </div>
        {selectedBackupUser && <p className="hint">Current user: <strong>{selectedBackupUser.username}</strong></p>}
        <div className="actions backup-subactions">
          <button disabled={!selectedBackupUserId || !!loading} onClick={() => listUserBackups()}><RefreshCw size={14}/> Refresh list</button>
        </div>
        {selectedBackupUserId && userBackups.length === 0 && <EmptyState icon={Archive} message="No user backups found." />}
        <div className="backup-list">
          {userBackups.map(file => <div className="backup-item" key={file}>
            <span>{file.split('/').pop()}</span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadUserBackup(file)}><Download size={14}/> Download</button>
              <button disabled={!!loading} onClick={() => restoreUserBackup(file)}><RotateCcw size={14}/> Restore user</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteUserBackup(file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>

        <div className="section-title restore-title backup-panel-heading backup-subtitle">
          <div><h3>Restore folder</h3><p className="hint">{restoreBackupDir || '/var/backups/snpanel/users/restore'}</p></div>
          <div className="actions">
            <button disabled={!!loading} onClick={loadRestoreBackups}><RefreshCw size={14}/> Refresh</button>
            <label className="upload-button">
              <Upload size={14}/> Upload backups
              <input type="file" multiple accept=".tar.gz,application/gzip" onChange={e => { uploadUserBackups(e.target.files); e.target.value = ''; }} />
            </label>
          </div>
        </div>
        <div className="backup-list">
          {restoreBackups.map(item => <div className="backup-item" key={item.backup_file}>
            <span>{item.filename || item.backup_file.split('/').pop()}<small>{item.valid ? `${item.source === 'opanel' ? 'opanel · ' : ''}${item.username || 'unknown user'} - ${item.websites || 0} website(s)` : (item.error || 'Invalid backup')}</small></span>
            <div className="actions">
              <button disabled={!!loading} onClick={() => downloadUserBackup(item.backup_file)}><Download size={14}/> Download</button>
              <button disabled={!!loading || !item.valid} onClick={() => restoreUserBackup(item.backup_file)}><RotateCcw size={14}/> Restore user</button>
              <button className="danger" disabled={!!loading} onClick={() => deleteRestoreBackup(item.backup_file)}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>

      </div>}

      {isAdmin && activeBackupTab === 'schedule' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Scheduled backups</h3><p className="hint">Run full user backups automatically with optional off-server destination.</p></div>
          <button disabled={!!loading} onClick={refreshScheduledBackupArea}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="sftp-form schedule-form backup-schedule-form">
          <label className="schedule-toggle">
            <input type="checkbox" checked={!!newBackupSchedule.all_users} onChange={e => setNewBackupSchedule(prev => ({ ...prev, all_users: e.target.checked }))} />
            <span>All users</span>
          </label>
          <select multiple value={newBackupSchedule.user_ids || []} disabled={!!newBackupSchedule.all_users} onChange={e => setNewBackupSchedule(prev => ({ ...prev, user_ids: Array.from(e.target.selectedOptions, option => option.value) }))}>
            {users.map(user => <option key={user.id} value={String(user.id)}>{user.username}</option>)}
          </select>
          <input value={newBackupSchedule.schedule} onChange={e => setNewBackupSchedule(prev => ({ ...prev, schedule: e.target.value }))} placeholder="0 2 * * *" />
          <select value={newBackupSchedule.target_id} onChange={e => setNewBackupSchedule(prev => ({ ...prev, target_id: e.target.value }))}>
            <option value="">Local only</option>
            {sftpTargets.map(target => <option key={target.id} value={target.id}>{target.name}</option>)}
          </select>
          <button disabled={(!newBackupSchedule.all_users && (!newBackupSchedule.user_ids || newBackupSchedule.user_ids.length === 0)) || !!loading} onClick={createBackupSchedule}><Clock size={14}/> Schedule</button>
        </div>
        <div className="backup-list">
          {backupSchedules.map(item => {
            const scheduleTarget = sftpTargets.find(target => target.id === item.target_id);
            return <div className="backup-item" key={item.id}>
              <span>{scheduleUserLabel(item)} - {item.schedule}{scheduleTarget ? ` - ${scheduleTarget.name}` : ''}<small>{item.last_status}: {item.last_message || 'not run yet'}</small></span>
              <button className="danger" disabled={!!loading} onClick={() => deleteBackupSchedule(item.id)}><Trash2 size={14}/></button>
            </div>;
          })}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'destination' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>Backup Destination</h3><p className="hint">Manage SFTP destinations used for off-server backup copies.</p></div>
          <button disabled={!!loading} onClick={loadSftpTargets}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="sftp-form sftp-target-form">
          <input value={newSftpTarget.name} onChange={e => setNewSftpTarget(prev => ({ ...prev, name: e.target.value }))} placeholder="Target name" />
          <input value={newSftpTarget.host} onChange={e => setNewSftpTarget(prev => ({ ...prev, host: e.target.value }))} placeholder="Host" />
          <input value={newSftpTarget.port} onChange={e => setNewSftpTarget(prev => ({ ...prev, port: e.target.value }))} placeholder="22" inputMode="numeric" />
          <input value={newSftpTarget.username} onChange={e => setNewSftpTarget(prev => ({ ...prev, username: e.target.value }))} placeholder="Username" />
          <input value={newSftpTarget.password} onChange={e => setNewSftpTarget(prev => ({ ...prev, password: e.target.value }))} placeholder="Password" type="password" />
          <input value={newSftpTarget.remote_path} onChange={e => setNewSftpTarget(prev => ({ ...prev, remote_path: e.target.value }))} placeholder="/backups/snpanel" />
          <textarea value={newSftpTarget.private_key} onChange={e => setNewSftpTarget(prev => ({ ...prev, private_key: e.target.value }))} placeholder="Private key (optional)" rows={4} />
          <button disabled={!!loading || !newSftpTarget.name || !newSftpTarget.host || !newSftpTarget.username || (!newSftpTarget.password && !newSftpTarget.private_key)} onClick={createSftpTarget}><Plus size={14}/> Save target</button>
        </div>
        {sftpTargets.length === 0 && <EmptyState icon={Network} message="No backup destinations found." />}
        <div className="backup-list">
          {sftpTargets.map(target => <div className="backup-item" key={target.id}>
            <span>{target.name} - {target.username}@{target.host}:{target.remote_path}</span>
            <button className="danger" disabled={!!loading} onClick={() => deleteSftpTarget(target.id)}><Trash2 size={14}/></button>
          </div>)}
        </div>
      </div>}

      {isAdmin && activeBackupTab === 'da-import' && <div className="backup-tab-panel">
        <div className="backup-panel-title">
          <div><h3>DirectAdmin Import</h3><p className="hint">Import websites, databases, and users from a DirectAdmin backup archive.</p></div>
          <button disabled={!!loading} onClick={() => listDaBackups()}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="da-toolbar">
          <label className="upload-button">
            <Upload size={14}/> Upload DA backup
            <input ref={daFileInputRef} type="file" accept=".tar.zst,.tzst,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,.tar" onChange={e => { uploadDaBackup(e.target.files?.[0]); e.target.value = ''; }} />
          </label>
          <label className="da-toggle">
            <input type="checkbox" checked={daReplaceExisting} onChange={e => setDaReplaceExisting(e.target.checked)} />
            Replace existing users/websites
          </label>
        </div>
        {daReplaceExisting && <p className="hint da-warn">
          Imports will delete any existing panel user, website, files and databases that share a name with the backup. Leave this off to have conflicting imports stop instead.
        </p>}
        {daBackups.length === 0 && <EmptyState icon={ArchiveRestore} message="No DirectAdmin backups uploaded. Upload a DA backup archive to get started." />}
        {daBackups.length > 0 && <>
          <div className="da-list-head">
            <label className="da-toggle">
              <input type="checkbox" checked={selectedDaBackups.length === daBackups.length && daBackups.length > 0} onChange={toggleSelectAllDaBackups} />
              Select all ({daBackups.length})
            </label>
            {selectedDaBackups.length > 0 && <div className="da-actions">
              <button disabled={!!loading} onClick={() => bulkImportDaBackups()} className="primary"><ArchiveRestore size={14}/> Restore selected ({selectedDaBackups.length})</button>
              <button disabled={!!loading} onClick={bulkDeleteDaBackups} className="danger"><Trash2 size={14}/> Delete selected ({selectedDaBackups.length})</button>
            </div>}
          </div>
          <div className="backup-list">
            {daBackups.map(file => <div className={`backup-item da-backup-row${selectedDaBackups.includes(file.path) ? ' selected' : ''}`} key={file.path}>
              <label className="da-backup-pick">
                <input type="checkbox" checked={selectedDaBackups.includes(file.path)} onChange={() => toggleDaBackupSelect(file.path)} />
                <span>{file.filename}<small>{(file.size / (1024 * 1024)).toFixed(1)} MB</small></span>
              </label>
              <div className="da-actions">
                <button disabled={!!loading} onClick={() => scanDaBackup(file.path)}><Search size={14}/> Scan</button>
                <button disabled={!!loading} onClick={() => importDaBackup(file.path)}><ArchiveRestore size={14}/> Import</button>
                <button className="danger" disabled={!!loading} onClick={() => deleteDaBackup(file.path)}><Trash2 size={14}/></button>
              </div>
            </div>)}
          </div>
        </>}

        {daScanResult && <div className="da-scan-result">
          <h4>Scan result: {daScanResult.filename}</h4>
          {daScanResult.errors?.length > 0 && <div className="error-list">
            {daScanResult.errors.map((err, i) => <p key={i} className="error-text">{err}</p>)}
          </div>}
          {daScanResult.users?.map((user, i) => <div key={i} className="da-user-block">
            <p className="da-user-head"><Users size={13}/> <strong>{user.username}</strong>{user.email && <small>{user.email}</small>}</p>
            {user.domains?.length > 0 && <div className="da-table-wrap">
              <table className="da-scan-table">
                <thead><tr><th>Domain</th><th>Type</th><th>Files</th><th>Database</th><th>SQL dump</th><th>Pointers</th></tr></thead>
                <tbody>
                  {user.domains.map((d, j) => <tr key={j}>
                    <td><Globe size={12}/> {d.domain}</td>
                    <td>{d.app_type}</td>
                    <td>{d.has_files ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                    <td>{d.db_name || <span className="da-muted">—</span>}</td>
                    <td>{d.has_sql_dump ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                    <td>{d.aliases?.length > 0 ? d.aliases.map(a => `${a.domain} (${a.mode})`).join(', ') : <span className="da-muted">—</span>}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>}
            {user.databases?.length > 0 && <div className="da-table-wrap">
              <p className="hint">Unassigned databases ({user.databases.length})</p>
              <table className="da-scan-table">
                <thead><tr><th>Database</th><th>SQL dump</th></tr></thead>
                <tbody>
                  {user.databases.map((db, j) => <tr key={j}>
                    <td><Database size={12}/> {db.db_name}</td>
                    <td>{db.has_sql_dump ? <Check size={13} className="da-yes"/> : <X size={13} className="da-no"/>}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>}
          </div>)}
        </div>}

        {daImportJob && <div className={`backup-job da-job ${daImportJob.status}`}>
          <Clock size={14}/>
          <span><strong>DA Import</strong><small>{daImportJob.archive || ''}</small></span>
          <span className={daImportJob.status === 'completed' ? 'badge ok' : daImportJob.status === 'failed' ? 'badge bad' : 'badge'}>{daImportJob.status}</span>
        </div>}
        {daImportJob?.status === 'completed' && daImportJob.result?.summary && <div className="da-scan-result">
          <h4>Import summary</h4>
          {daImportJob.result.summary.map((item, i) => <div key={i} className="da-user-block">
            <p className="da-user-head"><strong>{item.username}</strong> <span className="badge ok">{item.imported_domains?.length || 0} domain(s)</span> <span className="badge">{item.databases?.length || 0} database(s)</span></p>
            {item.aliases?.length > 0 && <p className="hint">Pointers: {item.aliases.join(', ')}</p>}
            {item.ssl_enabled_domains?.length > 0 && <p className="hint">SSL enabled: {item.ssl_enabled_domains.join(', ')}</p>}
            {item.warnings?.length > 0 && <p className="hint da-warn">Warnings: {item.warnings.join('; ')}</p>}
          </div>)}
          {daImportJob.result.credentials && <details className="da-creds-details">
            <summary>Generated credentials (click to show)</summary>
            <pre className="da-credentials">{daImportJob.result.credentials.join('\n')}</pre>
          </details>}
        </div>}

        {daBulkImportJob && <div className={`backup-job da-job ${daBulkImportJob.status}`}>
          <Clock size={14}/>
          <span><strong>Bulk restore</strong><small>{daBulkImportJob.status === 'running' ? `Processing ${daBulkImportJob.current + 1}/${daBulkImportJob.total}: ${daBulkImportJob.current_archive}` : `${daBulkImportJob.total} backup(s)`}</small></span>
          <span className={daBulkImportJob.status === 'completed' ? 'badge ok' : 'badge'}>{daBulkImportJob.status === 'running' ? `${daBulkImportJob.current}/${daBulkImportJob.total}` : daBulkImportJob.status}</span>
        </div>}
        {daBulkImportJob?.status === 'completed' && daBulkImportJob.results && <div className="da-scan-result">
          <h4>Bulk restore results</h4>
          {daBulkImportJob.results.map((item, i) => <div key={i} className={`da-user-block ${item.status === 'completed' ? 'ok' : 'bad'}`}>
            <p className="da-user-head"><strong>{item.archive}</strong> <span className={item.status === 'completed' ? 'badge ok' : 'badge bad'}>{item.status}</span></p>
            {item.result?.summary?.map((s, j) => <p key={j} className="hint">{s.username}: {s.imported_domains?.length || 0} domain(s), {s.databases?.length || 0} db(s)</p>)}
            {item.result?.credentials && <details className="da-creds-details">
              <summary>Credentials</summary>
              <pre className="da-credentials">{item.result.credentials.join('\n')}</pre>
            </details>}
            {item.error && <p className="error-text">{item.error}</p>}
          </div>)}
        </div>}
      </div>}
    </section>;
  }

  return renderBackups();
}
