import { Archive, ArchiveRestore, Check, Clock, Database, Download, Globe, Network, Plus, RefreshCw, RotateCcw, Search, Trash2, Upload, Users, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, serverText, useT } from '../i18n/index.jsx';
import S3Destinations from '../components/S3Destinations.jsx';
import './Backups.css';

const JOB_TITLES = { site_backup: msg('Website backup'), user_backup: msg('Full user backup'), sftp_backup: msg('SFTP backup') };
const JOB_STATES = { queued: msg('Queued'), running: msg('Running'), done: msg('Done'), error: msg('Failed') };
const IMPORT_STATES = { queued: msg('Queued'), running: msg('Running'), completed: msg('Completed'), failed: msg('Failed') };

// How a scheduled backup is named - what is appended to the user name - and
// so how many files it keeps. The file names are the server's, in English.
const NAME_STYLES = [
  { value: 'timestamp', label: msg('Date and time (default)'), short: msg('Date and time'), keeps: msg('A new file every run; the newest are kept.') },
  { value: 'none', label: msg('None - the user name only'), short: msg('User name only'), keeps: msg('Each run replaces the last file.') },
  { value: 'weekday', label: msg('Day of week - name and weekday'), short: msg('Day of week'), keeps: msg('One file per day of the week, each replaced a week later.') },
  { value: 'date', label: msg('Full date - name and date'), short: msg('Full date'), keeps: msg('One file per day; the newest are kept.') },
];
const STYLE_NAMES = Object.fromEntries(NAME_STYLES.map((style) => [style.value, style.short]));
const WEEKDAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
const pad = (n) => String(n).padStart(2, '0');

// What the file a schedule writes today would be called.
function exampleName(style, username) {
  const now = new Date();
  switch (style) {
    case 'none': return `${username}.tar.gz`;
    case 'weekday': return `${username}-${WEEKDAYS[now.getDay()]}.tar.gz`;
    case 'date': return `${username}-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}.tar.gz`;
    default: return `user-${username}-${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}00.tar.gz`;
  }
}

// Where a backup goes: this server, or one of the SFTP and S3 destinations.
// The value is '', 'sftp:<id>' or 's3:<id>'.
function DestinationSelect({ id, value, onChange }) {
  const { s3Targets, sftpTargets } = usePanel();
  const t = useT();
  return <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
    <option value="">{t('Local only')}</option>
    {sftpTargets.length > 0 && <optgroup label="SFTP">
      {sftpTargets.map((target) => <option key={target.id} value={`sftp:${target.id}`}>{target.name}</option>)}
    </optgroup>}
    {s3Targets.length > 0 && <optgroup label="S3">
      {s3Targets.map((target) => <option key={target.id} value={`s3:${target.id}`}>{target.name}</option>)}
    </optgroup>}
  </select>;
}

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
    loadRestoreBackups,
    loadS3Targets,
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
    s3Targets,
    scanDaBackup,
    selectedBackupUserId,
    selectedDaBackups,
    selectedWebsiteId,
    setBackupTab,
    setDaReplaceExisting,
    setNewBackupSchedule,
    setNewSftpTarget,
    setSelectedBackupUserId,
    setUserBackupDestination,
    sftpTargets,
    toggleDaBackupSelect,
    toggleSelectAllDaBackups,
    uploadBackup,
    uploadDaBackup,
    uploadUserBackups,
    userBackupDestination,
    userBackups,
    users,
  } = usePanel();
  const t = useT();
  const busy = !!loading;
  const setSftp = (key) => (e) => setNewSftpTarget((prev) => ({ ...prev, [key]: e.target.value }));

  const userNameById = (id) => users.find((user) => String(user.id) === String(id))?.username || t('User #{id}', { id });
  const scheduleUserLabel = (item) => {
    if (item.all_users) return t('All users');
    const ids = (item.user_ids && item.user_ids.length > 0) ? item.user_ids : (item.user_id ? [item.user_id] : []);
    return ids.length ? ids.map(userNameById).join(', ') : t('No users');
  };
  const scheduleDestination = (item) => {
    if (item.target_id) return sftpTargets.find((target) => target.id === item.target_id)?.name || t('SFTP destination #{id}', { id: item.target_id });
    if (item.s3_target_id) return s3Targets.find((target) => target.id === item.s3_target_id)?.name || t('S3 destination #{id}', { id: item.s3_target_id });
    return t('Local only');
  };
  const jobTitle = (job) => (JOB_TITLES[job.kind] ? t(JOB_TITLES[job.kind]) : t('Backup task'));
  const jobDetail = (job) => job.error || job.remote_file || job.backup_file || job.message || job.status;
  const backupTabs = isAdmin
    ? [
      ['website', t('Backup website'), Globe],
      ['user', t('Backup user'), Users],
      ['schedule', t('Scheduled backups'), Clock],
      ['destination', t('Destinations'), Network],
      ['da-import', t('DA Import'), ArchiveRestore],
    ]
    : [['website', t('Backup website'), Globe]];
  const activeBackupTab = backupTabs.some(([id]) => id === backupTab) ? backupTab : 'website';
  const visibleBackupJobs = backupJobs.filter((job) => job.status !== 'done');

  const style = newBackupSchedule.name_style || 'timestamp';
  const styleInfo = NAME_STYLES.find((s) => s.value === style) || NAME_STYLES[0];
  const firstScheduled = newBackupSchedule.all_users ? users[0] : users.find((user) => String(user.id) === String((newBackupSchedule.user_ids || [])[0]));
  const keepsNewest = style === 'timestamp' || style === 'date';
  const scheduleReady = newBackupSchedule.all_users || (newBackupSchedule.user_ids || []).length > 0;
  const setSchedule = (key) => (value) => setNewBackupSchedule((prev) => ({ ...prev, [key]: value }));

  return <section className="section backups-page">
    <h2>{t('Backups')}</h2>
    <div className="segmented-control backup-tabs" role="tablist" aria-label={t('Backup sections')}>
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
      {visibleBackupJobs.map((job) => <div className={`backup-job ${job.status}`} key={job.job_id}>
        <Clock size={14}/>
        <span><strong>{jobTitle(job)}</strong><small>{jobDetail(job)}</small></span>
        <span className={job.status === 'done' ? 'badge ok' : job.status === 'error' ? 'badge bad' : 'badge'}>{JOB_STATES[job.status] ? t(JOB_STATES[job.status]) : job.status}</span>
      </div>)}
    </div>}

    {activeBackupTab === 'website' && <div className="backup-tab-panel">
      <div className="backup-panel-title">
        <div><h3>{t('Backup website')}</h3><p className="hint">{t('Backups include website source files and a database SQL export.')}</p></div>
      </div>
      <WebsiteSelect />
      <div className="actions backup-toolbar">
        <button disabled={!selectedWebsiteId || busy} onClick={createBackup}><Plus size={14}/> {t('Create backup')}</button>
        <button className="secondary-light" disabled={!selectedWebsiteId || busy} onClick={refreshBackupArea}><RefreshCw size={14}/> {t('Refresh')}</button>
        <label className="upload-button secondary-light">
          <Upload size={14}/> {t('Upload backup')}
          <input type="file" accept=".tar.gz,application/gzip" onChange={(e) => { uploadBackup(e.target.files?.[0]); e.target.value = ''; }} />
        </label>
      </div>
      {backups.length === 0 && selectedWebsiteId && <EmptyState icon={Archive} message={t('No backups found for this website.')} />}
      <div className="backup-list">
        {backups.map((file) => <div className="backup-item" key={file}>
          <span>{file.split('/').pop()}</span>
          <div className="actions">
            <button disabled={busy} onClick={() => downloadBackup(file)}><Download size={14}/> {t('Download')}</button>
            <button disabled={busy} onClick={() => restoreBackup(file)}><RotateCcw size={14}/> {t('Restore')}</button>
            <button className="danger" disabled={busy} onClick={() => deleteBackup(file)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14}/></button>
          </div>
        </div>)}
      </div>
    </div>}

    {isAdmin && activeBackupTab === 'user' && <div className="backup-tab-panel">
      <div className="backup-panel-title">
        <div><h3>{t('Backup user')}</h3><p className="hint">{t('Includes the panel user, all owned websites and databases, source files, database dumps, and restore metadata.')}</p></div>
        <button className="secondary-light" disabled={busy} onClick={refreshUserBackupArea}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      <div className="bk-form bk-user-form">
        <div className="bk-field">
          <label htmlFor="bk-user">{t('User')}</label>
          <select id="bk-user" value={selectedBackupUserId} onChange={(e) => setSelectedBackupUserId(e.target.value)}>
            <option value="">{t('Select user')}</option>
            {users.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
          </select>
        </div>
        <div className="bk-field">
          <label htmlFor="bk-user-destination">{t('Destination')}</label>
          <DestinationSelect id="bk-user-destination" value={userBackupDestination} onChange={setUserBackupDestination} />
        </div>
        <div className="bk-actions">
          <button disabled={!selectedBackupUserId || busy} onClick={createUserBackup}><Archive size={14}/> {t('Create backup')}</button>
        </div>
      </div>
      {selectedBackupUserId && userBackups.length === 0 && <EmptyState icon={Archive} message={t('No user backups found.')} />}
      <div className="backup-list">
        {userBackups.map((file) => <div className="backup-item" key={file}>
          <span>{file.split('/').pop()}</span>
          <div className="actions">
            <button disabled={busy} onClick={() => downloadUserBackup(file)}><Download size={14}/> {t('Download')}</button>
            <button disabled={busy} onClick={() => restoreUserBackup(file)}><RotateCcw size={14}/> {t('Restore user')}</button>
            <button className="danger" disabled={busy} onClick={() => deleteUserBackup(file)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14}/></button>
          </div>
        </div>)}
      </div>

      <div className="section-title restore-title backup-panel-heading backup-subtitle">
        <div><h3>{t('Restore folder')}</h3><p className="hint">{restoreBackupDir || '/var/backups/snpanel/users/restore'}</p></div>
        <div className="actions">
          <button className="secondary-light" disabled={busy} onClick={loadRestoreBackups}><RefreshCw size={14}/> {t('Refresh')}</button>
          <label className="upload-button secondary-light">
            <Upload size={14}/> {t('Upload backups')}
            <input type="file" multiple accept=".tar.gz,application/gzip" onChange={(e) => { uploadUserBackups(e.target.files); e.target.value = ''; }} />
          </label>
        </div>
      </div>
      <div className="backup-list">
        {restoreBackups.map((item) => <div className="backup-item" key={item.backup_file}>
          <span>{item.filename || item.backup_file.split('/').pop()}<small>{item.valid
            ? `${item.source === 'opanel' ? 'opanel · ' : ''}${t('{user} - {count} website(s)', { user: item.username || t('unknown user'), count: item.websites || 0 })}`
            : (item.error || t('Invalid backup'))}</small></span>
          <div className="actions">
            <button disabled={busy} onClick={() => downloadUserBackup(item.backup_file)}><Download size={14}/> {t('Download')}</button>
            <button disabled={busy || !item.valid} onClick={() => restoreUserBackup(item.backup_file)}><RotateCcw size={14}/> {t('Restore user')}</button>
            <button className="danger" disabled={busy} onClick={() => deleteRestoreBackup(item.backup_file)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14}/></button>
          </div>
        </div>)}
      </div>
    </div>}

    {isAdmin && activeBackupTab === 'schedule' && <div className="backup-tab-panel">
      <div className="backup-panel-title">
        <div><h3>{t('Scheduled backups')}</h3><p className="hint">{t('Full user backups on a timetable, kept here and optionally copied to a destination.')}</p></div>
        <button className="secondary-light" disabled={busy} onClick={refreshScheduledBackupArea}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      <div className="bk-form bk-schedule-form">
        <div className="bk-field bk-users">
          <span className="bk-label" id="bk-schedule-users-label">{t('Users')}</span>
          <label className="schedule-toggle">
            <input type="checkbox" checked={!!newBackupSchedule.all_users} onChange={(e) => setSchedule('all_users')(e.target.checked)} />
            <span>{t('All users')}</span>
          </label>
          <select multiple aria-labelledby="bk-schedule-users-label" value={newBackupSchedule.user_ids || []} disabled={!!newBackupSchedule.all_users}
            onChange={(e) => setSchedule('user_ids')(Array.from(e.target.selectedOptions, (option) => option.value))}>
            {users.map((user) => <option key={user.id} value={String(user.id)}>{user.username}</option>)}
          </select>
        </div>
        <div className="bk-field">
          <label htmlFor="bk-schedule-cron">{t('Runs at (cron)')}</label>
          <input id="bk-schedule-cron" value={newBackupSchedule.schedule} onChange={(e) => setSchedule('schedule')(e.target.value)} placeholder="0 2 * * *" spellCheck={false} aria-describedby="bk-schedule-cron-hint" />
          <small className="hint" id="bk-schedule-cron-hint">{t('Minute, hour, day, month, weekday. 0 2 * * * is every day at 02:00.')}</small>
        </div>
        <div className="bk-field">
          <label htmlFor="bk-schedule-destination">{t('Destination')}</label>
          <DestinationSelect id="bk-schedule-destination" value={newBackupSchedule.destination || ''} onChange={setSchedule('destination')} />
        </div>
        <div className="bk-field">
          <label htmlFor="bk-schedule-style">{t('Append to the file name')}</label>
          <select id="bk-schedule-style" value={style} onChange={(e) => setSchedule('name_style')(e.target.value)} aria-describedby="bk-schedule-style-hint">
            {NAME_STYLES.map((option) => <option key={option.value} value={option.value}>{t(option.label)}</option>)}
          </select>
          <small className="hint" id="bk-schedule-style-hint"><code>{exampleName(style, firstScheduled?.username || 'user')}</code> · {t(styleInfo.keeps)}</small>
        </div>
        {keepsNewest && <div className="bk-field bk-keep">
          <label htmlFor="bk-schedule-keep">{t('Keep')}</label>
          <input id="bk-schedule-keep" type="number" min="1" max="365" inputMode="numeric" value={newBackupSchedule.retention ?? 7}
            onChange={(e) => setSchedule('retention')(e.target.value)} aria-describedby="bk-schedule-keep-hint" />
          <small className="hint" id="bk-schedule-keep-hint">{t('files per user, here')}</small>
        </div>}
        <div className="bk-actions bk-span-all">
          {newBackupSchedule.destination && keepsNewest && <p className="hint bk-note">{String(newBackupSchedule.destination).startsWith('s3:')
            ? t('The bucket keeps the same number: older copies there are removed after each upload.')
            : t('Copies on the SFTP server are not deleted: remove old ones there.')}</p>}
          <button disabled={!scheduleReady || busy} onClick={createBackupSchedule}><Clock size={14}/> {t('Add schedule')}</button>
        </div>
      </div>
      {backupSchedules.length === 0 && <EmptyState icon={Clock} message={t('No backup schedules yet.')} />}
      <div className="backup-list">
        {backupSchedules.map((item) => <div className="backup-item bk-schedule-row" key={item.id}>
          <span>
            {scheduleUserLabel(item)} · <code>{item.schedule}</code> · {scheduleDestination(item)} · {t(STYLE_NAMES[item.name_style] || STYLE_NAMES.timestamp)}
            <small>
              {item.last_status === 'ok' && <span className="badge ok">{t('OK')}</span>}
              {item.last_status === 'error' && <span className="badge bad">{t('Failed')}</span>}
              {' '}{item.last_message || t('Not run yet')}
            </small>
          </span>
          <button className="danger" disabled={busy} onClick={() => deleteBackupSchedule(item.id)} aria-label={t('Delete schedule')} title={t('Delete schedule')}><Trash2 size={14}/></button>
        </div>)}
      </div>
    </div>}

    {isAdmin && activeBackupTab === 'destination' && <div className="backup-tab-panel">
      <div className="backup-panel-title">
        <div><h3>{t('Destinations')}</h3><p className="hint">{t('Where backups are copied off this server: an SFTP server or an S3 bucket.')}</p></div>
        <button className="secondary-light" disabled={busy} onClick={() => { loadSftpTargets(); loadS3Targets(); }}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>

      <section className="bk-destination" aria-labelledby="bk-s3-title">
        <h4 id="bk-s3-title">{t('S3 buckets')}</h4>
        <p className="hint">{t('AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO, or any other S3-compatible storage.')}</p>
        <S3Destinations />
      </section>

      <section className="bk-destination" aria-labelledby="bk-sftp-title">
        <h4 id="bk-sftp-title">{t('SFTP servers')}</h4>
        <form className="bk-form bk-sftp-form" aria-label={t('SFTP servers')} onSubmit={(e) => { e.preventDefault(); createSftpTarget(); }}>
          <div className="bk-field">
            <label htmlFor="sftp-name">{t('Target name')}</label>
            <input id="sftp-name" value={newSftpTarget.name} onChange={setSftp('name')} autoComplete="off" />
          </div>
          <div className="bk-field bk-span-2">
            <label htmlFor="sftp-host">{t('Host')}</label>
            <input id="sftp-host" value={newSftpTarget.host} onChange={setSftp('host')} placeholder="backup.example.com" autoComplete="off" spellCheck={false} />
          </div>
          <div className="bk-field">
            <label htmlFor="sftp-port">{t('Port')}</label>
            <input id="sftp-port" value={newSftpTarget.port} onChange={setSftp('port')} placeholder="22" inputMode="numeric" />
          </div>
          <div className="bk-field">
            <label htmlFor="sftp-user">{t('Username')}</label>
            <input id="sftp-user" value={newSftpTarget.username} onChange={setSftp('username')} autoComplete="off" spellCheck={false} />
          </div>
          <div className="bk-field">
            <label htmlFor="sftp-password">{t('Password')}</label>
            <input id="sftp-password" type="password" value={newSftpTarget.password} onChange={setSftp('password')} autoComplete="new-password" />
          </div>
          <div className="bk-field bk-span-2">
            <label htmlFor="sftp-path">{t('Remote folder')}</label>
            <input id="sftp-path" value={newSftpTarget.remote_path} onChange={setSftp('remote_path')} placeholder="/backups/snpanel" spellCheck={false} />
          </div>
          <div className="bk-field bk-span-all">
            <label htmlFor="sftp-key">{t('Private key (optional)')}</label>
            <textarea id="sftp-key" value={newSftpTarget.private_key} onChange={setSftp('private_key')} rows={4} spellCheck={false} aria-describedby="sftp-key-hint" />
          </div>
          <div className="bk-actions bk-span-all">
            <p className="hint bk-note" id="sftp-key-hint">{t('Sign in with a password, a private key, or both.')}</p>
            <button type="submit" disabled={busy || !newSftpTarget.name || !newSftpTarget.host || !newSftpTarget.username || (!newSftpTarget.password && !newSftpTarget.private_key)}><Plus size={14}/> {t('Save target')}</button>
          </div>
        </form>
        {sftpTargets.length === 0 && <EmptyState icon={Network} message={t('No SFTP destinations yet.')} />}
        <div className="backup-list">
          {sftpTargets.map((target) => <div className="backup-item" key={target.id}>
            <span>{target.name}<small>{target.username}@{target.host}:{target.remote_path}</small></span>
            <button className="danger" disabled={busy} onClick={() => deleteSftpTarget(target.id)} aria-label={t('Delete {name}', { name: target.name })} title={t('Delete {name}', { name: target.name })}><Trash2 size={14}/></button>
          </div>)}
        </div>
      </section>
    </div>}

    {isAdmin && activeBackupTab === 'da-import' && <div className="backup-tab-panel">
      <div className="backup-panel-title">
        <div><h3>{t('DirectAdmin Import')}</h3><p className="hint">{t('Import websites, databases, and users from a DirectAdmin backup archive.')}</p></div>
        <button className="secondary-light" disabled={busy} onClick={() => listDaBackups()}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      <div className="da-toolbar">
        <label className="upload-button">
          <Upload size={14}/> {t('Upload DA backup')}
          <input ref={daFileInputRef} type="file" accept=".tar.zst,.tzst,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,.tar" onChange={(e) => { uploadDaBackup(e.target.files?.[0]); e.target.value = ''; }} />
        </label>
        <label className="da-toggle">
          <input type="checkbox" checked={daReplaceExisting} onChange={(e) => setDaReplaceExisting(e.target.checked)} />
          {t('Replace existing users/websites')}
        </label>
      </div>
      {daReplaceExisting && <p className="hint da-warn">
        {t('Imports will delete any existing panel user, website, files and databases that share a name with the backup. Leave this off to have conflicting imports stop instead.')}
      </p>}
      {daBackups.length === 0 && <EmptyState icon={ArchiveRestore} message={t('No DirectAdmin backups uploaded. Upload a DA backup archive to get started.')} />}
      {daBackups.length > 0 && <>
        <div className="da-list-head">
          <label className="da-toggle">
            <input type="checkbox" checked={selectedDaBackups.length === daBackups.length && daBackups.length > 0} onChange={toggleSelectAllDaBackups} />
            {t('Select all ({count})', { count: daBackups.length })}
          </label>
          {selectedDaBackups.length > 0 && <div className="da-actions">
            <button disabled={busy} onClick={() => bulkImportDaBackups()} className="primary"><ArchiveRestore size={14}/> {t('Restore selected ({count})', { count: selectedDaBackups.length })}</button>
            <button disabled={busy} onClick={bulkDeleteDaBackups} className="danger"><Trash2 size={14}/> {t('Delete selected ({count})', { count: selectedDaBackups.length })}</button>
          </div>}
        </div>
        <div className="backup-list">
          {daBackups.map((file) => <div className={`backup-item da-backup-row${selectedDaBackups.includes(file.path) ? ' selected' : ''}`} key={file.path}>
            <label className="da-backup-pick">
              <input type="checkbox" checked={selectedDaBackups.includes(file.path)} onChange={() => toggleDaBackupSelect(file.path)} />
              <span>{file.filename}<small>{t('{size} MB', { size: (file.size / (1024 * 1024)).toFixed(1) })}</small></span>
            </label>
            <div className="da-actions">
              <button disabled={busy} onClick={() => scanDaBackup(file.path)}><Search size={14}/> {t('Inspect')}</button>
              <button disabled={busy} onClick={() => importDaBackup(file.path)}><ArchiveRestore size={14}/> {t('Import')}</button>
              <button className="danger" disabled={busy} onClick={() => deleteDaBackup(file.path)} aria-label={t('Delete')} title={t('Delete')}><Trash2 size={14}/></button>
            </div>
          </div>)}
        </div>
      </>}

      {daScanResult && <div className="da-scan-result">
        <h4>{t('Scan result: {name}', { name: daScanResult.filename })}</h4>
        {daScanResult.errors?.length > 0 && <div className="error-list">
          {daScanResult.errors.map((err, i) => <p key={i} className="error-text">{serverText(err)}</p>)}
        </div>}
        {daScanResult.users?.map((user, i) => <div key={i} className="da-user-block">
          <p className="da-user-head"><Users size={13}/> <strong>{user.username}</strong>{user.email && <small>{user.email}</small>}</p>
          {user.domains?.length > 0 && <div className="da-table-wrap">
            <table className="da-scan-table">
              <thead><tr><th>{t('Domain')}</th><th>{t('Type')}</th><th>{t('Files')}</th><th>{t('Database')}</th><th>{t('SQL dump')}</th><th>{t('Pointers')}</th></tr></thead>
              <tbody>
                {user.domains.map((d, j) => <tr key={j}>
                  <td><Globe size={12}/> {d.domain}</td>
                  <td>{d.app_type}</td>
                  <td>{d.has_files ? <Check size={13} className="da-yes" aria-label={t('Yes')}/> : <X size={13} className="da-no" aria-label={t('No')}/>}</td>
                  <td>{d.db_name || <span className="da-muted">—</span>}</td>
                  <td>{d.has_sql_dump ? <Check size={13} className="da-yes" aria-label={t('Yes')}/> : <X size={13} className="da-no" aria-label={t('No')}/>}</td>
                  <td>{d.aliases?.length > 0 ? d.aliases.map((a) => `${a.domain} (${a.mode})`).join(', ') : <span className="da-muted">—</span>}</td>
                </tr>)}
              </tbody>
            </table>
          </div>}
          {user.databases?.length > 0 && <div className="da-table-wrap">
            <p className="hint">{t('Unassigned databases ({count})', { count: user.databases.length })}</p>
            <table className="da-scan-table">
              <thead><tr><th>{t('Database')}</th><th>{t('SQL dump')}</th></tr></thead>
              <tbody>
                {user.databases.map((db, j) => <tr key={j}>
                  <td><Database size={12}/> {db.db_name}</td>
                  <td>{db.has_sql_dump ? <Check size={13} className="da-yes" aria-label={t('Yes')}/> : <X size={13} className="da-no" aria-label={t('No')}/>}</td>
                </tr>)}
              </tbody>
            </table>
          </div>}
        </div>)}
      </div>}

      {daImportJob && <div className={`backup-job da-job ${daImportJob.status}`}>
        <Clock size={14}/>
        <span><strong>{t('DA Import')}</strong><small>{daImportJob.archive || ''}</small></span>
        <span className={daImportJob.status === 'completed' ? 'badge ok' : daImportJob.status === 'failed' ? 'badge bad' : 'badge'}>{IMPORT_STATES[daImportJob.status] ? t(IMPORT_STATES[daImportJob.status]) : daImportJob.status}</span>
      </div>}
      {daImportJob?.status === 'completed' && daImportJob.result?.summary && <div className="da-scan-result">
        <h4>{t('Import summary')}</h4>
        {daImportJob.result.summary.map((item, i) => <div key={i} className="da-user-block">
          <p className="da-user-head"><strong>{item.username}</strong> <span className="badge ok">{t('{count} domain(s)', { count: item.imported_domains?.length || 0 })}</span> <span className="badge">{t('{count} database(s)', { count: item.databases?.length || 0 })}</span></p>
          {item.aliases?.length > 0 && <p className="hint">{t('Pointers: {list}', { list: item.aliases.join(', ') })}</p>}
          {item.ssl_enabled_domains?.length > 0 && <p className="hint">{t('SSL enabled: {list}', { list: item.ssl_enabled_domains.join(', ') })}</p>}
          {item.warnings?.length > 0 && <p className="hint da-warn">{t('Warnings: {list}', { list: item.warnings.map(serverText).join('; ') })}</p>}
        </div>)}
        {daImportJob.result.credentials && <details className="da-creds-details">
          <summary>{t('Generated credentials (click to show)')}</summary>
          <pre className="da-credentials">{daImportJob.result.credentials.join('\n')}</pre>
        </details>}
      </div>}

      {daBulkImportJob && <div className={`backup-job da-job ${daBulkImportJob.status}`}>
        <Clock size={14}/>
        <span><strong>{t('Bulk restore')}</strong><small>{daBulkImportJob.status === 'running'
          ? t('Processing {current}/{total}: {archive}', { current: daBulkImportJob.current + 1, total: daBulkImportJob.total, archive: daBulkImportJob.current_archive })
          : t('{count} backup(s)', { count: daBulkImportJob.total })}</small></span>
        <span className={daBulkImportJob.status === 'completed' ? 'badge ok' : 'badge'}>{daBulkImportJob.status === 'running' ? `${daBulkImportJob.current}/${daBulkImportJob.total}` : (IMPORT_STATES[daBulkImportJob.status] ? t(IMPORT_STATES[daBulkImportJob.status]) : daBulkImportJob.status)}</span>
      </div>}
      {daBulkImportJob?.status === 'completed' && daBulkImportJob.results && <div className="da-scan-result">
        <h4>{t('Bulk restore results')}</h4>
        {daBulkImportJob.results.map((item, i) => <div key={i} className={`da-user-block ${item.status === 'completed' ? 'ok' : 'bad'}`}>
          <p className="da-user-head"><strong>{item.archive}</strong> <span className={item.status === 'completed' ? 'badge ok' : 'badge bad'}>{IMPORT_STATES[item.status] ? t(IMPORT_STATES[item.status]) : item.status}</span></p>
          {item.result?.summary?.map((s, j) => <p key={j} className="hint">{t('{name}: {domains} domain(s), {databases} database(s)', { name: s.username, domains: s.imported_domains?.length || 0, databases: s.databases?.length || 0 })}</p>)}
          {item.result?.credentials && <details className="da-creds-details">
            <summary>{t('Credentials')}</summary>
            <pre className="da-credentials">{item.result.credentials.join('\n')}</pre>
          </details>}
          {item.error && <p className="error-text">{serverText(item.error)}</p>}
        </div>)}
      </div>}
    </div>}
  </section>;
}
