import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertCircle, Check, CloudDownload, HardDrive, Loader2, Network, RotateCcw, Search, Upload, UserCheck } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './BackupRestore.css';

const SOURCES = [
  { id: 'local', icon: HardDrive, title: msg('This server'), text: msg('Every account backup kept here: each account\'s own, the restore folder and uploads.') },
  { id: 'upload', icon: Upload, title: msg('Upload'), text: msg('Archives from your computer, up to 1 GB each.') },
  { id: 'sftp', icon: Network, title: msg('SFTP server'), text: msg('A saved SFTP destination.') },
  { id: 's3', icon: CloudDownload, title: msg('S3 bucket'), text: msg('A saved S3 destination.') },
];
const ITEM_STATES = {
  queued: msg('Waiting'),
  fetching: msg('Downloading'),
  restoring: msg('Restoring'),
  done: msg('Restored'),
  error: msg('Failed'),
};

// Accounts put back from their backups, DirectAdmin's way: where the backups
// are, which of them, one button. The restore runs on the server, one
// account after another, and the page follows it - also when it is opened
// again part-way through.
export default function BackupRestore() {
  const {
    EmptyState,
    formatBytes,
    listRestoreSource,
    loadRestoreJob,
    loading,
    restoreFinished,
    s3Targets,
    sftpTargets,
    startRestore,
    uploadUserBackups,
  } = usePanel();
  const t = useT();
  const [source, setSource] = useState('local');
  const [targetId, setTargetId] = useState('');
  const [items, setItems] = useState(null);
  const [selected, setSelected] = useState([]);
  const [job, setJob] = useState(null);
  const finishedRef = useRef('');
  const busy = !!loading;
  const remote = source === 'sftp' || source === 's3';
  const targets = source === 'sftp' ? sftpTargets : source === 's3' ? s3Targets : [];
  const running = job?.status === 'running';

  // The key a restore names an archive by: its path here, its name there.
  const keyOf = (item) => (remote ? item.name : item.backup_file);
  const nameOf = (item) => (remote ? item.name : (item.filename || String(item.backup_file).split('/').pop()));
  const dateOf = (item) => item.generated_at || item.modified || '';

  async function find(nextSource = source, nextTarget = targetId) {
    setSelected([]);
    const isRemote = nextSource === 'sftp' || nextSource === 's3';
    if (isRemote && !nextTarget) { setItems(null); return; }
    setItems(null);
    const found = await listRestoreSource(isRemote ? nextSource : 'local', nextTarget);
    setItems(found || []);
  }

  function choose(next) {
    if (running) return;
    setSource(next);
    const list = next === 'sftp' ? sftpTargets : next === 's3' ? s3Targets : [];
    const first = list[0] ? String(list[0].id) : '';
    setTargetId(first);
    setItems(null);
    setSelected([]);
    if (next === 'local') find('local', '');
  }

  // What is running, or ran last, when the page opens.
  useEffect(() => {
    let live = true;
    loadRestoreJob().then((found) => { if (live && found) { setJob(found); if (found.status !== 'running') finishedRef.current = found.id; } });
    find('local', '');
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Followed every two seconds while it runs.
  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(async () => {
      const next = await loadRestoreJob(job.id);
      if (!next) return;
      setJob(next);
      if (next.status !== 'running' && finishedRef.current !== next.id) {
        finishedRef.current = next.id;
        await restoreFinished(next);
        if (source === 'local') find('local', '');
      }
    }, 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, job?.id]);

  const usable = useMemo(() => (items || []).filter((item) => item.valid), [items]);
  const allChosen = usable.length > 0 && usable.every((item) => selected.includes(keyOf(item)));
  const toggle = (key) => setSelected((prev) => (prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]));
  const chooseAll = () => setSelected(allChosen ? [] : usable.map(keyOf));
  // The newest archive of every account: the usual restore of a whole server.
  const chooseNewest = () => {
    const newest = new Map();
    for (const item of usable) {
      const user = item.username || nameOf(item);
      const best = newest.get(user);
      if (!best || dateOf(item) > dateOf(best)) newest.set(user, item);
    }
    setSelected([...newest.values()].map(keyOf));
  };
  const chosenUsers = [...new Set(usable.filter((item) => selected.includes(keyOf(item))).map((item) => item.username || nameOf(item)))];

  async function restore() {
    if (!selected.length) return;
    const question = t('Restore {count} backup(s)? An account that already exists is overwritten: its websites\' files and its databases are replaced by the backup\'s.', { count: selected.length });
    if (!confirm(question)) return;
    const started = await startRestore(remote ? source : 'local', remote ? targetId : '', selected);
    if (started) { finishedRef.current = ''; setJob(started); setSelected([]); }
  }

  async function upload(files) {
    const done = await uploadUserBackups(files);
    if (done) { setSource('local'); find('local', ''); }
  }

  const when = (text) => {
    const date = text ? new Date(text) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : '';
  };

  return <div className="bk-restore">
    {job && <section className={`bk-restore-job ${job.status}`} aria-live="polite">
      <div className="bk-restore-job-head">
        {running ? <Loader2 size={16} className="spin" aria-hidden="true" /> : job.failed ? <AlertCircle size={16} aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}
        <strong>{running
          ? t('Restoring {done} of {total}...', { done: job.done + job.failed + 1 > job.total ? job.total : job.done + job.failed + 1, total: job.total })
          : t('Restore finished: {done} restored, {failed} failed.', { done: job.done, failed: job.failed })}</strong>
        <small>{job.source === 'local' ? t('From this server') : t('From {name}', { name: job.target_name })}</small>
        {!running && <button type="button" className="secondary-light mini" onClick={() => setJob(null)}>{t('Hide')}</button>}
      </div>
      <ol className="bk-restore-steps">
        {job.items.map((item) => <li key={item.file} className={item.status}>
          <span className={`badge ${item.status === 'done' ? 'ok' : item.status === 'error' ? 'bad' : ''}`}>{ITEM_STATES[item.status] ? t(ITEM_STATES[item.status]) : item.status}</span>
          <span className="bk-restore-step-text">
            <strong>{item.username || item.name}</strong>
            <small>{item.status === 'done'
              ? t('{sites} website(s), {databases} database(s)', { sites: item.websites, databases: item.databases })
              : item.message || item.name}</small>
          </span>
        </li>)}
      </ol>
    </section>}

    <fieldset className="bk-restore-step" disabled={running}>
      <legend><span className="bk-restore-num">1</span> {t('Where are the backups?')}</legend>
      <div className="bk-restore-sources" role="radiogroup" aria-label={t('Where are the backups?')}>
        {SOURCES.map(({ id, icon: Icon, title, text }) => <button key={id} type="button" role="radio" aria-checked={source === id}
          className={`bk-restore-source${source === id ? ' active' : ''}`} onClick={() => choose(id)}>
          <Icon size={18} aria-hidden="true" />
          <span><strong>{t(title)}</strong><small>{t(text)}</small></span>
        </button>)}
      </div>
      {source === 'upload' && <div className="bk-restore-detail">
        <label className="upload-button">
          <Upload size={14} aria-hidden="true" /> {t('Choose backup files')}
          <input type="file" multiple accept=".tar.gz,application/gzip" onChange={(e) => { upload(e.target.files); e.target.value = ''; }} />
        </label>
        <p className="hint">{t('They go to the restore folder and are listed under This server.')}</p>
      </div>}
      {remote && <div className="bk-restore-detail">
        {targets.length === 0
          ? <p className="hint">{source === 'sftp' ? t('No SFTP destination yet. Add one in Destinations.') : t('No S3 destination yet. Add one in Destinations.')}</p>
          : <>
            <label className="bk-field">
              <span className="bk-label">{t('Destination')}</span>
              <select value={targetId} onChange={(e) => { setTargetId(e.target.value); setItems(null); setSelected([]); }}>
                {targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
              </select>
            </label>
            <button type="button" disabled={busy || !targetId} onClick={() => find()}><Search size={14} aria-hidden="true" /> {t('Find backups')}</button>
          </>}
      </div>}
    </fieldset>

    {source !== 'upload' && <fieldset className="bk-restore-step" disabled={running}>
      <legend><span className="bk-restore-num">2</span> {t('Choose the accounts')}</legend>
      {items === null
        ? <p className="hint">{remote ? t('Pick a destination and find its backups.') : t('Looking for backups...')}</p>
        : items.length === 0
          ? <EmptyState icon={RotateCcw} message={t('No account backups here.')} />
          : <>
            <div className="bk-restore-tools">
              <label className="bk-check-inline"><input type="checkbox" checked={allChosen} onChange={chooseAll} disabled={!usable.length} /> {t('All ({count})', { count: usable.length })}</label>
              <button type="button" className="secondary-light mini" disabled={!usable.length} onClick={chooseNewest}><UserCheck size={13} aria-hidden="true" /> {t('Newest of each account')}</button>
            </div>
            <div className="data-table-wrap bk-restore-table">
              <table className="data-table">
                <thead><tr><th aria-label={t('Choose')} /><th>{t('Account')}</th><th>{t('Date')}</th><th>{t('Size')}</th><th>{t('File')}</th></tr></thead>
                <tbody>
                  {items.map((item) => {
                    const key = keyOf(item);
                    return <tr key={key} className={item.valid ? '' : 'invalid'}>
                      <td><input type="checkbox" aria-label={t('Choose {name}', { name: nameOf(item) })} disabled={!item.valid}
                        checked={selected.includes(key)} onChange={() => toggle(key)} /></td>
                      <td>{item.valid ? <strong>{item.username || t('unknown user')}</strong> : <span className="data-table-muted">{remote ? t('Not an account backup') : (item.error || t('Invalid backup'))}</span>}</td>
                      <td>{when(dateOf(item))}</td>
                      <td>{formatBytes(item.size)}</td>
                      <td><code>{nameOf(item)}</code>{!remote && item.folder && <small className="bk-restore-folder">{item.folder === 'restore' ? t('restore folder') : item.folder === 'uploads' ? t('uploaded') : item.folder}</small>}</td>
                    </tr>;
                  })}
                </tbody>
              </table>
            </div>
          </>}
    </fieldset>}

    {source !== 'upload' && <div className="bk-restore-go">
      <span className="hint">{selected.length
        ? t('{count} backup(s) chosen: {users}', { count: selected.length, users: chosenUsers.join(', ') })
        : t('Nothing chosen yet.')}</span>
      <button type="button" disabled={busy || running || !selected.length} onClick={restore}><RotateCcw size={14} aria-hidden="true" /> {t('Restore')}</button>
    </div>}
  </div>;
}
