import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertCircle, CalendarDays, Check, CloudDownload, HardDrive, Loader2, Network, RotateCcw, Search, Upload, X } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
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
// are, which of them, one button. Each account is one row, its backups a
// list of dates with the newest chosen. The restore runs on the server, one
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
  // The accounts ticked, and the backup chosen for each - its newest until
  // another date is picked.
  const [ticked, setTicked] = useState([]);
  const [picked, setPicked] = useState({});
  const [findAccount, setFindAccount] = useState('');
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

  const accountOf = (item) => item.username || nameOf(item);
  function clearChoice() { setTicked([]); setPicked({}); }

  async function find(nextSource = source, nextTarget = targetId) {
    clearChoice();
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
    clearChoice();
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

  // Every account's backups, newest first; the accounts by name.
  const groups = useMemo(() => {
    const byAccount = new Map();
    for (const item of (items || []).filter((one) => one.valid)) {
      const account = accountOf(item);
      if (!byAccount.has(account)) byAccount.set(account, []);
      byAccount.get(account).push(item);
    }
    return [...byAccount.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([account, list]) => ({
        account,
        backups: list.sort((a, b) => String(dateOf(b)).localeCompare(String(dateOf(a))) || nameOf(b).localeCompare(nameOf(a))),
      }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);
  const invalid = useMemo(() => (items || []).filter((item) => !item.valid), [items]);
  const chosenOf = (group) => group.backups.find((item) => keyOf(item) === picked[group.account]) || group.backups[0];
  const chosen = groups.filter((group) => ticked.includes(group.account)).map(chosenOf);
  const allChosen = groups.length > 0 && groups.every((group) => ticked.includes(group.account));
  const toggle = (account) => setTicked((prev) => (prev.includes(account) ? prev.filter((a) => a !== account) : [...prev, account]));
  const chooseAll = () => setTicked(allChosen ? [] : groups.map((group) => group.account));
  // A date picked is an account meant.
  function pickDate(account, key) {
    setPicked((prev) => ({ ...prev, [account]: key }));
    setTicked((prev) => (prev.includes(account) ? prev : [...prev, account]));
  }

  async function restore() {
    if (!chosen.length) return;
    const question = t('Restore {count} backup(s)? An account that already exists is overwritten: its websites\' files and its databases are replaced by the backup\'s.', { count: chosen.length });
    if (!confirm(question)) return;
    const started = await startRestore(remote ? source : 'local', remote ? targetId : '', chosen.map(keyOf));
    if (started) { finishedRef.current = ''; setJob(started); clearChoice(); }
  }

  async function upload(files) {
    const done = await uploadUserBackups(files);
    if (done) { setSource('local'); find('local', ''); }
  }

  // What a finished restore brought back, in a line.
  function outcome(done) {
    const back = done.items.filter((item) => item.status === 'done');
    const names = back.map((item) => item.username || item.name).join(', ');
    if (done.failed > 0) {
      return back.length
        ? t('Restored {names}; {failed} could not be restored:', { names, failed: done.failed })
        : t('Nothing was restored:');
    }
    if (back.length === 1) {
      return t('Restored {name}: {sites} website(s), {databases} database(s).', { name: names, sites: back[0].websites, databases: back[0].databases });
    }
    return t('Restored {count} accounts: {names}.', { count: back.length, names });
  }

  // As every date of the panel reads: 2026-09-27 03:00.
  const when = (text) => formatWhen(text);
  const needle = findAccount.trim().toLowerCase();
  const shown = needle ? groups.filter((group) => group.account.toLowerCase().includes(needle)) : groups;
  const folderOf = (item) => (!remote && item.folder === 'restore' ? t('restore folder') : !remote && item.folder === 'uploads' ? t('uploaded') : '');

  return <div className="bk-restore">
    {job && <section className={`bk-restore-job ${job.status}${!running && job.failed ? ' bad' : ''}`} aria-live="polite">
      <div className="bk-restore-job-head">
        {running ? <Loader2 size={16} className="spin" aria-hidden="true" /> : job.failed ? <AlertCircle size={16} aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}
        <strong>{running
          ? t('Restoring {done} of {total}...', { done: job.done + job.failed + 1 > job.total ? job.total : job.done + job.failed + 1, total: job.total })
          : outcome(job)}</strong>
        {running && job.source !== 'local' && <small>{t('From {name}', { name: job.target_name })}</small>}
        {!running && <button type="button" className="bk-restore-job-close" onClick={() => setJob(null)} aria-label={t('Hide')} title={t('Hide')}><X size={15} aria-hidden="true" /></button>}
      </div>
      {/* While it runs, every account's progress; once done, only what failed. */}
      {(running || job.failed > 0) && <ol className="bk-restore-steps">
        {job.items.filter((item) => running || item.status === 'error').map((item) => <li key={item.file} className={item.status}>
          <span className={`badge ${item.status === 'done' ? 'ok' : item.status === 'error' ? 'bad' : ''}`}>{ITEM_STATES[item.status] ? t(ITEM_STATES[item.status]) : item.status}</span>
          <span className="bk-restore-step-text">
            <strong>{item.username || item.name}</strong>
            <small>{item.status === 'done'
              ? t('{sites} website(s), {databases} database(s)', { sites: item.websites, databases: item.databases })
              : item.message || item.name}</small>
          </span>
        </li>)}
      </ol>}
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
              <select value={targetId} onChange={(e) => { setTargetId(e.target.value); setItems(null); clearChoice(); }}>
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
              <label className="bk-check-inline"><input type="checkbox" checked={allChosen} onChange={chooseAll} disabled={!groups.length} /> {t('All ({count})', { count: groups.length })}</label>
              {groups.length > 6 && <input type="search" className="bk-restore-find" value={findAccount} onChange={(e) => setFindAccount(e.target.value)}
                placeholder={t('Find an account')} aria-label={t('Find an account')} />}
            </div>
            <ul className="bk-accounts">
              {shown.map((group) => {
                const item = chosenOf(group);
                const on = ticked.includes(group.account);
                const folder = folderOf(item);
                return <li key={group.account} className={`bk-account${on ? ' on' : ''}`} title={nameOf(item)}>
                  <label className="bk-account-who">
                    <input type="checkbox" checked={on} onChange={() => toggle(group.account)} aria-label={t('Choose {name}', { name: group.account })} />
                    <span className="bk-account-avatar" aria-hidden="true">{group.account.slice(0, 1).toUpperCase()}</span>
                    <span className="bk-account-name">
                      <strong>{group.account}</strong>
                      <small>{group.backups.length === 1 ? t('1 backup') : t('{count} backups', { count: group.backups.length })}{folder && <span className="bk-account-folder">{folder}</span>}</small>
                    </span>
                  </label>
                  <label className="bk-account-date">
                    <CalendarDays size={15} aria-hidden="true" />
                    <select aria-label={t('Date of the backup of {name}', { name: group.account })} value={keyOf(item)} onChange={(e) => pickDate(group.account, e.target.value)}>
                      {group.backups.map((backup) => <option key={keyOf(backup)} value={keyOf(backup)}>{when(dateOf(backup)) || nameOf(backup)}</option>)}
                    </select>
                  </label>
                  <span className="bk-account-size">{formatBytes(item.size)}</span>
                </li>;
              })}
            </ul>
            {shown.length === 0 && <p className="hint">{t('No account matches {text}.', { text: findAccount.trim() })}</p>}
            {invalid.length > 0 && <details className="bk-restore-invalid">
              <summary>{t('{count} file(s) here are not account backups', { count: invalid.length })}</summary>
              <ul>{invalid.map((item) => <li key={keyOf(item)}><code>{nameOf(item)}</code><small>{remote ? t('Not an account backup') : (item.error || t('Invalid backup'))}</small></li>)}</ul>
            </details>}
          </>}
    </fieldset>}

    {source !== 'upload' && <div className={`bk-restore-go${chosen.length ? ' ready' : ''}`}>
      <span className="bk-restore-chosen">{chosen.length
        ? <><strong>{t('{count} chosen', { count: chosen.length })}</strong> {chosen.map((item) => `${accountOf(item)} · ${when(dateOf(item)) || nameOf(item)}`).join(', ')}</>
        : t('Nothing chosen yet.')}</span>
      <button type="button" disabled={busy || running || !chosen.length} onClick={restore}><RotateCcw size={14} aria-hidden="true" /> {t('Restore')}</button>
    </div>}
  </div>;
}
