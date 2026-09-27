import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertCircle, CalendarDays, Check, HardDrive, Loader2, Network, RefreshCw, RotateCcw, Server, ShieldAlert, Upload, X } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './BackupRestore.css';

const SOURCES = [
  { id: 'local', icon: HardDrive, title: msg('This server'), text: msg('Backups kept here, and archives uploaded.') },
  { id: 'destination', icon: Network, title: msg('Backup destination'), text: msg('A saved SFTP or S3 destination.') },
  { id: 'connection', icon: Server, title: msg('Another server'), text: msg('SFTP, FTP or FTPS.') },
];
const PROTOCOLS = [
  { id: 'sftp', label: 'SFTP', port: 22 },
  { id: 'ftp', label: 'FTP', port: 21 },
  { id: 'ftps', label: 'FTPS', port: 21 },
];
const NO_CONNECTION = { protocol: 'sftp', host: '', port: '', username: '', password: '', folder: '' };
const ITEM_STATES = {
  queued: msg('Waiting'),
  fetching: msg('Downloading'),
  restoring: msg('Restoring'),
  done: msg('Restored'),
  error: msg('Failed'),
};

// Accounts put back from their backups, in four steps: where the backups
// are - this server, a saved destination, or another server given by hand -
// then that source (with an upload and a refresh beside it), the accounts
// found there, and one button. Each account is one card, its backups a list
// of dates with the newest chosen. The restore runs on the server, one
// account after another, and the page follows it - also when it is opened
// again part-way through.
export default function BackupRestore() {
  const {
    EmptyState,
    formatBytes,
    listRestoreConnection,
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
  // A saved destination: 'sftp:<id>' or 's3:<id>'.
  const [destination, setDestination] = useState('');
  // Another server: how to reach it, and what its listing learned - the SFTP
  // host key the restore insists on, an FTPS certificate to trust.
  const [connection, setConnection] = useState(NO_CONNECTION);
  const [learned, setLearned] = useState({});
  const [items, setItems] = useState(null);
  // The accounts ticked, and the backup chosen for each - its newest until
  // another date is picked.
  const [ticked, setTicked] = useState([]);
  const [picked, setPicked] = useState({});
  const [findAccount, setFindAccount] = useState('');
  const [job, setJob] = useState(null);
  const finishedRef = useRef('');
  const fileInput = useRef(null);
  // Which listing is the newest: an older one still on its way is dropped.
  const listing = useRef(0);
  const busy = !!loading;
  const remote = source !== 'local';
  const running = job?.status === 'running';
  const destinations = [
    ...sftpTargets.map((target) => ({ value: `sftp:${target.id}`, name: target.name, kind: 'SFTP' })),
    ...s3Targets.map((target) => ({ value: `s3:${target.id}`, name: target.name, kind: 'S3' })),
  ];
  const protocol = PROTOCOLS.find((p) => p.id === connection.protocol) || PROTOCOLS[0];
  const connectionReady = !!(connection.host.trim() && connection.username.trim() && connection.password);

  // The key a restore names an archive by: its path here, its name there.
  const keyOf = (item) => (remote ? item.name : item.backup_file);
  const nameOf = (item) => (remote ? item.name : (item.filename || String(item.backup_file).split('/').pop()));
  const dateOf = (item) => item.generated_at || item.modified || '';
  const accountOf = (item) => item.username || nameOf(item);
  function clearChoice() { setTicked([]); setPicked({}); }

  // What the connection is sent as: the form, and what its listing learned.
  const connectionBody = (extra = {}) => ({
    ...connection,
    port: connection.port || protocol.port,
    host_key: learned.host_key?.fingerprint || '',
    certificate: learned.certificate || '',
    ...extra,
  });

  async function refresh(nextSource = source, nextDestination = destination, extra = {}) {
    const ticket = ++listing.current;
    const newest = () => ticket === listing.current;
    clearChoice();
    setItems(null);
    if (nextSource === 'local') {
      const found = await listRestoreSource('local', '');
      if (newest()) setItems(found || []);
    } else if (nextSource === 'destination') {
      const [kind, id] = String(nextDestination).split(':');
      if (!id) return;
      const found = await listRestoreSource(kind, id);
      if (newest()) setItems(found || []);
    } else {
      if (!connectionReady) return;
      const found = await listRestoreConnection(connectionBody(extra));
      // Not reached: the error says why, and step 3 waits for Refresh.
      if (!newest() || !found) return;
      setLearned({ host_key: found.host_key, certificate: found.certificate || extra.certificate || '', untrusted: found.untrusted });
      setItems(found.untrusted ? null : (found.items || []));
    }
  }

  function choose(next) {
    if (running || next === source) return;
    listing.current += 1;
    setSource(next);
    setItems(null);
    clearChoice();
    if (next === 'local') refresh('local');
    if (next === 'destination') {
      const first = destinations[0]?.value || '';
      setDestination(first);
      if (first) refresh('destination', first);
    }
  }

  // Another server changed: what its last listing learned is not its.
  function editConnection(key, value) {
    setConnection((prev) => ({ ...prev, [key]: value }));
    if (['protocol', 'host', 'port', 'username'].includes(key)) { listing.current += 1; setLearned({}); setItems(null); clearChoice(); }
  }

  function trust() {
    const fingerprint = learned.untrusted?.fingerprint;
    if (fingerprint) refresh('connection', destination, { certificate: fingerprint });
  }

  // What is running, or ran last, when the page opens.
  useEffect(() => {
    let live = true;
    loadRestoreJob().then((found) => { if (live && found) { setJob(found); if (found.status !== 'running') finishedRef.current = found.id; } });
    refresh('local');
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
        if (source === 'local') refresh('local');
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
    const files = chosen.map(keyOf);
    const [kind, id] = String(destination).split(':');
    const started = source === 'local'
      ? await startRestore('local', '', files)
      : source === 'destination'
        ? await startRestore(kind, id, files)
        : await startRestore('connection', '', files, connectionBody());
    if (started) { finishedRef.current = ''; setJob(started); clearChoice(); }
  }

  // An upload lands on this server, and is listed there.
  async function upload(files) {
    const done = await uploadUserBackups(files);
    if (done) { setSource('local'); refresh('local'); }
  }

  // As every date of the panel reads: 2026-09-27 03:00.
  const when = (text) => formatWhen(text);
  const needle = findAccount.trim().toLowerCase();
  const shown = needle ? groups.filter((group) => group.account.toLowerCase().includes(needle)) : groups;
  const folderOf = (item) => (!remote && item.folder === 'restore' ? t('restore folder') : !remote && item.folder === 'uploads' ? t('uploaded') : '');

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

  const stepTwo = source === 'local' ? t('Backups on this server') : source === 'destination' ? t('Choose the destination') : t('Connect to the server');
  const canRefresh = source === 'local' || (source === 'destination' ? !!destination : connectionReady);
  const waiting = source === 'local' ? t('Looking for backups...')
    : source === 'destination' ? (destinations.length ? t('Choose a destination.') : t('No destination yet: add one in Destinations.'))
      : learned.untrusted ? t('Trust the certificate, or check the server.') : t('Enter the server, then press Refresh.');

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
    </fieldset>

    <fieldset className="bk-restore-step" disabled={running}>
      <legend><span className="bk-restore-num">2</span> {stepTwo}</legend>
      {source === 'destination' && (destinations.length === 0
        ? <p className="hint bk-restore-note">{t('No destination yet: add one in Destinations.')}</p>
        : <label className="bk-field bk-restore-destination">
          <span className="bk-label">{t('Destination')}</span>
          <select value={destination} onChange={(e) => { setDestination(e.target.value); refresh('destination', e.target.value); }}>
            {['SFTP', 'S3'].map((kind) => destinations.some((d) => d.kind === kind) && <optgroup key={kind} label={kind}>
              {destinations.filter((d) => d.kind === kind).map((d) => <option key={d.value} value={d.value}>{d.name}</option>)}
            </optgroup>)}
          </select>
        </label>)}
      {source === 'connection' && <form className="bk-connection" autoComplete="off" onSubmit={(e) => e.preventDefault()}
        onKeyDown={(e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); if (canRefresh && !busy) refresh('connection'); } }}>
        <label className="bk-field">
          <span className="bk-label">{t('Protocol')}</span>
          <select value={connection.protocol} onChange={(e) => editConnection('protocol', e.target.value)}>
            {PROTOCOLS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
        </label>
        <label className="bk-field bk-connection-host">
          <span className="bk-label">{t('Server')}</span>
          <input value={connection.host} onChange={(e) => editConnection('host', e.target.value)} placeholder="backup.example.com" spellCheck={false} />
        </label>
        <label className="bk-field">
          <span className="bk-label">{t('Port')}</span>
          <input inputMode="numeric" value={connection.port} onChange={(e) => editConnection('port', e.target.value.replace(/\D/g, ''))} placeholder={String(protocol.port)} />
        </label>
        <label className="bk-field">
          <span className="bk-label">{t('User name')}</span>
          <input value={connection.username} onChange={(e) => editConnection('username', e.target.value)} spellCheck={false} autoComplete="off" />
        </label>
        <label className="bk-field">
          <span className="bk-label">{t('Password')}</span>
          <input type="password" value={connection.password} onChange={(e) => editConnection('password', e.target.value)} autoComplete="new-password" />
        </label>
        <label className="bk-field">
          <span className="bk-label">{t('Folder')}</span>
          <input value={connection.folder} onChange={(e) => editConnection('folder', e.target.value)} placeholder="/backups" spellCheck={false} />
        </label>
        {connection.protocol === 'ftp' && <p className="hint bk-connection-note">{t('FTP sends the password unencrypted.')}</p>}
        {learned.host_key?.fingerprint && <p className="hint bk-connection-note">{t('Host key')}: <code>{learned.host_key.type} {learned.host_key.fingerprint}</code></p>}
        {learned.untrusted && <div className="bk-trust" role="alert">
          <ShieldAlert size={16} aria-hidden="true" />
          <span>{t('The certificate of {host} is not one this machine trusts.', { host: connection.host.trim() })}<small>SHA-256 <code>{learned.untrusted.fingerprint}</code></small></span>
          <button type="button" className="secondary-light" disabled={busy} onClick={trust}>{t('Trust this certificate')}</button>
        </div>}
      </form>}
      <div className="bk-restore-actions">
        <input ref={fileInput} type="file" multiple accept=".tar.gz,application/gzip" hidden onChange={(e) => { upload(e.target.files); e.target.value = ''; }} />
        <button type="button" className="secondary-light" disabled={busy} onClick={() => fileInput.current?.click()}><Upload size={14} aria-hidden="true" /> {t('Upload backup')}</button>
        <button type="button" className="secondary-light" disabled={busy || !canRefresh} onClick={() => refresh()}><RefreshCw size={14} aria-hidden="true" /> {t('Refresh')}</button>
      </div>
    </fieldset>

    <fieldset className="bk-restore-step" disabled={running}>
      <legend><span className="bk-restore-num">3</span> {t('Accounts to restore')}</legend>
      {items === null
        ? <p className="hint bk-restore-note">{waiting}</p>
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
    </fieldset>

    <div className={`bk-restore-go${chosen.length ? ' ready' : ''}`}>
      <span className="bk-restore-num" aria-hidden="true">4</span>
      <span className="bk-restore-chosen">{chosen.length
        ? <><strong>{t('{count} chosen', { count: chosen.length })}</strong> {chosen.map((item) => `${accountOf(item)} · ${when(dateOf(item)) || nameOf(item)}`).join(', ')}</>
        : t('Nothing chosen yet.')}</span>
      <button type="button" disabled={busy || running || !chosen.length} onClick={restore}><RotateCcw size={14} aria-hidden="true" /> {t('Restore')}</button>
    </div>
  </div>;
}
