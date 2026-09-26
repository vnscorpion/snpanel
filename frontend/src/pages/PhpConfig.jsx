import { AlertCircle, Ban, Check, Cpu, Play, RotateCcw } from 'lucide-react';
import { sortPhpVersions } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './PhpConfig.css';

// SNPanel's floor for each limit - the API refuses anything lower, and the
// defaults are these - and the helper's ceiling.
const COUNTS = [
  ['max_execution_time', 300, 3600, msg('At least {value} seconds')],
  ['max_input_time', 600, 3600, msg('At least {value} seconds')],
  ['max_input_vars', 10000, 1000000, msg('At least {value}')],
];
const SIZES = ['memory_limit', 'post_max_size', 'upload_max_filesize'];
const MIN_SIZE_MB = 1024;

// PHP's shorthand - 1024M, 2G, 524288K, or bytes - in MB; null when it is
// not a size at all.
function sizeMb(value) {
  const match = /^\s*(\d{1,12})([KMG]?)\s*$/i.exec(String(value ?? ''));
  if (!match) return null;
  const n = Number(match[1]);
  const unit = match[2].toUpperCase();
  if (unit === 'G') return n * 1024;
  if (unit === 'M') return n;
  return Math.floor(unit === 'K' ? n / 1024 : n / 1048576);
}

// What is wrong with one limit, as a message and its values, or null.
function limitProblem(key, value) {
  const text = String(value ?? '').trim();
  const count = COUNTS.find(([name]) => name === key);
  if (count) {
    const [, lo, hi, atLeast] = count;
    const n = Number(text);
    if (text === '' || !Number.isInteger(n) || n < lo) return [atLeast, { value: lo }];
    if (n > hi) return [msg('At most {value}'), { value: hi }];
    return null;
  }
  const mb = sizeMb(text);
  if (mb === null) return [msg('A size such as 1024M or 2G'), {}];
  if (mb < MIN_SIZE_MB) return [msg('At least {value}'), { value: `${MIN_SIZE_MB}M` }];
  return null;
}

// The note under a limit that is fine: its floor.
function limitFloor(key) {
  const count = COUNTS.find(([name]) => name === key);
  return count ? [count[3], { value: count[1] }] : [msg('At least {value}'), { value: `${MIN_SIZE_MB}M` }];
}

export default function PhpConfigPage() {
  const {
    applyPhpTune,
    installPhpVersion,
    isAdmin,
    loadPhpConfig,
    loadPhpTune,
    loading,
    phpConfig,
    phpTune,
    phpTuneApplied,
    phpVersions,
    restorePhpDefaults,
    setPhpConfig,
    toggleOpcache,
    updatePhpConfig,
  } = usePanel();
  const t = useT();

  function renderPhpConfig() {
    if (!isAdmin) return <section className="section"><h2>{t('PHP config')}</h2><p className="hint">{t('You do not have permission to edit PHP config.')}</p></section>;
    const notInstalled = sortPhpVersions(phpVersions.supported.filter(v => !phpVersions.installed.includes(v)));
    const limits = [
      ...COUNTS.map(([key, lo, hi]) => ({ key, count: true, lo, hi })),
      ...SIZES.map(key => ({ key, count: false })),
    ].map(item => ({ ...item, problem: limitProblem(item.key, phpConfig[item.key]) }));
    const invalid = limits.some(item => item.problem);
    // The only thing worth an administrator's attention: settings Auto tune
    // would actually change. A row that already matches, or one pinned by the
    // form below (it always wins - PHP reads it last), is not a decision to
    // make, so it does not belong in a list someone has to read every time.
    const tuneChanges = (phpTune?.settings || []).filter(row => row.changes && !row.overridden_value);
    // Every pool on a server is sized from the same CPU/RAM/pool-count budget,
    // so they normally all carry identical numbers - a row per pool (this test
    // box alone has 49) is a wall of the same four numbers repeated. Collapse
    // to "N/N pools run X", and only list the ones that do not match: those are
    // the only ones worth an administrator's attention.
    const poolKey = p => `${p.max_children}|${p.idle_timeout}|${p.max_requests}|${p.request_terminate_timeout}`;
    const poolGroups = {};
    (phpTune?.pools || []).forEach(p => { (poolGroups[poolKey(p)] ||= []).push(p); });
    const [commonPools, ...restPoolGroups] = Object.values(poolGroups).sort((a, b) => b.length - a.length);
    const poolOutliers = restPoolGroups.flat();
    return <section className="section">
      <div className="section-title">
        <div><h2>{t('PHP Configuration')}</h2></div>
      </div>
      <div className="user-create-card php-config-card">
        <label><span>{t('PHP version')}</span><select value={phpConfig.php_version} onChange={e => { const v = e.target.value; setPhpConfig(prev => ({ ...prev, php_version: v })); loadPhpConfig(v); loadPhpTune(v); }}>
          {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
        </select></label>
        <label><span>display_errors</span><select value={phpConfig.display_errors} onChange={e => setPhpConfig(prev => ({ ...prev, display_errors: e.target.value }))}>
          <option value="Off">{t('Off (production)')}</option><option value="On">{t('On (debug)')}</option>
        </select></label>
        {limits.map(({ key, count, lo, hi, problem }) => {
          const [note, values] = problem || limitFloor(key);
          return <label key={key} className="php-limit">
            <span>{key}</span>
            <input type={count ? 'number' : 'text'} min={count ? lo : undefined} max={count ? hi : undefined}
              inputMode={count ? 'numeric' : undefined} value={phpConfig[key]} placeholder={count ? String(lo) : '1024M'}
              onChange={e => { const value = e.target.value; setPhpConfig(prev => ({ ...prev, [key]: value })); }}
              aria-invalid={problem ? 'true' : undefined} aria-describedby={`php-limit-${key}`} spellCheck={false} autoComplete="off" />
            <small id={`php-limit-${key}`} className={problem ? 'php-limit-note bad' : 'php-limit-note'}>{t(note, values)}</small>
          </label>;
        })}
        <button className="secondary-light" disabled={!!loading} onClick={restorePhpDefaults}><RotateCcw size={14}/> {t('Restore defaults')}</button>
        <button disabled={!!loading || invalid} onClick={updatePhpConfig}
          title={invalid ? t('Fix the values marked in red first.') : undefined}>{t('Save')}</button>
        {phpTune && tuneChanges.length > 0 && <div className="php-tune-diff">
          <strong><AlertCircle size={14}/> {t('Auto tune for PHP {version} will change {count} setting(s)', { version: phpTune.php_version, count: tuneChanges.length })}</strong>
          <span>{tuneChanges.map(row => `${row.key} ${row.current || t('not set')} → ${row.value}`).join(', ')}.</span>
          <button className="mini" disabled={!!loading} onClick={applyPhpTune}>{t('Auto tune PHP')}</button>
        </div>}
        {phpTune && tuneChanges.length === 0 && <div className="notice php-tune-diff">
          <Check size={14}/> {t('PHP {version} already matches the auto tune recommendation for this server ({cpus} CPU, {memory} MB RAM).', { version: phpTune.php_version, cpus: phpTune.facts.cpu_count, memory: phpTune.facts.total_memory_mb })}
        </div>}
      </div>
      {phpTune && <div className="php-tune" style={{ marginTop: 16 }}>
        <div className="php-tune-actions">
          <button disabled={!!loading} onClick={applyPhpTune}><Cpu size={14}/> {t('Auto tune PHP')}</button>
          <button className="secondary-light" disabled={!!loading} onClick={toggleOpcache}>
            {phpTune.opcache_enabled
              ? <><Ban size={14}/> {t('Turn off OPcache (PHP {version})', { version: phpTune.php_version })}</>
              : <><Play size={14}/> {t('Turn on OPcache (PHP {version})', { version: phpTune.php_version })}</>}
          </button>
        </div>
        {phpTuneApplied && <div className="notice php-tune-result">
          <strong><Check size={14}/> {t('PHP {version} is tuned.', { version: phpTune.php_version })}</strong>
        </div>}
        {commonPools && <p className="hint">
          {t('PHP-FPM pools: {running}/{total} running pm.max_children={children}, idle {idle}, at most {requests} requests per process.', { running: commonPools.length, total: phpTune.pools.length, children: commonPools[0].max_children || '—', idle: commonPools[0].idle_timeout || '—', requests: commonPools[0].max_requests || '—' })}
          {poolOutliers.length > 0 && ` ${t('{count} other pool(s) run different settings:', { count: poolOutliers.length })}`}
        </p>}
        {poolOutliers.length > 0 && <ul className="php-tune-pool-outliers">
          {poolOutliers.map(p => <li key={p.pool}>
            <code>{p.pool}</code>
            <span>{t('pm.max_children={children}, idle {idle}, at most {requests} requests', { children: p.max_children || '—', idle: p.idle_timeout || '—', requests: p.max_requests || '—' })}</span>
          </li>)}
        </ul>}
      </div>}
      {notInstalled.length > 0 && <div className="user-create-card" style={{ marginTop: 16 }}>
        <h3>{t('Install PHP')}</h3>
        <div className="php-install-grid">
          {notInstalled.map(v => <button key={v} className="secondary-light" disabled={!!loading} onClick={() => installPhpVersion(v)}>+ {t('PHP {version}', { version: v })}</button>)}
        </div>
      </div>}
    </section>;
  }

  return renderPhpConfig();
}
