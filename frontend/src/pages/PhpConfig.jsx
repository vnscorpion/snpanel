import { AlertCircle, Ban, Check, Cpu, Play, RotateCcw } from 'lucide-react';
import { sortPhpVersions } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';

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

  function renderPhpConfig() {
    if (!isAdmin) return <section className="section"><h2>PHP config</h2><p className="hint">You do not have permission to edit PHP config.</p></section>;
    const notInstalled = sortPhpVersions(phpVersions.supported.filter(v => !phpVersions.installed.includes(v)));
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
        <div><h2>PHP Configuration</h2></div>
      </div>
      <div className="user-create-card">
        <label><span>PHP version</span><select value={phpConfig.php_version} onChange={e => { const v = e.target.value; setPhpConfig(prev => ({ ...prev, php_version: v })); loadPhpConfig(v); loadPhpTune(v); }}>
          {phpVersions.installed.map(v => <option key={v} value={v}>PHP {v}</option>)}
        </select></label>
        <label><span>display_errors</span><select value={phpConfig.display_errors} onChange={e => setPhpConfig(prev => ({ ...prev, display_errors: e.target.value }))}>
          <option value="Off">Off (production)</option><option value="On">On (debug)</option>
        </select></label>
        <label><span>max_execution_time</span><input type="number" value={phpConfig.max_execution_time} onChange={e => setPhpConfig(prev => ({ ...prev, max_execution_time: e.target.value }))} /></label>
        <label><span>max_input_time</span><input type="number" value={phpConfig.max_input_time} onChange={e => setPhpConfig(prev => ({ ...prev, max_input_time: e.target.value }))} /></label>
        <label><span>max_input_vars</span><input type="number" value={phpConfig.max_input_vars} onChange={e => setPhpConfig(prev => ({ ...prev, max_input_vars: e.target.value }))} /></label>
        <label><span>memory_limit</span><input value={phpConfig.memory_limit} onChange={e => setPhpConfig(prev => ({ ...prev, memory_limit: e.target.value }))} placeholder="1024M" /></label>
        <label><span>post_max_size</span><input value={phpConfig.post_max_size} onChange={e => setPhpConfig(prev => ({ ...prev, post_max_size: e.target.value }))} placeholder="1024M" /></label>
        <label><span>upload_max_filesize</span><input value={phpConfig.upload_max_filesize} onChange={e => setPhpConfig(prev => ({ ...prev, upload_max_filesize: e.target.value }))} placeholder="1024M" /></label>
        <button className="secondary-light" disabled={!!loading} onClick={restorePhpDefaults}><RotateCcw size={14}/> Restore defaults</button>
        <button disabled={!!loading} onClick={updatePhpConfig}>Save</button>
        {phpTune && tuneChanges.length > 0 && <div className="php-tune-diff">
          <strong><AlertCircle size={14}/> Auto tune PHP {phpTune.php_version} sẽ đổi {tuneChanges.length} thông số</strong>
          <span>{tuneChanges.map(row => `${row.key} ${row.current || 'chưa đặt'} → ${row.value}`).join(', ')}.</span>
          <button className="mini" disabled={!!loading} onClick={applyPhpTune}>Auto tune PHP</button>
        </div>}
        {phpTune && tuneChanges.length === 0 && <div className="notice php-tune-diff">
          <Check size={14}/> PHP {phpTune.php_version} đã khớp khuyến nghị auto tune cho máy này ({phpTune.facts.cpu_count} CPU, {phpTune.facts.total_memory_mb} MB RAM).
        </div>}
      </div>
      {phpTune && <div className="php-tune" style={{ marginTop: 16 }}>
        <div className="php-tune-actions">
          <button disabled={!!loading} onClick={applyPhpTune}><Cpu size={14}/> Auto tune PHP</button>
          <button className="secondary-light" disabled={!!loading} onClick={toggleOpcache}>
            {phpTune.opcache_enabled
              ? <><Ban size={14}/> Tắt OPcache (PHP {phpTune.php_version})</>
              : <><Play size={14}/> Bật OPcache (PHP {phpTune.php_version})</>}
          </button>
        </div>
        {phpTuneApplied && <div className="notice php-tune-result">
          <strong><Check size={14}/> Đã tối ưu PHP {phpTune.php_version} xong.</strong>
        </div>}
        {commonPools && <p className="hint">
          Pool PHP-FPM: {commonPools.length}/{phpTune.pools.length} pool đang chạy pm.max_children={commonPools[0].max_children || '—'},
          idle {commonPools[0].idle_timeout || '—'}, tối đa {commonPools[0].max_requests || '—'} request/tiến trình.
          {poolOutliers.length > 0 && ` ${poolOutliers.length} pool khác đang chạy thông số khác:`}
        </p>}
        {poolOutliers.length > 0 && <ul className="php-tune-pool-outliers">
          {poolOutliers.map(p => <li key={p.pool}>
            <code>{p.pool}</code>
            <span>pm.max_children={p.max_children || '—'}, idle {p.idle_timeout || '—'}, tối đa {p.max_requests || '—'} request</span>
          </li>)}
        </ul>}
      </div>}
      {notInstalled.length > 0 && <div className="user-create-card" style={{ marginTop: 16 }}>
        <h3>Install PHP</h3>
        <div className="php-install-grid">
          {notInstalled.map(v => <button key={v} disabled={!!loading} onClick={() => installPhpVersion(v)}>+ PHP {v}</button>)}
        </div>
      </div>}
    </section>;
  }

  return renderPhpConfig();
}
