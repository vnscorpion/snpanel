import { Clock, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function CronPage() {
  const {
    EmptyState,
    WebsiteSelect,
    addCron,
    cronCommand,
    cronItems,
    cronPhpInfo,
    cronSchedule,
    cronUser,
    currentSite,
    deleteCron,
    listCron,
    loading,
    selectedWebsiteId,
    setCronCommand,
    setCronSchedule,
  } = usePanel();

  function renderCron() {
    const sitePhpVersion = cronPhpInfo.php_version || currentSite?.php_version || '';
    const sitePhpBinary = cronPhpInfo.php_binary || (sitePhpVersion ? `/usr/bin/php${sitePhpVersion}` : 'php');
    const cronExamples = [
      ['php -q cron.php', 'Path is relative to public_html.'],
      ['php cron.php >/dev/null 2>&1', 'Discard output so cron does not try to mail it.'],
      ['php cron.php >> ../logs/cron.log 2>&1', 'Keep output in a log file inside this website.'],
      ['wp cron event run --due-now', 'WP-CLI, for WordPress sites.'],
    ];
    return <section className="section">
      <div className="section-title">
        <div><h2>Cron manager</h2></div>
        <button disabled={!selectedWebsiteId || !!loading} onClick={listCron}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="cron-form">
        <WebsiteSelect />
        <input value={cronSchedule} onChange={e => setCronSchedule(e.target.value)} placeholder="*/15 * * * *" />
        <input value={cronCommand} onChange={e => setCronCommand(e.target.value)} placeholder="php -q cron.php >/dev/null 2>&1" />
        <button disabled={!selectedWebsiteId || !!loading} onClick={addCron}><Plus size={14}/> Add cron</button>
      </div>
      {selectedWebsiteId && <p className="hint">Cron runs as <strong>{cronUser || currentSite?.linux_user || 'www-data'}</strong> for the selected website.</p>}
      {selectedWebsiteId && <div className="cron-help">
        <p>
          Write <code>php</code> and SNPanel rewrites it to <code>{sitePhpBinary}</code>
          {sitePhpVersion ? <> — the PHP {sitePhpVersion} CLI this website is set to</> : null}, so the job never
          runs on the server default version. Change the website's PHP version and its cron jobs follow.
        </p>
        <ul>
          {cronExamples.map(([example, note]) => <li key={example}>
            <button type="button" className="cron-example" onClick={() => setCronCommand(example)}>{example}</button>
            <small>{note}</small>
          </li>)}
        </ul>
        <p className="cron-help-note">
          Only PHP scripts inside <code>public_html</code> and the safe WP-CLI maintenance commands are allowed.
          A trailing <code>&gt;</code>, <code>&gt;&gt;</code>, <code>2&gt;</code> or <code>2&gt;&amp;1</code> may
          redirect to <code>/dev/null</code> or to a file inside this website.
        </p>
      </div>}
      <div className="cron-list">
        {selectedWebsiteId && cronItems.length === 0 && <EmptyState icon={Clock} message="No cron jobs found for this website." />}
        {cronItems.map(item => <div className="cron-item" key={`${item.index}-${item.line}`}>
          <span className="badge">#{item.index}</span>
          <span><strong>{item.schedule}</strong><small>{item.command || item.line}</small></span>
          <button className="mini danger" disabled={!!loading} onClick={() => deleteCron(item.index)}><Trash2 size={13}/></button>
        </div>)}
      </div>
    </section>;
  }

  return renderCron();
}
