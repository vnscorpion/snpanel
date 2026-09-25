import { Clock, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';

export default function CronPage() {
  const t = useT();
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
      ['php -q cron.php', msg('Path is relative to public_html.')],
      ['php cron.php >/dev/null 2>&1', msg('Discard output so cron does not try to mail it.')],
      ['php cron.php >> ../logs/cron.log 2>&1', msg('Keep output in a log file inside this website.')],
      ['wp cron event run --due-now', msg('WP-CLI, for WordPress sites.')],
    ];
    return <section className="section">
      <div className="section-title">
        <div><h2>{t('Cron manager')}</h2></div>
        <button disabled={!selectedWebsiteId || !!loading} onClick={listCron}><RefreshCw size={14}/> {t('Refresh')}</button>
      </div>
      <div className="cron-form">
        <WebsiteSelect />
        <input value={cronSchedule} onChange={e => setCronSchedule(e.target.value)} placeholder="*/15 * * * *" />
        <input value={cronCommand} onChange={e => setCronCommand(e.target.value)} placeholder="php -q cron.php >/dev/null 2>&1" />
        <button disabled={!selectedWebsiteId || !!loading} onClick={addCron}><Plus size={14}/> {t('Add cron')}</button>
      </div>
      {selectedWebsiteId && <p className="hint">{t('Cron runs as {user} for the selected website.', { user: <strong>{cronUser || currentSite?.linux_user || 'www-data'}</strong> })}</p>}
      {selectedWebsiteId && <div className="cron-help">
        <p>
          {sitePhpVersion
            ? t('Write {php} and SNPanel rewrites it to {binary} — the PHP {version} CLI this website is set to, so the job never runs on the server default version. Change the website\'s PHP version and its cron jobs follow.', { php: <code>php</code>, binary: <code>{sitePhpBinary}</code>, version: sitePhpVersion })
            : t('Write {php} and SNPanel rewrites it to {binary}, so the job never runs on the server default version. Change the website\'s PHP version and its cron jobs follow.', { php: <code>php</code>, binary: <code>{sitePhpBinary}</code> })}
        </p>
        <ul>
          {cronExamples.map(([example, note]) => <li key={example}>
            <button type="button" className="cron-example" onClick={() => setCronCommand(example)}>{example}</button>
            <small>{t(note)}</small>
          </li>)}
        </ul>
        <p className="cron-help-note">
          {t('Only PHP scripts inside {folder} and the safe WP-CLI maintenance commands are allowed. A trailing {a}, {b}, {c} or {d} may redirect to {null} or to a file inside this website.', { folder: <code>public_html</code>, a: <code>&gt;</code>, b: <code>&gt;&gt;</code>, c: <code>2&gt;</code>, d: <code>2&gt;&amp;1</code>, null: <code>/dev/null</code> })}
        </p>
      </div>}
      <div className="cron-list">
        {selectedWebsiteId && cronItems.length === 0 && <EmptyState icon={Clock} message={t('No cron jobs found for this website.')} />}
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
