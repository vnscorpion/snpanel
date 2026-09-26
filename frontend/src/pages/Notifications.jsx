import { useEffect, useMemo, useRef, useState } from 'react';
import { Bell, Boxes, Link2, Mail, RefreshCw, Save, Send, Trash2, Unlink } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { serverText, useLocale, useT } from '../i18n/index.jsx';
import './Notifications.css';

const SECURITY_PORTS = { starttls: 587, tls: 465, none: 25 };

// Settings, Notifications: how messages go out (the administrator's SMTP
// server and Telegram bot), where this account is told and of what, and -
// for an administrator - what was sent. See crate::notify.
export default function NotificationsPage() {
  const {
    EmptyState,
    checkTelegramLink,
    isAdmin,
    loadNotificationLog,
    loadNotifications,
    loading,
    navigateToPage,
    notificationLog,
    notifications,
    removeSmtp,
    removeTelegramBot,
    saveNotificationDefaults,
    saveNotificationPrefs,
    saveSmtp,
    saveTelegramBot,
    sendTestNotification,
    setTelegramChat,
    startTelegramLink,
    unlinkTelegram,
  } = usePanel();
  const t = useT();
  const { locale } = useLocale();
  const busy = !!loading;
  const n = notifications || {};
  const me = n.me || {};
  const channels = n.channels || {};
  const emailReady = !!channels.email?.ready;
  const botReady = !!channels.telegram?.ready;

  // ---- the administrator's forms
  const [smtp, setSmtp] = useState({ host: '', port: 587, security: 'starttls', username: '', password: '', from_address: '', from_name: '' });
  const [token, setToken] = useState('');
  const [testTo, setTestTo] = useState('');
  useEffect(() => {
    if (!n.loaded) return;
    setSmtp(n.smtp
      ? { ...n.smtp, password: '' }
      : { host: '', port: 587, security: 'starttls', username: '', password: '', from_address: '', from_name: '' });
  }, [n.loaded, n.smtp?.host, n.smtp?.port, n.smtp?.security, n.smtp?.username, n.smtp?.from_address, n.smtp?.from_name]);

  // ---- this account's
  const [mine, setMine] = useState({ email_enabled: true, email: '', telegram_enabled: true, language: '' });
  useEffect(() => {
    if (!n.loaded) return;
    setMine({
      email_enabled: me.email_enabled !== false,
      email: me.email || '',
      telegram_enabled: me.telegram_enabled !== false,
      language: me.language || '',
    });
  }, [n.loaded, me.email_enabled, me.email, me.telegram_enabled, me.language]);
  const [chat, setChat] = useState('');
  const [link, setLink] = useState(null);
  const polling = useRef(null);

  useEffect(() => () => clearInterval(polling.current), []);
  useEffect(() => { if (isAdmin && n.installed) loadNotificationLog(); }, [isAdmin, n.installed]);

  const smtpField = (key) => ({ value: smtp[key] ?? '', onChange: (e) => setSmtp((prev) => ({ ...prev, [key]: e.target.value })) });
  const smtpReady = smtp.host.trim() && Number(smtp.port) > 0 && smtp.from_address.trim();

  function chooseSecurity(value) {
    setSmtp((prev) => ({
      ...prev,
      security: value,
      // The port follows the choice while it is still one of the usual three.
      port: Object.values(SECURITY_PORTS).includes(Number(prev.port)) ? SECURITY_PORTS[value] : prev.port,
    }));
  }

  async function submitSmtp(event) {
    event.preventDefault();
    await saveSmtp({ ...smtp, port: Number(smtp.port) });
  }

  async function submitBot(event) {
    event.preventDefault();
    if (await saveTelegramBot(token.trim())) setToken('');
  }

  async function submitMine(event) {
    event.preventDefault();
    await saveNotificationPrefs({ ...mine, email: mine.email.trim() });
  }

  async function beginLink() {
    const started = await startTelegramLink();
    if (!started) return;
    setLink(started);
    clearInterval(polling.current);
    const until = Date.now() + (started.expires_in || 600) * 1000;
    polling.current = setInterval(async () => {
      if (Date.now() > until) {
        clearInterval(polling.current);
        setLink(null);
        return;
      }
      const answer = await checkTelegramLink();
      if (answer?.linked) {
        clearInterval(polling.current);
        setLink(null);
        await loadNotifications();
      }
    }, 3000);
  }

  function stopLink() {
    clearInterval(polling.current);
    setLink(null);
  }

  const EVENT_TEXT = {
    backup_failed: [t('A backup of yours failed'), t('A scheduled backup of your account, or one you started, did not finish.')],
    backup_done: [t('A backup of yours finished'), t('Each time - leave it off if backups run every day.')],
    malware: [t('Malware on your websites'), t('What a scan found, and what was moved to quarantine.')],
    ssl_expiring: [t('A certificate about to expire'), t('An SSL certificate of your websites that renewal has not renewed, a week before it ends.')],
    storage_full: [t('Storage nearly full'), t('Your account has used 90% of its storage.')],
    sign_in: [t('A sign-in from a new address'), t('Someone signed in to your account from an address it has not used before.')],
    security: [t('Changes to how you sign in'), t('Your password, two-step verification, passkeys, AI assistant tokens and SFTP passwords.')],
    server_backup_failed: [t('A scheduled backup failed'), t('Any schedule, for any account.')],
    server_backup_done: [t('A scheduled backup finished'), t('Each run - leave it off for daily schedules.')],
    server_malware: [t('Malware on any website'), t('Every scan that finds something, on every account.')],
    server_ssl_expiring: [t('Any certificate about to expire'), t('Checked once a day, a week before the end.')],
    disk_low: [t('The disk nearly full'), t('90% of the server\'s disk used.')],
    service_down: [t('A service stopped'), t('nginx, PHP-FPM, MariaDB or Redis seen stopped twice, five minutes apart - and again when it runs.')],
    panel_update: [t('A new SNPanel release'), t('Once per release.')],
    server_storage_full: [t('An account nearly out of storage'), t('Any account at 90% of its storage.')],
  };
  const events = n.events || [];
  const ownEvents = events.filter((e) => !e.admin);
  const serverEvents = events.filter((e) => e.admin);
  const toggle = (key) => saveNotificationPrefs({ events: { [key]: !me.events?.[key] } });

  const logLabel = useMemo(() => Object.fromEntries(Object.entries(EVENT_TEXT).map(([k, v]) => [k, v[0]])), [locale]);

  if (n.loaded && !n.installed) {
    return <section className="section notif-page">
      <h2>{t('Notifications')}</h2>
      <EmptyState icon={Bell} message={t('The Notifications addon is not installed on this panel.')} />
      {isAdmin && <div className="addon-missing-actions"><button type="button" onClick={() => navigateToPage('addons')}><Boxes size={14} aria-hidden="true"/> {t('Go to Addons')}</button></div>}
    </section>;
  }

  const eventList = (list, title, hint, id) => <section className="section" aria-labelledby={id}>
    <h2 id={id}>{title}</h2>
    {hint && <p className="hint">{hint}</p>}
    <ul className="notif-events">
      {list.map((e) => <li key={e.key}>
        <label className="notif-event">
          <input type="checkbox" role="switch" checked={!!me.events?.[e.key]} disabled={busy} onChange={() => toggle(e.key)} />
          <span>
            <strong>{EVENT_TEXT[e.key]?.[0] || e.key}</strong>
            <small>{EVENT_TEXT[e.key]?.[1]}</small>
          </span>
        </label>
      </li>)}
    </ul>
  </section>;

  return <div className="notif-page">
    {isAdmin && <section className="section" aria-labelledby="notif-channels-title">
      <div className="notif-head">
        <div>
          <h2 id="notif-channels-title">{t('How messages go out')}</h2>
          <p className="hint">{t('Set up e-mail, Telegram or both. Every account then chooses where it is told, and of what.')}</p>
        </div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={loadNotifications} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      <div className="notif-channel-grid">
        <form className="notif-card" onSubmit={submitSmtp} aria-labelledby="notif-smtp-title">
          <div className="notif-card-head">
            <Mail size={18} aria-hidden="true"/>
            <h3 id="notif-smtp-title">{t('E-mail (SMTP)')}</h3>
            <span className={`badge ${emailReady ? 'ok' : ''}`}>{emailReady ? t('Set up') : t('Not set up')}</span>
          </div>
          <p className="hint">{t('Your mail host\'s SMTP server, or a service such as Gmail (smtp.gmail.com, STARTTLS 587, with an app password), SendGrid or Amazon SES.')}</p>
          <div className="notif-fields">
            <div className="notif-field notif-wide">
              <label htmlFor="smtp-host">{t('SMTP server')}</label>
              <input id="smtp-host" {...smtpField('host')} placeholder="smtp.example.com" autoComplete="off" spellCheck={false} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-security">{t('Security')}</label>
              <select id="smtp-security" value={smtp.security} onChange={(e) => chooseSecurity(e.target.value)}>
                <option value="starttls">{t('STARTTLS (usually port 587)')}</option>
                <option value="tls">{t('SSL/TLS (usually port 465)')}</option>
                <option value="none">{t('None - a relay on this server only')}</option>
              </select>
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-port">{t('Port')}</label>
              <input id="smtp-port" inputMode="numeric" {...smtpField('port')} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-user">{t('User name')}</label>
              <input id="smtp-user" {...smtpField('username')} autoComplete="off" spellCheck={false} placeholder={t('Empty: no sign-in')} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-password">{t('Password')}</label>
              <input id="smtp-password" type="password" {...smtpField('password')} autoComplete="new-password"
                placeholder={n.smtp?.password_set ? t('Saved - empty keeps it') : ''} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-from">{t('Sender address')}</label>
              <input id="smtp-from" {...smtpField('from_address')} placeholder="panel@example.com" autoComplete="off" spellCheck={false} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-from-name">{t('Sender name')}</label>
              <input id="smtp-from-name" {...smtpField('from_name')} placeholder="SNPanel" autoComplete="off" />
            </div>
          </div>
          <div className="notif-actions">
            {emailReady && <button type="button" className="secondary-light danger-hover" disabled={busy} onClick={removeSmtp}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>}
            <button type="submit" disabled={busy || !smtpReady}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
          </div>
          {emailReady && <div className="notif-test">
            <label htmlFor="smtp-test-to">{t('Send a test to')}</label>
            <input id="smtp-test-to" value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder={me.email || me.account_email || ''} autoComplete="off" />
            <button type="button" className="secondary-light" disabled={busy} onClick={() => sendTestNotification('email', testTo.trim())}><Send size={14} aria-hidden="true"/> {t('Send a test')}</button>
          </div>}
        </form>

        <form className="notif-card" onSubmit={submitBot} aria-labelledby="notif-bot-title">
          <div className="notif-card-head">
            <Send size={18} aria-hidden="true"/>
            <h3 id="notif-bot-title">{t('Telegram')}</h3>
            <span className={`badge ${botReady ? 'ok' : ''}`}>{botReady ? `@${channels.telegram.bot}` : t('Not set up')}</span>
          </div>
          <ol className="notif-steps">
            <li>{t('In Telegram, open @BotFather and send /newbot. Give the bot a name.')}</li>
            <li>{t('Copy the token it answers with - it looks like 123456789:AA... - and paste it here.')}</li>
            <li>{t('Give the panel a bot of its own: another program reading the same bot would take its messages.')}</li>
          </ol>
          <div className="notif-field">
            <label htmlFor="bot-token">{botReady ? t('A new bot token') : t('Bot token')}</label>
            <input id="bot-token" type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false} placeholder="123456789:AA..." />
          </div>
          <div className="notif-actions">
            {botReady && <button type="button" className="secondary-light danger-hover" disabled={busy} onClick={removeTelegramBot}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>}
            <button type="submit" disabled={busy || !token.trim()}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
          </div>
        </form>
      </div>
      <div className="notif-default-language">
        <label htmlFor="notif-default-language">{t('Language of messages for accounts that have not chosen')}</label>
        <select id="notif-default-language" value={n.language || 'vi'} disabled={busy} onChange={(e) => saveNotificationDefaults(e.target.value)}>
          <option value="vi">Tiếng Việt</option>
          <option value="en">English</option>
        </select>
      </div>
    </section>}

    <section className="section" aria-labelledby="notif-mine-title">
      <div className="notif-head">
        <div>
          <h2 id="notif-mine-title">{t('Where you are told')}</h2>
          <p className="hint">{t('Messages about your account, and - as an administrator - about the server.')}</p>
        </div>
        {!isAdmin && <button type="button" className="secondary icon-button" disabled={busy} onClick={loadNotifications} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>}
      </div>
      <form className="notif-mine" onSubmit={submitMine}>
        <div className={`notif-way ${emailReady ? '' : 'off'}`}>
          <label className="switch-line">
            <input type="checkbox" checked={mine.email_enabled} disabled={busy || !emailReady} onChange={(e) => setMine((prev) => ({ ...prev, email_enabled: e.target.checked }))} />
            <span><Mail size={15} aria-hidden="true"/> {t('By e-mail')}</span>
          </label>
          {emailReady
            ? <div className="notif-field">
              <label htmlFor="notif-email">{t('Address')}</label>
              <input id="notif-email" type="email" value={mine.email} onChange={(e) => setMine((prev) => ({ ...prev, email: e.target.value }))} placeholder={me.account_email || ''} autoComplete="email" />
              <small className="hint">{t('Empty: your account\'s address, {address}.', { address: me.account_email || '-' })}</small>
            </div>
            : <p className="hint">{t('The administrator has not set up e-mail yet.')}</p>}
        </div>

        <div className={`notif-way ${botReady ? '' : 'off'}`}>
          <label className="switch-line">
            <input type="checkbox" checked={mine.telegram_enabled} disabled={busy || !botReady} onChange={(e) => setMine((prev) => ({ ...prev, telegram_enabled: e.target.checked }))} />
            <span><Send size={15} aria-hidden="true"/> {t('On Telegram')}</span>
          </label>
          {!botReady && <p className="hint">{t('The administrator has not set up Telegram yet.')}</p>}
          {botReady && me.telegram?.linked && <div className="notif-linked">
            <span className="badge ok">{t('Linked: {name}', { name: me.telegram.name || '-' })}</span>
            <button type="button" className="secondary-light" disabled={busy} onClick={() => sendTestNotification('telegram')}><Send size={14} aria-hidden="true"/> {t('Send a test')}</button>
            <button type="button" className="secondary-light danger-hover" disabled={busy} onClick={unlinkTelegram}><Unlink size={14} aria-hidden="true"/> {t('Unlink')}</button>
          </div>}
          {botReady && !me.telegram?.linked && !link && <div className="notif-linked">
            <button type="button" disabled={busy} onClick={beginLink}><Link2 size={14} aria-hidden="true"/> {t('Link Telegram')}</button>
          </div>}
          {link && <div className="notif-linking" role="status">
            <p>{t('Open the link, and press Start in the chat with @{bot}. This page notices by itself.', { bot: link.bot })}</p>
            <div className="notif-linked">
              <a className="button-link" href={link.url} target="_blank" rel="noreferrer noopener"><Send size={14} aria-hidden="true"/> {t('Open Telegram')}</a>
              <button type="button" className="secondary-light" onClick={stopLink}>{t('Cancel')}</button>
            </div>
            <small className="hint">{t('On a computer without Telegram, send /start {code} to @{bot} from your phone.', { code: link.code, bot: link.bot })}</small>
          </div>}
          {botReady && !link && <details className="notif-chat">
            <summary>{t('A group or a channel instead')}</summary>
            <p className="hint">{t('Add @{bot} to the group or channel, then enter its chat id - a group\'s starts with -100. A test message is sent to prove the bot can post there.', { bot: channels.telegram.bot })}</p>
            <div className="notif-linked">
              <input aria-label={t('Chat id')} value={chat} onChange={(e) => setChat(e.target.value)} placeholder="-1001234567890" autoComplete="off" />
              <button type="button" className="secondary-light" disabled={busy || !chat.trim()} onClick={async () => { if (await setTelegramChat(chat.trim())) setChat(''); }}>{t('Use this chat')}</button>
            </div>
          </details>}
        </div>

        <div className="notif-way">
          <div className="notif-field">
            <label htmlFor="notif-language">{t('Language of your messages')}</label>
            <select id="notif-language" value={mine.language} onChange={(e) => setMine((prev) => ({ ...prev, language: e.target.value }))}>
              <option value="">{t('The panel\'s default')}</option>
              <option value="vi">Tiếng Việt</option>
              <option value="en">English</option>
            </select>
          </div>
        </div>
        <div className="notif-actions">
          {emailReady && <button type="button" className="secondary-light" disabled={busy} onClick={() => sendTestNotification('email')}><Mail size={14} aria-hidden="true"/> {t('Send me a test e-mail')}</button>}
          <button type="submit" disabled={busy}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
        </div>
      </form>
    </section>

    {eventList(ownEvents, t('What you are told of'), t('About your own account and websites.'), 'notif-own-title')}
    {isAdmin && serverEvents.length > 0 && eventList(serverEvents, t('What you are told of the server'), t('For administrators: about every account and the machine itself.'), 'notif-server-title')}

    {isAdmin && <section className="section" aria-labelledby="notif-log-title">
      <div className="notif-head">
        <h2 id="notif-log-title">{t('Recently sent')}</h2>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={loadNotificationLog} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      {(notificationLog || []).length === 0
        ? <EmptyState icon={Bell} message={t('Nothing has been sent yet.')} />
        : <div className="data-table-wrap">
          <table className="data-table notif-log">
            <thead><tr>
              <th scope="col">{t('When')}</th>
              <th scope="col">{t('What')}</th>
              <th scope="col">{t('To')}</th>
              <th scope="col">{t('Result')}</th>
            </tr></thead>
            <tbody>
              {notificationLog.map((row) => <tr key={row.id}>
                <td>{formatWhen(row.created_at)}</td>
                <td><strong>{row.event === 'test' ? t('Test') : (logLabel[row.event] || row.event)}</strong><small>{row.subject}</small></td>
                <td>{row.username}<small>{row.channel === 'email' ? t('E-mail') : 'Telegram'} · {row.target}</small></td>
                <td>{row.status === 'sent'
                  ? <span className="badge ok">{t('Sent')}</span>
                  : <><span className="badge bad">{t('Failed')}</span><small>{serverText(row.detail)}</small></>}</td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </section>}
  </div>;
}
