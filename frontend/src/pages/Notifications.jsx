import { useEffect, useMemo, useState } from 'react';
import { Bell, Boxes, Mail, RefreshCw, Save, Search, Send, Trash2 } from 'lucide-react';
import { formatWhen } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';
import { serverText, useLocale, useT } from '../i18n/index.jsx';
import './Notifications.css';

const SECURITY_PORTS = { starttls: 587, tls: 465, none: 25 };
const EMPTY_SMTP = { host: '', port: 587, security: 'starttls', username: '', password: '', from_address: '', from_name: '', to: '' };

// Settings, Notifications - the administrators' alone: how messages go out
// (an SMTP server and the addresses it sends to, a Telegram bot and the chat
// it writes in), what is sent, and what was. Customers are sent nothing.
// See crate::notify.
export default function NotificationsPage() {
  const {
    EmptyState,
    findTelegramChats,
    isAdmin,
    loadNotificationLog,
    loadNotifications,
    loading,
    navigateToPage,
    notificationLog,
    notifications,
    removeSmtp,
    removeTelegramBot,
    saveNotificationSettings,
    saveSmtp,
    saveTelegram,
    sendTestNotification,
  } = usePanel();
  const t = useT();
  const { locale } = useLocale();
  const busy = !!loading;
  const n = notifications || {};
  const email = n.email || {};
  const telegram = n.telegram || {};
  const botSaved = !!telegram.bot;
  const adminList = (email.administrators || []).join(', ');

  // ---- e-mail
  const [smtp, setSmtp] = useState(EMPTY_SMTP);
  const [testTo, setTestTo] = useState('');
  const saved = email.smtp;
  const savedTo = (email.to || []).join(', ');
  useEffect(() => {
    if (!n.loaded) return;
    setSmtp(saved ? { ...saved, password: '', to: savedTo } : { ...EMPTY_SMTP, to: savedTo });
  }, [n.loaded, saved?.host, saved?.port, saved?.security, saved?.username, saved?.from_address, saved?.from_name, savedTo]);
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
    await saveSmtp({ ...smtp, port: Number(smtp.port), to: smtp.to.trim() });
  }

  // ---- Telegram
  const [token, setToken] = useState('');
  const [chatId, setChatId] = useState('');
  const [found, setFound] = useState(null);
  useEffect(() => { if (n.loaded) setChatId(telegram.chat_id || ''); }, [n.loaded, telegram.chat_id]);
  const canUseToken = !!token.trim() || botSaved;

  async function findChats() {
    const answer = await findTelegramChats(token.trim());
    if (!answer) return;
    setFound({ bot: answer.bot, chats: answer.chats || [] });
    // One chat is the one meant.
    if (answer.chats?.length === 1) setChatId(answer.chats[0].id);
  }

  async function submitTelegram(event) {
    event.preventDefault();
    if (await saveTelegram({ token: token.trim(), chat_id: chatId.trim() })) {
      setToken('');
      setFound(null);
      loadNotificationLog();
    }
  }

  useEffect(() => { if (isAdmin && n.installed) loadNotificationLog(); }, [isAdmin, n.installed]);

  const CHAT_KIND = { private: t('Person'), group: t('Group'), supergroup: t('Group'), channel: t('Channel') };
  const EVENT_TEXT = {
    backup_failed: [t('A backup failed'), t('A scheduled backup, or one someone started, of any account.')],
    backup_done: [t('A scheduled backup finished'), t('Each run - leave it off for daily schedules.')],
    malware: [t('Malware found'), t('What a scan found on any website, and what was moved to quarantine.')],
    ssl_expiring: [t('A certificate about to expire'), t('An SSL certificate renewal has not renewed, a week before it ends. Checked once a day.')],
    storage_full: [t('An account nearly out of storage'), t('A customer\'s account at 90% of its storage.')],
    disk_low: [t('The disk nearly full'), t('90% of the server\'s disk used.')],
    service_down: [t('A service stopped'), t('nginx, PHP-FPM, MariaDB or Redis seen stopped twice, five minutes apart - and again when it runs.')],
    panel_update: [t('A new SNPanel release'), t('Once per release.')],
    sign_in: [t('A sign-in from a new address'), t('To an administrator account, from an address it has not signed in from before.')],
    security: [t('Changes to an administrator account'), t('Its password, two-step verification, passkeys, AI assistant tokens and SFTP passwords - and a new administrator.')],
  };
  const GROUPS = [
    ['accounts', t('Websites and backups'), t('Of every account on the panel.')],
    ['server', t('The server'), ''],
    ['admins', t('Administrator accounts'), t('A customer\'s own sign-ins and passwords are not told.')],
  ];
  const events = n.events || [];
  const logLabel = useMemo(() => {
    const labels = Object.fromEntries(Object.entries(EVENT_TEXT).map(([k, v]) => [k, v[0]]));
    // The log's older rows, from when administrators had kinds of their own.
    for (const key of ['backup_failed', 'backup_done', 'malware', 'ssl_expiring', 'storage_full']) labels[`server_${key}`] = labels[key];
    return labels;
  }, [locale]);

  if (!isAdmin) {
    return <section className="section notif-page">
      <h2>{t('Notifications')}</h2>
      <EmptyState icon={Bell} message={t('Notifications go to the panel\'s administrators, and only they set them up.')} />
    </section>;
  }

  if (n.loaded && !n.installed) {
    return <section className="section notif-page">
      <h2>{t('Notifications')}</h2>
      <EmptyState icon={Bell} message={t('The Notifications addon is not installed on this panel.')} />
      <div className="addon-missing-actions"><button type="button" onClick={() => navigateToPage('addons')}><Boxes size={14} aria-hidden="true"/> {t('Go to Addons')}</button></div>
    </section>;
  }

  return <div className="notif-page">
    <section className="section" aria-labelledby="notif-channels-title">
      <div className="notif-head">
        <div>
          <h2 id="notif-channels-title">{t('How messages go out')}</h2>
          <p className="hint">{t('Messages go to the panel\'s administrators - by e-mail, on Telegram, or both. Customers are not sent anything.')}</p>
        </div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={() => { loadNotifications(); loadNotificationLog(); }} aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      {n.loaded && !n.ready && <p className="notif-callout" role="status">{t('Nothing is sent until e-mail, or a Telegram bot and its chat, is set up.')}</p>}
      <div className="notif-channel-grid">
        <form className="notif-card" onSubmit={submitSmtp} aria-labelledby="notif-smtp-title">
          <div className="notif-card-head">
            <Mail size={18} aria-hidden="true"/>
            <h3 id="notif-smtp-title">{t('E-mail (SMTP)')}</h3>
            <span className={`badge ${email.ready ? 'ok' : ''}`}>{email.ready ? t('Set up') : t('Not set up')}</span>
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
                placeholder={saved?.password_set ? t('Saved - empty keeps it') : ''} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-from">{t('Sender address')}</label>
              <input id="smtp-from" {...smtpField('from_address')} placeholder="panel@example.com" autoComplete="off" spellCheck={false} />
            </div>
            <div className="notif-field">
              <label htmlFor="smtp-from-name">{t('Sender name')}</label>
              <input id="smtp-from-name" {...smtpField('from_name')} placeholder="SNPanel" autoComplete="off" />
            </div>
            <div className="notif-field notif-wide">
              <label htmlFor="smtp-to">{t('Send to')}</label>
              <input id="smtp-to" {...smtpField('to')} placeholder={adminList || 'admin@example.com'} autoComplete="off" spellCheck={false} />
              <small className="hint">{adminList
                ? t('Addresses separated by commas. Empty: every administrator\'s own address - {addresses}.', { addresses: adminList })
                : t('Addresses separated by commas. No administrator account has an address of its own, so give at least one.')}</small>
            </div>
          </div>
          <div className="notif-actions">
            {email.ready && <button type="button" className="secondary-light danger-hover" disabled={busy} onClick={removeSmtp}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>}
            <button type="submit" disabled={busy || !smtpReady}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
          </div>
          {email.ready && <div className="notif-test">
            <label htmlFor="smtp-test-to">{t('Send a test to')}</label>
            <input id="smtp-test-to" value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder={t('Every address messages go to')} autoComplete="off" spellCheck={false} />
            <button type="button" className="secondary-light" disabled={busy} onClick={() => sendTestNotification('email', testTo.trim())}><Send size={14} aria-hidden="true"/> {t('Send a test')}</button>
          </div>}
        </form>

        <form className="notif-card" onSubmit={submitTelegram} aria-labelledby="notif-bot-title">
          <div className="notif-card-head">
            <Send size={18} aria-hidden="true"/>
            <h3 id="notif-bot-title">{t('Telegram')}</h3>
            <span className={`badge ${telegram.ready ? 'ok' : ''}`}>{telegram.ready ? `@${telegram.bot}` : t('Not set up')}</span>
          </div>
          {botSaved && !telegram.chat_id && <p className="notif-callout warn" role="status">{t('The bot @{bot} is saved, but not the chat it writes in: nothing goes to Telegram until it is.', { bot: telegram.bot })}</p>}
          <ol className="notif-steps">
            <li>{t('In Telegram, open @BotFather, send /newbot and copy the token it answers with - it looks like 123456789:AA...')}</li>
            <li>{t('Open your bot and press Start - or add it to a group of administrators, or to a channel as an administrator.')}</li>
            <li>{t('Press Find chat ID and choose the chat, or type its ID. Saving sends a test message there.')}</li>
          </ol>
          <div className="notif-field">
            <label htmlFor="bot-token">{t('Bot token')}</label>
            <input id="bot-token" type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false}
              placeholder={botSaved ? t('Saved - empty keeps it') : '123456789:AA...'} />
          </div>
          <div className="notif-field">
            <label htmlFor="bot-chat">{t('Chat ID')}</label>
            <div className="notif-chat-row">
              <input id="bot-chat" value={chatId} onChange={(e) => setChatId(e.target.value)} placeholder="123456789 / -1001234567890" autoComplete="off" spellCheck={false} />
              <button type="button" className="secondary-light" disabled={busy || !canUseToken} onClick={findChats}><Search size={14} aria-hidden="true"/> {t('Find chat ID')}</button>
            </div>
            <small className="hint">{telegram.chat_id
              ? t('Messages go to {chat}.', { chat: telegram.chat_name ? `${telegram.chat_name} (${telegram.chat_id})` : telegram.chat_id })
              : t('A person\'s or a group\'s number - a group\'s starts with -100 - or a channel\'s @name.')}</small>
          </div>
          {found && <div className="notif-found" role="region" aria-label={t('Chats found')}>
            {found.chats.length === 0
              ? <p className="hint">{t('No chat has written to @{bot} in the last day. Open the bot and press Start, or add it to the group, then look again.', { bot: found.bot })}</p>
              : <>
                <p className="hint">{t('Chats that wrote to @{bot} lately - choose one:', { bot: found.bot })}</p>
                <ul className="notif-chat-list">
                  {found.chats.map((c) => <li key={c.id}>
                    <button type="button" className={`notif-chat-pick ${chatId === c.id ? 'chosen' : ''}`} aria-pressed={chatId === c.id} onClick={() => setChatId(c.id)}>
                      <strong>{c.name || c.id}</strong>
                      <small>{CHAT_KIND[c.kind] || c.kind} · {c.id}</small>
                    </button>
                  </li>)}
                </ul>
              </>}
          </div>}
          <div className="notif-actions">
            {botSaved && <button type="button" className="secondary-light danger-hover" disabled={busy} onClick={removeTelegramBot}><Trash2 size={14} aria-hidden="true"/> {t('Remove')}</button>}
            {telegram.ready && <button type="button" className="secondary-light" disabled={busy} onClick={() => sendTestNotification('telegram')}><Send size={14} aria-hidden="true"/> {t('Send a test')}</button>}
            <button type="submit" disabled={busy || !chatId.trim() || !canUseToken}><Save size={14} aria-hidden="true"/> {t('Save')}</button>
          </div>
        </form>
      </div>
    </section>

    <section className="section" aria-labelledby="notif-events-title">
      <div className="notif-head">
        <div>
          <h2 id="notif-events-title">{t('What is sent')}</h2>
          <p className="hint">{t('The same for every administrator, by every way set up above.')}</p>
        </div>
        <div className="notif-language">
          <label htmlFor="notif-language">{t('Language of the messages')}</label>
          <select id="notif-language" value={n.language || 'vi'} disabled={busy} onChange={(e) => saveNotificationSettings({ language: e.target.value })}>
            <option value="vi">Tiếng Việt</option>
            <option value="en">English</option>
          </select>
        </div>
      </div>
      {GROUPS.map(([group, title, hint]) => {
        const list = events.filter((e) => e.group === group);
        if (list.length === 0) return null;
        return <div className="notif-group" key={group} role="group" aria-labelledby={`notif-group-${group}`}>
          <h3 id={`notif-group-${group}`}>{title}</h3>
          {hint && <p className="hint">{hint}</p>}
          <ul className="notif-events">
            {list.map((e) => <li key={e.key}>
              <label className="notif-event">
                <input type="checkbox" role="switch" checked={!!e.on} disabled={busy} onChange={() => saveNotificationSettings({ events: { [e.key]: !e.on } })} />
                <span>
                  <strong>{EVENT_TEXT[e.key]?.[0] || e.key}</strong>
                  <small>{EVENT_TEXT[e.key]?.[1]}</small>
                </span>
              </label>
            </li>)}
          </ul>
        </div>;
      })}
    </section>

    <section className="section" aria-labelledby="notif-log-title">
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
                <td>{row.channel === 'email' ? t('E-mail') : 'Telegram'}<small>{row.target}</small></td>
                <td>{row.status === 'sent'
                  ? <span className="badge ok">{t('Sent')}</span>
                  : <><span className="badge bad">{t('Failed')}</span><small>{serverText(row.detail)}</small></>}</td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </section>
  </div>;
}
