import { useEffect, useState } from 'react';
import { AlertTriangle, Ban, Boxes, RefreshCw, ShieldBan, ShieldCheck, ShieldOff, ShieldQuestion, UserCheck } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import './Fail2ban.css';

// The panel's jails, in the order the API lists them: a name for people and
// what each one watches. A jail somebody added by hand has neither and is
// shown by its own name.
const JAIL_TEXT = {
  sshd: [msg('SSH'), msg('Sign-ins to SSH, on every port sshd listens on.')],
  'snpanel-login': [msg('Panel sign-in'), msg('Wrong passwords and codes on this panel\'s sign-in page.')],
  'snpanel-wordpress': [msg('WordPress sign-in'), msg('Failed sign-ins to wp-login.php on every site. Cloudflare\'s addresses are never banned.')],
  'nginx-http-auth': [msg('Password-protected folders'), msg('Wrong passwords for folders protected with a password, on every site.')],
  recidive: [msg('Repeat offenders'), msg('An address banned again and again in a day is banned for a week, on every port.')],
};

const BAN_TIMES = [
  [600, msg('10 minutes')], [1800, msg('30 minutes')], [3600, msg('1 hour')], [21600, msg('6 hours')],
  [86400, msg('1 day')], [604800, msg('1 week')], [2592000, msg('30 days')],
];
const WINDOWS = [
  [300, msg('5 minutes')], [600, msg('10 minutes')], [1800, msg('30 minutes')], [3600, msg('1 hour')], [86400, msg('1 day')],
];

// The presets, plus the saved value when it is not one of them - set through
// the API, say - so the select never shows something other than the truth.
function durationOptions(presets, value, t) {
  const options = presets.map(([seconds, label]) => [seconds, t(label)]);
  if (!presets.some(([seconds]) => seconds === value)) options.push([value, t('{count} seconds', { count: value })]);
  return options.sort((a, b) => a[0] - b[0]);
}

const lines = (text) => text.split('\n').map((line) => line.trim()).filter(Boolean);

function draftFrom(settings) {
  return { ...settings, ignoreipText: settings.ignoreip.join('\n') };
}

function payloadFrom(draft, extraExempt) {
  return {
    ignoreip: [...lines(draft.ignoreipText), ...(extraExempt ? [extraExempt] : [])],
    bantime: Number(draft.bantime),
    findtime: Number(draft.findtime),
    maxretry: Number(draft.maxretry),
    jails: draft.jails,
  };
}

const STATE_ICON = { loading: ShieldQuestion, on: ShieldCheck, off: ShieldOff };

export default function Fail2banPage() {
  const {
    EmptyState,
    addons,
    fail2ban,
    fail2banBan,
    fail2banUnban,
    isAdmin,
    loadFail2ban,
    loading,
    navigateToPage,
    saveFail2banSettings,
  } = usePanel();
  const t = useT();
  const [draft, setDraft] = useState(null);
  const [banAddress, setBanAddress] = useState('');
  const [banJail, setBanJail] = useState('recidive');

  const settings = fail2ban?.settings;
  // A fresh copy whenever the server's settings arrive - after a save or a
  // refresh - so the form never shows something the server does not have.
  useEffect(() => { if (settings) setDraft(draftFrom(settings)); }, [settings]);

  const installed = !!addons.items.find((addon) => addon.slug === 'fail2ban')?.installed;
  if (!isAdmin) return <section className="section"><h2>Fail2ban</h2><p className="hint">{t('No permission.')}</p></section>;
  if (addons.loaded && !installed) {
    return <section className="section">
      <div className="section-title"><div><h2>Fail2ban</h2></div></div>
      <EmptyState icon={ShieldBan} message={t('The Fail2ban addon is not installed on this server.')} />
      <div className="site-app-form-actions">
        <button type="button" disabled={!!loading} onClick={() => navigateToPage('addons')}><Boxes size={14} aria-hidden="true"/> {t('Go to Addons')}</button>
      </div>
    </section>;
  }

  const busy = !!loading;
  const service = fail2ban?.service;
  const jails = fail2ban?.jails || [];
  const bans = jails.flatMap((jail) => (jail.banned || []).map((address) => ({ address, jail: jail.name })));
  const bannedNow = new Set(bans.map((ban) => ban.address)).size;
  const state = !fail2ban ? 'loading' : service?.running ? 'on' : 'off';
  const StateIcon = STATE_ICON[state];
  const you = fail2ban?.your_address;
  const jailName = (name) => (JAIL_TEXT[name] ? t(JAIL_TEXT[name][0]) : name);

  // A ban goes into a jail that runs; the default is the one that covers
  // every port, when it does.
  const banJails = jails.filter((jail) => jail.managed && jail.enabled && jail.running);
  const chosenJail = banJails.some((jail) => jail.name === banJail) ? banJail : banJails[0]?.name || '';

  const dirty = !!(draft && settings) && (
    Number(draft.bantime) !== settings.bantime
    || Number(draft.findtime) !== settings.findtime
    || Number(draft.maxretry) !== settings.maxretry
    || lines(draft.ignoreipText).join('\n') !== settings.ignoreip.join('\n')
    || [...draft.jails].sort().join() !== [...settings.jails].sort().join());
  const draftExemptsYou = !!(draft && you) && lines(draft.ignoreipText).includes(you);

  const change = (field) => (event) => setDraft((prev) => ({ ...prev, [field]: event.target.value }));
  const toggleJail = (name, on) => setDraft((prev) => ({
    ...prev,
    jails: on ? [...prev.jails.filter((jail) => jail !== name), name] : prev.jails.filter((jail) => jail !== name),
  }));

  async function ban(event) {
    event.preventDefault();
    if (await fail2banBan(chosenJail, banAddress.trim())) setBanAddress('');
  }

  return <div className="f2b-page">
    <section className="section f2b-status" data-state={state}>
      <div className="f2b-status-head">
        <span className="f2b-status-icon"><StateIcon size={22} aria-hidden="true"/></span>
        <div className="f2b-status-text">
          <h2>{{ loading: t('Loading Fail2ban…'), on: t('Fail2ban is running'), off: t('Fail2ban is not running') }[state]}</h2>
          {state === 'on' && <p className="hint">{t('Banned right now: {count}', { count: bannedNow })}{service?.version ? ` · fail2ban ${service.version}` : ''}</p>}
          {state === 'off' && <p className="hint">{t('Nobody is being banned. Reinstall the addon, or look at journalctl -u fail2ban on the server.')}</p>}
        </div>
        <button type="button" className="secondary icon-button" disabled={busy} onClick={loadFail2ban}
          aria-label={t('Refresh')} title={t('Refresh')}><RefreshCw size={16} aria-hidden="true"/></button>
      </div>
      {you && (fail2ban.your_address_exempt
        ? <p className="f2b-you"><ShieldCheck size={15} aria-hidden="true"/> {t('Your address, {address}, is never banned.', { address: you })}</p>
        : <p className="f2b-you f2b-you-warn">
          <AlertTriangle size={15} aria-hidden="true"/>
          <span>{t('Your address, {address}, is not on the never-ban list: a few wrong passwords would lock you out.', { address: you })}</span>
          <button type="button" className="mini secondary-light" disabled={busy || !draft} onClick={() => saveFail2banSettings(payloadFrom(draft, draftExemptsYou ? null : you))}>
            <UserCheck size={14} aria-hidden="true"/> {t('Never ban it')}
          </button>
        </p>)}
    </section>

    <section className="section">
      <div className="f2b-section-head">
        <h2>{t('Banned addresses')}</h2>
        <p className="hint">{t('A ban ends by itself when its time is up. Unbanning lets the address back in at once, from every jail.')}</p>
      </div>
      <form className="f2b-ban-form" onSubmit={ban}>
        <div className="f2b-field">
          <label htmlFor="f2b-ban-address">{t('Address')}</label>
          <input id="f2b-ban-address" value={banAddress} onChange={(event) => setBanAddress(event.target.value)} placeholder="203.0.113.7" spellCheck="false" autoComplete="off" />
        </div>
        <div className="f2b-field">
          <label htmlFor="f2b-ban-jail">{t('Jail')}</label>
          <select id="f2b-ban-jail" value={chosenJail} onChange={(event) => setBanJail(event.target.value)} disabled={banJails.length === 0}>
            {banJails.map((jail) => <option key={jail.name} value={jail.name}>{jailName(jail.name)}</option>)}
          </select>
        </div>
        <button type="submit" className="danger" disabled={busy || !banAddress.trim() || !chosenJail}><Ban size={15} aria-hidden="true"/> {t('Ban')}</button>
      </form>
      {bans.length === 0
        ? <p className="empty-note">{t('Nobody is banned right now.')}</p>
        : <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr>
              <th scope="col">{t('Address')}</th>
              <th scope="col">{t('Jail')}</th>
              <th scope="col"><span className="sr-only">{t('Unban')}</span></th>
            </tr></thead>
            <tbody>
              {bans.map((ban) => <tr key={`${ban.jail} ${ban.address}`}>
                <td><code>{ban.address}</code></td>
                <td>{jailName(ban.jail)}</td>
                <td className="data-table-actions">
                  <button type="button" className="mini secondary-light" disabled={busy} onClick={() => fail2banUnban(ban.address)}
                    aria-label={t('Unban {address}', { address: ban.address })}>{t('Unban')}</button>
                </td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </section>

    {draft && <form className="section f2b-settings" onSubmit={(event) => { event.preventDefault(); saveFail2banSettings(payloadFrom(draft)); }}>
      <div className="f2b-section-head">
        <h2>{t('Jails')}</h2>
        <p className="hint">{t('Each jail watches one kind of sign-in and bans the addresses that keep failing it.')}</p>
      </div>
      <ul className="f2b-jails">
        {jails.map((jail) => {
          const [, about] = JAIL_TEXT[jail.name] || [];
          const on = jail.managed ? draft.jails.includes(jail.name) : true;
          return <li key={jail.name} className="f2b-jail">
            {/* Named by the jail and described by what it watches: a label
                around both would read the whole sentence as the name. */}
            <label className="f2b-jail-toggle">
              <input type="checkbox" checked={on} disabled={!jail.managed}
                aria-label={jailName(jail.name)} aria-describedby={`f2b-about-${jail.name}`}
                onChange={(event) => toggleJail(jail.name, event.target.checked)} />
              <span className="f2b-jail-text">
                <strong>{jailName(jail.name)}</strong>
                <span className="hint" id={`f2b-about-${jail.name}`}>{about ? t(about) : t('Added outside the panel. Change it in fail2ban\'s own files.')}</span>
              </span>
            </label>
            <span className="f2b-jail-stats">
              {jail.running
                ? <>
                  <span>{t('{count} banned now', { count: jail.currently_banned })}</span>
                  <span>{t('{count} banned in all', { count: jail.total_banned })}</span>
                  <span>{t('{count} failing', { count: jail.currently_failed })}</span>
                </>
                : <span className="data-table-muted">{jail.enabled ? t('Starts when you save') : t('Off')}</span>}
            </span>
          </li>;
        })}
      </ul>

      <div className="f2b-section-head">
        <h2>{t('When to ban')}</h2>
      </div>
      <div className="f2b-timing">
        <div className="f2b-field">
          <label htmlFor="f2b-maxretry">{t('Failures before a ban')}</label>
          <input id="f2b-maxretry" type="number" min="1" max="100" value={draft.maxretry} onChange={change('maxretry')} />
        </div>
        <div className="f2b-field">
          <label htmlFor="f2b-findtime">{t('Counted over')}</label>
          <select id="f2b-findtime" value={Number(draft.findtime)} onChange={change('findtime')}>
            {durationOptions(WINDOWS, Number(draft.findtime), t).map(([seconds, label]) => <option key={seconds} value={seconds}>{label}</option>)}
          </select>
        </div>
        <div className="f2b-field">
          <label htmlFor="f2b-bantime">{t('Banned for')}</label>
          <select id="f2b-bantime" value={Number(draft.bantime)} onChange={change('bantime')}>
            {durationOptions(BAN_TIMES, Number(draft.bantime), t).map(([seconds, label]) => <option key={seconds} value={seconds}>{label}</option>)}
          </select>
        </div>
      </div>
      <div className="f2b-field f2b-exempt">
        <label htmlFor="f2b-never-ban">{t('Never ban')}</label>
        <textarea id="f2b-never-ban" rows={4} value={draft.ignoreipText} onChange={change('ignoreipText')} placeholder={'203.0.113.7\n198.51.100.0/24'}
          spellCheck="false" aria-describedby="f2b-never-ban-hint" />
        <p className="hint" id="f2b-never-ban-hint">{t('One address or network per line. This server itself is never banned.')}</p>
      </div>
      <div className="f2b-actions">
        {you && !draftExemptsYou && <button type="button" className="secondary" disabled={busy}
          onClick={() => setDraft((prev) => ({ ...prev, ignoreipText: [...lines(prev.ignoreipText), you].join('\n') }))}>
          <UserCheck size={15} aria-hidden="true"/> {t('Add my address')}
        </button>}
        {dirty && <button type="button" className="secondary" disabled={busy} onClick={() => setDraft(draftFrom(settings))}>{t('Discard changes')}</button>}
        <button type="submit" disabled={busy || !dirty}>{t('Save')}</button>
      </div>
    </form>}
  </div>;
}
