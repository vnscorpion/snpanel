import { useRef, useState } from 'react';
import { msg, useT } from '../i18n/index.jsx';
import './CronSchedule.css';

// The schedules people ask for, by name. Anything else is "Custom", which
// takes a crontab expression as before - nothing a preset cannot say is lost.
export const CRON_PRESETS = [
  ['* * * * *', msg('Every minute')],
  ['*/5 * * * *', msg('Every 5 minutes')],
  ['*/15 * * * *', msg('Every 15 minutes')],
  ['*/30 * * * *', msg('Every 30 minutes')],
  ['0 * * * *', msg('Every hour')],
  ['0 */6 * * *', msg('Every 6 hours')],
  ['0 0 * * *', msg('Every day at 00:00')],
  ['0 2 * * *', msg('Every day at 02:00')],
  ['0 3 * * *', msg('Every day at 03:00')],
  ['0 0 * * 0', msg('Every Sunday at 00:00')],
  ['0 0 1 * *', msg('On the 1st of every month')],
];

const tidy = (expr) => String(expr || '').trim().replace(/\s+/g, ' ');

// A preset's name for a schedule, or null when it is not one of them.
export function cronPresetLabel(expr) {
  const hit = CRON_PRESETS.find(([value]) => value === tidy(expr));
  return hit ? hit[1] : null;
}

// A select of the presets beside the expression itself, in a box of its own:
// picking a preset writes its expression there, and typing one the presets
// do not name turns the select to "Custom".
export default function CronSchedule({ id, value, onChange, describedBy }) {
  const t = useT();
  const input = useRef(null);
  const known = CRON_PRESETS.some(([preset]) => preset === tidy(value));
  // "Custom" picked while the box still holds a preset's expression: the
  // select stays on it rather than jumping back to that preset's name.
  const [picked, setPicked] = useState(false);

  return <div className="cron-schedule">
    <select id={id} value={known && !picked ? tidy(value) : 'custom'} aria-describedby={describedBy}
      onChange={(event) => {
        if (event.target.value === 'custom') {
          setPicked(true);
          input.current?.focus();
          input.current?.select();
        } else {
          setPicked(false);
          onChange(event.target.value);
        }
      }}>
      {CRON_PRESETS.map(([preset, label]) => <option key={preset} value={preset}>{t(label)}</option>)}
      <option value="custom">{t('Custom schedule…')}</option>
    </select>
    <input ref={input} className="cron-schedule-input" value={value} onChange={(event) => onChange(event.target.value)}
      placeholder="*/15 * * * *" aria-label={t('Cron expression')} spellCheck={false} autoComplete="off" />
  </div>;
}
