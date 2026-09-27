// A Telegram Bot API of the checks' own, on 127.0.0.1:8099: getMe, getChat,
// getUpdates and sendMessage, for any token of a bot token's shape.
//
// Two chats it knows - a person (777001, "Ops", @ops_admin) and a group
// (-100777002, "Ops team") - and what the bot "was sent": a message from the
// person and the bot being added to the group, which is what Find chat ID
// reads. Chat 404 is one Telegram does not know.
//
// Imported by notify-check.mjs. Run by itself, on the box as root, it points
// the panel at itself for as long as it runs - a systemd drop-in with
// SNPANEL_TELEGRAM_API_BASE, the API restarted - and takes both away again
// on SIGTERM, so a browser check can go through the Telegram card:
//
//     systemd-run --unit=snpanel-telegram-mock node telegram-mock.mjs
//     ... the browser check ...
//     systemctl stop snpanel-telegram-mock
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const PORT = 8099;
export const BOT = 'snpanel_check_bot';
export const PERSON = { id: 777001, type: 'private', first_name: 'Ops', username: 'ops_admin' };
export const GROUP = { id: -100777002, type: 'supergroup', title: 'Ops team' };
const TOKEN_SHAPE = /^\d{1,20}:[A-Za-z0-9_-]{20,100}$/;

export function startTelegramMock() {
  const sent = [];
  const updates = [
    { update_id: 500, message: { message_id: 1, text: 'hello', chat: PERSON, from: { id: PERSON.id, first_name: 'Ops', username: 'ops_admin' } } },
    { update_id: 501, my_chat_member: { chat: GROUP, from: { id: PERSON.id, first_name: 'Ops' }, new_chat_member: { status: 'member' } } },
  ];
  const chats = new Map([[String(PERSON.id), PERSON], [String(GROUP.id), GROUP]]);
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const answer = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
      const m = /^\/bot([^/]+)\/(\w+)$/.exec(req.url);
      if (!m || !TOKEN_SHAPE.test(m[1])) return answer(404, { ok: false, error_code: 404, description: 'Not Found' });
      const payload = body ? JSON.parse(body) : {};
      const notFound = () => answer(400, { ok: false, error_code: 400, description: 'Bad Request: chat not found' });
      switch (m[2]) {
        case 'getMe': return answer(200, { ok: true, result: { id: 123456789, is_bot: true, username: BOT } });
        case 'getChat': {
          const chat = chats.get(String(payload.chat_id));
          return chat ? answer(200, { ok: true, result: chat }) : notFound();
        }
        case 'getUpdates': {
          const from = payload.offset || 0;
          return answer(200, { ok: true, result: updates.filter((u) => u.update_id >= from) });
        }
        case 'sendMessage':
          if (!chats.has(String(payload.chat_id))) return notFound();
          sent.push({ chat: String(payload.chat_id), text: payload.text, mode: payload.parse_mode });
          return answer(200, { ok: true, result: { message_id: sent.length } });
        default: return answer(400, { ok: false, description: 'unknown method' });
      }
    });
  });
  const listening = new Promise((r) => server.listen(PORT, '127.0.0.1', r));
  return { server, sent, updates, listening };
}

const DROPIN_DIR = '/etc/systemd/system/snpanel-api.service.d';
export const DROPIN = `${DROPIN_DIR}/zz-telegram-mock.conf`;

/** The panel pointed at the mock, or back at Telegram. */
export function pointPanel(atMock) {
  if (atMock) {
    mkdirSync(DROPIN_DIR, { recursive: true });
    writeFileSync(DROPIN, `[Service]\nEnvironment=SNPANEL_TELEGRAM_API_BASE=http://127.0.0.1:${PORT}\n`);
  } else {
    rmSync(DROPIN, { force: true });
  }
  execFileSync('systemctl', ['daemon-reload']);
  execFileSync('systemctl', ['restart', 'snpanel-api']);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const mock = startTelegramMock();
  await mock.listening;
  pointPanel(true);
  console.log(`telegram mock on 127.0.0.1:${PORT}; the panel points at it`);
  const stop = () => {
    pointPanel(false);
    console.log(`stopped; ${mock.sent.length} message(s) were sent`);
    process.exit(0);
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
