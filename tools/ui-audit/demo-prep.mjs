// The demo panel, readied for the README's screenshots, and tidied after.
//
//     node demo-prep.mjs setup     (LOGIN_FILE: the administrator's; telegram-mock.mjs running on the box)
//     node demo-prep.mjs cleanup
//
// setup: the OWASP rule set loaded on every website (the WAF switched off and
// on, as the WAF page advises for a site made before it); WordPress on
// blog.example.com, if it has none; the Notifications addon's e-mail pointed
// at smtp.example.com and its Telegram at the mock's "Ops team"; an AI
// assistant token named "Claude Code". cleanup: the channels and the token
// removed again. WordPress and the rule sets stay: they are demo data.
//
// Every password and token is made at random here and never printed.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { BASE, logIn } from './capture.mjs';

const MODE = process.argv[2];
const TOKEN_NAME = 'Claude Code';
const secret = (n = 18) => randomBytes(n).toString('base64url');

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value || '';
const api = async (method, path, data) => {
  const r = await context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 900000 });
  let json = null;
  try { json = await r.json(); } catch {}
  return { status: r.status(), ok: r.ok(), json };
};
const say = (what, r) => console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${what} (${r.status})`);

try {
  if (MODE === 'setup') {
    const listed = (await api('GET', '/websites')).json;
    const sites = listed?.items || listed || [];
    for (const site of sites.filter((s) => s.waf_enabled && s.domain !== 'shop.example.com')) {
      await api('PATCH', `/websites/${site.id}/waf`, { waf_enabled: false });
      say(`WAF rule set reloaded on ${site.domain}`, await api('PATCH', `/websites/${site.id}/waf`, { waf_enabled: true }));
    }
    const blog = sites.find((s) => s.domain === 'blog.example.com');
    if (blog) {
      const answer = await api('POST', `/websites/${blog.id}/wordpress`, {
        title: 'Demo Blog', admin_user: 'blogadmin', admin_email: 'admin@blog.example.com', admin_password: `W-${secret()}`,
      });
      say('WordPress on blog.example.com', answer.status === 400 ? { ok: true, status: '400, already there' } : answer);
    }
    say('e-mail through smtp.example.com', await api('PUT', '/notifications/smtp', {
      host: 'smtp.example.com', port: 587, security: 'starttls', username: 'panel@example.com', password: secret(),
      from_address: 'panel@example.com', from_name: 'SNPanel', to: 'ops@example.com',
    }));
    say('Telegram to the Ops team group', await api('PUT', '/notifications/telegram', {
      token: `123456789:${secret(27)}`, chat_id: '-100777002',
    }));
    say(`an AI assistant token, ${TOKEN_NAME}`, await api('POST', '/mcp/tokens', { name: TOKEN_NAME, can_write: false, expires_days: 90 }));
  } else if (MODE === 'cleanup') {
    say('e-mail removed', await api('DELETE', '/notifications/smtp'));
    say('Telegram removed', await api('DELETE', '/notifications/telegram'));
    const tokens = (await api('GET', '/mcp/tokens')).json;
    for (const token of (tokens?.items || tokens || []).filter((x) => x.name === TOKEN_NAME)) {
      say(`token ${TOKEN_NAME} revoked`, await api('DELETE', `/mcp/tokens/${token.id}`));
    }
  } else {
    console.log('usage: node demo-prep.mjs setup|cleanup');
  }
} finally {
  await browser.close();
}
