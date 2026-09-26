// The SFTP page as the customer: changing a password there asks for the
// current panel password and the authenticator code, in the row's own
// form - for the account's own login and for one of its SFTP accounts.
//
//     LOGIN_FILE=login-demo.txt node sftp-self.mjs [out-dir]
//
// The login file names a customer with two-step verification (User,
// Password, TOTP). A code is good once in its 30 seconds, so each step
// waits for a fresh one. It gives both logins new passwords.
import { chromium } from 'playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import { BASE } from './capture.mjs';
import { totp } from './totp.mjs';

const OUT = process.argv[2] || '/root/ui-audit/sftp-self';
mkdirSync(OUT, { recursive: true });
const text = readFileSync(process.env.LOGIN_FILE, 'utf8');
const USER = /^User: (.+)$/m.exec(text)[1].trim();
const PASSWORD = /^Password: (.+)$/m.exec(text)[1].trim();
const SECRET = /^TOTP: (.+)$/m.exec(text)[1].trim();
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const freshCode = async () => {
  await new Promise((r) => setTimeout(r, 30000 - (Date.now() % 30000) + 800));
  return totp(SECRET);
};

const hostMap = process.env.HOST_MAP;
const browser = await chromium.launch(hostMap ? { args: [`--host-resolver-rules=MAP ${hostMap.split('=')[0]} ${hostMap.split('=')[1]}`] } : {});
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-locale', 'en'); } catch {} });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
const login = await page.evaluate(async (f) => {
  const res = await fetch('/api/auth/login', { method: 'POST', body: new URLSearchParams(f), credentials: 'include' });
  return res.status;
}, { username: USER, password: PASSWORD, otp: await freshCode() });
check(login === 200, `${USER} signs in with a code (${login})`);

await page.goto(`${BASE}/sftp`, { waitUntil: 'networkidle' });
for (const [label, rowOf] of [
  ['its own login', () => page.locator('.sftp-list li').first()],
  ['an SFTP account of its', () => page.locator('.sftp-list li').nth(1)],
]) {
  const row = rowOf();
  if (!(await row.count())) { console.log(`SKIP  ${label}: no such row`); continue; }
  const name = (await row.locator('code').first().textContent()).trim();
  await row.getByRole('button', { name: 'Change password' }).click();
  const form = row.locator('form');
  const save = form.getByRole('button', { name: 'Save' });
  check(await save.isDisabled(), `${label} (${name}): Save waits for the current password and a code`);
  await form.getByLabel('Current panel password').fill(PASSWORD);
  check(await save.isDisabled(), '... and still for the code');
  await form.getByLabel('Authenticator code').fill(await freshCode());
  const answer = page.waitForResponse((r) => r.url().includes('/password') && r.request().method() === 'POST');
  await save.click();
  const res = await answer;
  check(res.ok(), `${label}: a new password with the right proof (${res.status()})`);
  await page.locator('.sftp-shown code').waitFor();
  check((await page.locator('.sftp-shown').textContent()).includes(name), `${label}: shown once, named ${name}`);
}
await page.screenshot({ path: `${OUT}/self-light-en.png`, fullPage: true });
check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
