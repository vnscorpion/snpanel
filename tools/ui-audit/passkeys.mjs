// Passkeys, end to end, with Chromium's virtual authenticator.
//
//     node passkeys.mjs [out-dir]
//
// WebAuthn wants a secure page with a hostname, so this runs against
// https://localhost:2222 with --allow-insecure-localhost, which makes the
// panel's self-signed certificate acceptable for localhost only.
//
// A throwaway user "uiprobe2" is made, turns on the authenticator app (the
// code is computed here from the secret), and then:
//   - adds a passkey on the Security page;
//   - signs in with it, typing no code;
//   - signs in with the code after choosing it over a pending passkey prompt;
//   - signs in with the code after the passkey is refused by the server (the
//     authenticator's key swapped for a wrong one, so the signature fails);
//   - removes the passkey on the Security page;
//   - adds one again and turns the app off: the passkey goes with it.
// The user is deleted at the end, whatever happened.
import { chromium } from 'playwright';
import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/passkeys';
const LOCAL = 'https://localhost:2222';
const USERNAME = 'uiprobe2';
const PASSWORD = randomBytes(18).toString('base64url');
mkdirSync(OUT, { recursive: true });

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

function base32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of text.replace(/=+$/, '').toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v >= 0) bits += v.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
// RFC 6238, as pyotp and the panel do it: SHA-1, 30 seconds, 6 digits.
function totp(secret) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac('sha1', base32(secret)).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

const browser = await chromium.launch({ args: ['--allow-insecure-localhost'] });
const csrfOf = async (context) => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (context, base, method, path, data) => {
  const csrf = await csrfOf(context);
  return context.request.fetch(`${base}/api${path}`, { method, data, headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
};

const admin = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(admin);
async function removeProbe() {
  const users = await (await api(admin, BASE, 'GET', '/users?usage=0')).json();
  const probe = users.find((u) => u.username === USERNAME);
  if (probe) await api(admin, BASE, 'DELETE', `/users/${probe.id}`);
}

await removeProbe();
const created = await api(admin, BASE, 'POST', '/users', {
  username: USERNAME, email: `${USERNAME}@example.invalid`, password: PASSWORD,
  role: 'end_user', package_id: null, website_limit: 1, storage_limit_mb: 100,
});
check(created.ok(), `created ${USERNAME} (HTTP ${created.status()})`);

const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US', timezoneId: 'Asia/Ho_Chi_Minh' });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('dialog', (d) => d.accept());

try {
  // ------------------------------------------------ the app code, by the API
  const login = await context.request.post(`${LOCAL}/api/auth/login`, { form: { username: USERNAME, password: PASSWORD } });
  check(login.status() === 200, `${USERNAME} signs in with a password (HTTP ${login.status()})`);
  const setup = await (await api(context, LOCAL, 'POST', '/auth/2fa/setup', { current_password: PASSWORD })).json();
  const secret = setup.secret;
  const enabled = await api(context, LOCAL, 'POST', '/auth/2fa/enable', { code: totp(secret) });
  check(enabled.ok() && !!secret, `the authenticator app is on (HTTP ${enabled.status()})`);

  // ------------------------------------------------ a virtual authenticator
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  // ------------------------------------------------ add one on the Security page
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.passkey-form', { timeout: 15000 });
  await page.locator('.passkey-form').getByLabel('Name').fill('Virtual key');
  await page.locator('.passkey-form').getByLabel('Authentication code').fill(totp(secret));
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await page.locator('.passkey-table tbody tr', { hasText: 'Virtual key' }).waitFor({ timeout: 20000 });
  let listed = await (await api(context, LOCAL, 'GET', '/auth/passkeys')).json();
  check(listed.items.length === 1 && listed.items[0].rp_id === 'localhost' && listed.items[0].usable_here,
    `the passkey is stored for localhost (${JSON.stringify(listed.items.map((p) => [p.name, p.rp_id]))})`);
  // The API writes naive UTC; the page shows it in the viewer's zone (UTC+7 here).
  const addedCell = (await page.locator('.passkey-table tbody tr', { hasText: 'Virtual key' }).locator('td').nth(1).textContent()).trim();
  const utc = new Date(`${listed.items[0].created_at.replace(' ', 'T').slice(0, 23)}Z`);
  const local = new Date(utc.getTime() + 7 * 3600 * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  const expectedCell = `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())} ${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}`;
  check(addedCell === expectedCell, `the time added is shown in the viewer's zone (${addedCell}, stored ${listed.items[0].created_at} UTC)`);
  await page.screenshot({ path: `${OUT}/security-with-passkey-light-en.png`, fullPage: true });

  // ------------------------------------------------ sign in with it
  const signIn = async () => {
    await context.clearCookies();
    await page.goto(`${LOCAL}/`, { waitUntil: 'networkidle' });
    await page.getByPlaceholder('Username').fill(USERNAME);
    await page.getByPlaceholder('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Login' }).click();
  };
  await signIn();
  await page.waitForSelector('.dash-group', { timeout: 20000 });
  check(await page.locator('.dash-group').count() > 0, 'a passkey completes the sign-in, no code typed');
  listed = await (await api(context, LOCAL, 'GET', '/auth/passkeys')).json();
  check(!!listed.items[0].last_used_at, `its use is recorded (${listed.items[0].last_used_at})`);

  // ------------------------------------------------ choosing the code instead
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  await signIn();
  await page.locator('.login-passkey').waitFor({ timeout: 15000 });
  await page.screenshot({ path: `${OUT}/login-waiting-light-en.png`, fullPage: true });
  await page.getByRole('button', { name: 'Use the authenticator code instead' }).click();
  const code = page.getByPlaceholder('Authentication code');
  await code.waitFor({ timeout: 10000 });
  await code.fill(totp(secret));
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForSelector('.dash-group', { timeout: 20000 });
  check(true, 'while the passkey prompt waits, the code can be chosen and signs in');
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });

  // ------------------------------------------------ the passkey refused: fall back
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  const real = credentials[0];
  const wrong = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: { credentialId: real.credentialId, isResidentCredential: false, rpId: 'localhost', privateKey: wrong, signCount: real.signCount + 10 },
  });
  await signIn();
  await page.locator('.login-passkey-failed').waitFor({ timeout: 20000 });
  await page.screenshot({ path: `${OUT}/login-failed-light-en.png`, fullPage: true });
  check(await page.getByPlaceholder('Authentication code').isVisible(), 'a refused passkey says so and asks for the code');
  await page.getByPlaceholder('Authentication code').fill(totp(secret));
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForSelector('.dash-group', { timeout: 20000 });
  check(true, 'and the code signs in');

  // ------------------------------------------------ remove it on the Security page
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Remove Virtual key' }).click();
  await page.locator('.passkey-table').waitFor({ state: 'detached', timeout: 15000 });
  listed = await (await api(context, LOCAL, 'GET', '/auth/passkeys')).json();
  check(listed.items.length === 0, 'removing it on the Security page removes it');

  // ------------------------------------------------ the app off takes passkeys with it
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await page.locator('.passkey-form').getByLabel('Name').fill('Second key');
  await page.locator('.passkey-form').getByLabel('Authentication code').fill(totp(secret));
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await page.locator('.passkey-table tbody tr', { hasText: 'Second key' }).waitFor({ timeout: 20000 });
  const off = await api(context, LOCAL, 'POST', '/auth/2fa/disable', { current_password: PASSWORD, code: totp(secret) });
  listed = await (await api(context, LOCAL, 'GET', '/auth/passkeys')).json();
  check(off.ok() && listed.items.length === 0 && !listed.totp_enabled,
    `turning the app off removes the passkeys too (HTTP ${off.status()}, ${listed.items.length} left)`);

  // Without the app, the page says why a passkey cannot be added.
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  const note = await page.locator('.security-page .empty-note').textContent();
  check(/authenticator app first/.test(note), `with the app off, the page says a passkey needs it (${note.slice(0, 60)}…)`);

  // Guessing the code to add a passkey is limited like a sign-in.
  const again = await (await api(context, LOCAL, 'POST', '/auth/2fa/setup', { current_password: PASSWORD })).json();
  await api(context, LOCAL, 'POST', '/auth/2fa/enable', { code: totp(again.secret) });
  const statuses = [];
  for (let i = 0; i < 10; i += 1) {
    const res = await api(context, LOCAL, 'POST', '/auth/passkeys/register/options', { code: '000000' });
    statuses.push(res.status());
    if (res.status() === 429) break;
  }
  check(statuses.at(-1) === 429 && statuses.slice(0, -1).every((s) => s === 401),
    `wrong codes for a new passkey are cut off (${statuses.join(' ')})`);

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} finally {
  await removeProbe();
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
