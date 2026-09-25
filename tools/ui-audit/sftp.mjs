// A panel user's SFTP login, from the Users page and from the user's own
// Account security page, checked by signing in over SFTP for real.
//
//     node sftp.mjs [out-dir]
//
// Runs on the box, as root: it signs in with sshpass and sftp (the password
// in the environment, not in argv) and reads `passwd -S`. Makes a user of its
// own, `sftpcheck`, and deletes it at the end. The user has no sites, which
// is the case suspension used to miss.
//
//   - A new user's SFTP is on, with the panel password, and follows it when
//     the administrator changes it.
//   - A password of its own, generated on the Users page and shown once:
//     SFTP takes it, and stops following the panel password.
//   - Off: locked, badge "SFTP off"; a suspension and an un-suspension leave
//     it off.
//   - On again with a typed password; a suspension locks it, un-suspending
//     unlocks it.
//   - The user, on their own page, changes the SFTP password - after the
//     current panel password, which the button waits for.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/sftp';
mkdirSync(OUT, { recursive: true });
const NAME = 'sftpcheck';
const P1 = 'first panel password 1';
const P2 = 'second panel password 2';
const P3 = 'third panel password 3';
const TYPED = 'typed sftp password 4';
const OWN = 'own sftp password 5';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args, env = {}) => {
  try {
    return { code: 0, out: execFileSync(cmd, args, { encoding: 'utf8', input: 'pwd\nbye\n', env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000 }) };
  } catch (e) {
    return { code: e.status ?? -1, out: String(e.stdout || '') + String(e.stderr || '') };
  }
};
// A real SFTP sign-in, chrooted to the user's home: `pwd` answers "/".
const sftp = (password) => {
  const r = run('sshpass', ['-e', 'sftp', '-q', '-oStrictHostKeyChecking=no', '-oUserKnownHostsFile=/dev/null',
    '-oPubkeyAuthentication=no', '-oPreferredAuthentications=password', '-oNumberOfPasswordPrompts=1',
    `${NAME}@127.0.0.1`], { SSHPASS: password });
  return r.code === 0 && /Remote working directory: \/\s*$/m.test(r.out);
};
const locked = () => run('passwd', ['-S', NAME]).out.split(/\s+/)[1] === 'L';

const browser = await chromium.launch();
const admin = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await admin.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(admin);
const csrfOf = async (context) => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const call = async (context, method, path, data) => context.request.fetch(`${BASE}/api${path}`, {
  method, data, headers: { 'X-CSRF-Token': await csrfOf(context) }, timeout: 120000,
});
const page = await admin.newPage();
page.on('dialog', (d) => d.accept());
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error' && !/jobs\/latest/.test(m.location()?.url || '')) consoleErrors.push(m.text()); });
const go = async (path) => { await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(300); };
const row = () => page.locator('.user-row', { has: page.locator('strong', { hasText: new RegExp(`^${NAME}$`) }) });
const openEditor = async () => {
  await go('/users');
  await row().getByRole('button', { name: 'Edit' }).click();
  await row().locator('.sftp-access .sftp-head').waitFor();
  await row().locator('.sftp-details, .sftp-access .hint').first().waitFor();
};

let userId = null;
try {
  // ---------------------------------------------------------------- a new user
  const existing = (await (await call(admin, 'GET', '/users?usage=0')).json()).find((u) => u.username === NAME);
  if (existing) await call(admin, 'DELETE', `/users/${existing.id}`);
  const created = await call(admin, 'POST', '/users', {
    username: NAME, email: `${NAME}@example.com`, password: P1, role: 'end_user', website_limit: 1, storage_limit_mb: 100,
  });
  userId = (await created.json()).id;
  check(created.status() === 200 && userId, `a new end user (${created.status()})`);
  check(sftp(P1), 'signs in over SFTP with the panel password, chrooted to their home');

  await openEditor();
  check(await row().locator('.badge', { hasText: /^SFTP$/ }).isVisible(), 'the list shows SFTP on');
  const box = row().locator('.sftp-access');
  check(await box.getByText('On. It signs in with the panel password, and follows it when that changes.').isVisible(),
    'the editor says it follows the panel password');
  const details = await box.locator('.sftp-details').innerText();
  check(details.includes('127.0.0.1') && details.includes('22') && details.includes(NAME) && details.includes(`/home/${NAME}`),
    `with what to connect to (${details.replace(/\s+/g, ' ')})`);
  await page.screenshot({ path: `${OUT}/users-editor-light-en.png`, fullPage: true });

  // ---------------------------------------------------------------- following the panel password
  await call(admin, 'POST', `/users/${userId}/password`, { password: P2 });
  check(sftp(P2) && !sftp(P1), 'the administrator changes the panel password: SFTP follows it');

  // ---------------------------------------------------------------- a password of its own
  await box.getByRole('button', { name: 'Generate a new password' }).click();
  await box.locator('.sftp-shown code').waitFor({ timeout: 30000 });
  const generated = (await box.locator('.sftp-shown code').innerText()).trim();
  check(/^[A-Za-z0-9]{20}$/.test(generated), `a generated password, shown once (${generated.length} characters)`);
  check(await box.getByText('On, with a password of its own.').isVisible(), 'the editor says it has its own now');
  check(sftp(generated) && !sftp(P2), 'SFTP takes it, and the panel password no longer opens SFTP');
  await call(admin, 'POST', `/users/${userId}/password`, { password: P3 });
  check(sftp(generated) && !sftp(P3), 'a panel password change no longer reaches it');

  // ---------------------------------------------------------------- off
  await box.getByRole('button', { name: 'Turn SFTP off' }).click();
  await box.getByText('Off. This account cannot sign in over SFTP.').waitFor({ timeout: 30000 });
  check(locked() && !sftp(generated), 'off: the account is locked and SFTP refuses');
  await page.waitForTimeout(500);
  check(await row().locator('.badge', { hasText: /^SFTP off$/ }).isVisible(), 'the list shows SFTP off');
  await call(admin, 'POST', `/users/${userId}/suspend`);
  await call(admin, 'POST', `/users/${userId}/unsuspend`);
  check(locked() && !sftp(generated), 'a suspension and an un-suspension leave it off');

  // ---------------------------------------------------------------- on again, and suspension
  await openEditor();
  await row().locator('.sftp-access').getByLabel('SFTP password', { exact: true }).fill(TYPED);
  await row().locator('.sftp-access').getByRole('button', { name: 'Turn on with this password' }).click();
  await row().locator('.sftp-access').getByText('On, with a password of its own.').waitFor({ timeout: 30000 });
  check(!locked() && sftp(TYPED), 'on again with a typed password');
  await call(admin, 'POST', `/users/${userId}/suspend`);
  check(locked() && !sftp(TYPED), 'a user with no sites is locked by a suspension');
  await call(admin, 'POST', `/users/${userId}/unsuspend`);
  check(!locked() && sftp(TYPED), 'and let back in, SFTP works again');

  // ---------------------------------------------------------------- the user's own page
  const user = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
  await user.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
  const login = await user.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: P3 } });
  check(login.status() === 200, `the user signs in to the panel (${login.status()})`);
  const own = await user.newPage();
  await own.goto(`${BASE}/security`, { waitUntil: 'networkidle' });
  check(await own.getByRole('heading', { name: 'Account security' }).first().isVisible()
    || await own.getByText('Account security').first().isVisible(), 'the page is called Account security');
  const card = own.locator('.sftp-access');
  await card.locator('.sftp-details').waitFor({ timeout: 30000 });
  check(await card.getByRole('heading', { name: 'SFTP access' }).isVisible(), 'with an SFTP access section');
  check(await card.getByRole('button', { name: 'Turn SFTP off' }).count() === 0, 'which a user cannot turn off themselves');
  await card.getByLabel('New SFTP password', { exact: true }).fill(OWN);
  check(await card.getByRole('button', { name: 'Set this password' }).isDisabled(), 'the button waits for the current panel password');
  await card.getByLabel('Current panel password').fill('not the password at all');
  await card.getByRole('button', { name: 'Set this password' }).click();
  await own.waitForTimeout(1500);
  check(sftp(TYPED) && !sftp(OWN), 'a wrong panel password changes nothing');
  await card.getByLabel('Current panel password').fill(P3);
  await card.getByRole('button', { name: 'Set this password' }).click();
  await own.waitForTimeout(1500);
  check(sftp(OWN) && !sftp(TYPED), 'the right one sets it');
  await own.screenshot({ path: `${OUT}/account-security-light-en.png`, fullPage: true });
  await user.close();

  check(consoleErrors.length === 0, `no console errors (${consoleErrors.slice(0, 3).join(' | ')})`);
} finally {
  if (userId) await call(admin, 'DELETE', `/users/${userId}`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
