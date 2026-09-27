// The Restore tab in a browser, as the administrator, in four steps: three
// sources - this server, a saved destination, another server - with Upload
// backup and Refresh beside each; this server's backups are listed one card
// per account, an account with several backups offers
// their dates - the newest chosen - and picking another date ticks the
// account; Restore - after asking - restores the chosen backup while the
// page follows the job to its end, and says in a line what came back. A
// destination offers its list; another server its form, listing nothing
// until it is reached - not what another source listed before it.
//
//     node restore-ui.mjs [account] [out-dir]
//
// `account` (demo by default) is given a second backup first when it has
// only one, and that backup is deleted again at the end. The newest backup of
// `account` is restored over the account as it is: on a test box, the same
// files and databases again.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const ACCOUNT = process.argv[2] || 'demo';
const OUT = process.argv[3] || '/root/ui-audit/restore';
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value || '';
const api = async (method, path, data) => {
  const r = await context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
  let json = null;
  try { json = await r.json(); } catch {}
  return { status: r.status(), ok: r.ok(), json };
};
const localBackups = async () => ((await api('GET', '/maintenance/restore/local')).json?.items || []).filter((i) => i.valid);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// At least two backups of the account, so it has dates to choose from.
let made = null;
const before = (await localBackups()).filter((i) => i.username === ACCOUNT);
if (before.length < 2) {
  const users = (await api('GET', '/users?usage=0')).json;
  const user = (users?.items || users || []).find((u) => u.username === ACCOUNT);
  await api('POST', '/maintenance/user-backup', { user_id: user?.id });
  for (let i = 0; i < 120 && !made; i += 1) {
    await sleep(2500);
    made = (await localBackups()).find((b) => b.username === ACCOUNT && !before.some((o) => o.backup_file === b.backup_file)) || null;
  }
  check(!!made, `a second backup of ${ACCOUNT} to choose from (${made?.filename || 'none'})`);
}

const page = await context.newPage();
const errors = [];
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', (e) => errors.push(String(e)));
const dialogs = [];
page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });

try {
  await page.goto(`${BASE}/backups`, { waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Restore' }).click();
  const rows = page.locator('.bk-accounts .bk-account');
  await rows.first().waitFor({ timeout: 20000 });
  check(await page.getByRole('radio', { name: /This server/ }).getAttribute('aria-checked') === 'true', 'this server is the source it opens on');
  const sources = await page.getByRole('radio').allTextContents();
  check(sources.length === 3 && /This server/.test(sources[0]) && /Backup destination/.test(sources[1]) && /Another server/.test(sources[2]),
    `three sources: ${sources.map((x) => x.split(/(?=[A-Z][a-z]+ [a-z])/)[0]).join(' / ')}`);
  const legends = await page.locator('.bk-restore-step legend').allTextContents();
  check(legends.join('|') === '1 Where are the backups?|2 Backups on this server|3 Accounts to restore'
    && await page.locator('.bk-restore-go .bk-restore-num').textContent() === '4', `four steps: ${legends.join(' / ')} / 4`);
  check(await page.getByRole('button', { name: 'Upload backup' }).isEnabled() && await page.getByRole('button', { name: 'Refresh', exact: true }).isEnabled(),
    'Upload backup and Refresh beside this server\'s backups');
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await rows.first().waitFor({ timeout: 20000 });
  check(await rows.count() > 0, 'Refresh lists them again');

  const valid = await localBackups();
  const accounts = new Set(valid.map((i) => i.username));
  const names = await page.locator('.bk-account-name strong').allTextContents();
  check(names.length === accounts.size && new Set(names).size === names.length,
    `one row per account: ${names.length} rows for ${valid.length} backups of ${accounts.size} accounts`);

  const restore = page.locator('.bk-restore-go button');
  check(await restore.isDisabled(), 'Restore waits for a choice');
  await page.locator('.bk-check-inline input').check();
  check(await page.locator('.bk-accounts input[type=checkbox]:checked').count() === names.length, 'All ticks every account');
  await page.locator('.bk-check-inline input').uncheck();
  check(await page.locator('.bk-accounts input[type=checkbox]:checked').count() === 0, 'and again, none');

  // The account's dates: the newest chosen.
  const row = rows.filter({ has: page.locator('.bk-account-name strong', { hasText: new RegExp(`^${ACCOUNT}$`) }) }).first();
  const dates = row.locator('.bk-account-date select');
  const theirs = valid.filter((i) => i.username === ACCOUNT)
    .sort((a, b) => String(b.generated_at || b.modified).localeCompare(String(a.generated_at || a.modified)));
  const options = await dates.locator('option').evaluateAll((list) => list.map((o) => o.value));
  check(options.length === theirs.length && options.length >= 2 && await dates.inputValue() === theirs[0].backup_file,
    `${ACCOUNT} has its ${theirs.length} backups as dates, the newest chosen`);
  check((await row.locator('.bk-account-name small').textContent()).startsWith(`${theirs.length} backups`), 'and says how many');

  // Another date: the account is ticked, and the choice says which.
  await dates.selectOption(options[1]);
  check(await row.locator('input[type=checkbox]').isChecked() && /\bon\b/.test(await row.getAttribute('class')), 'picking another date ticks the account, and the card shows it');
  check(await row.getAttribute('title') === theirs[1].filename, `the card is that backup (${theirs[1].filename})`);
  const hint = await page.locator('.bk-restore-chosen').textContent();
  check(hint.startsWith('1 chosen') && hint.includes(`${ACCOUNT} · `), `the choice is said beside the button (${hint})`);
  await row.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${OUT}/grouped-light-en.png` });

  // Back to the newest, and restored.
  await dates.selectOption(options[0]);
  await restore.click();
  check(dialogs.some((m) => m.startsWith('Restore 1 backup(s)?')), `it asks first (${dialogs.at(-1)?.slice(0, 60)})`);
  // The line may still say the restore before this one: this one is
  // followed from running to done.
  const banner = page.locator('.bk-restore-job');
  await page.locator('.bk-restore-job.running').waitFor({ timeout: 30000 });
  await page.locator('.bk-restore-job.done').waitFor({ timeout: 300000 });
  const said = (await banner.textContent()).replace(/\s+/g, ' ').trim();
  check(new RegExp(`^Restored ${ACCOUNT}: \\d+ website\\(s\\), \\d+ database\\(s\\)\\.$`).test(said), `the page follows the restore to its end, and says what came back in a line (${said})`);
  check(await banner.locator('.bk-restore-steps').count() === 0, 'with nothing failed, no list under it');
  check(await page.locator('.app-toast-stack').getByText(/Restore finished|Restored/).count() === 0, 'and no toast saying it again');
  await page.screenshot({ path: `${OUT}/restored-light-en.png`, fullPage: true });

  // Opened again: the last restore is still there to read.
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Restore' }).click();
  await banner.waitFor({ timeout: 10000 });
  const again = await banner.filter({ hasText: `Restored ${ACCOUNT}:` }).waitFor({ timeout: 15000 }).then(() => true, () => false);
  check(again, `opened again, the page shows the last restore (${(await banner.textContent()).replace(/\s+/g, ' ').trim()})`);
  // ---------------------------------------------------------------- the other sources
  await page.getByRole('radio', { name: /Backup destination/ }).click();
  const destinations = page.locator('.bk-restore-destination select');
  check(await page.locator('.bk-restore-step legend').nth(1).textContent() === '2 Choose the destination'
    && (await destinations.count() === 1 || await page.getByText('No destination yet: add one in Destinations.').first().isVisible()),
    'Backup destination: its list, or where to add one');
  await page.getByRole('radio', { name: /Another server/ }).click();
  const form = page.locator('.bk-connection');
  await form.waitFor();
  // The protocol is a select: its label's text holds the options too.
  const field = (label) => (label === 'Protocol'
    ? form.getByRole('combobox', { name: label, exact: true })
    : form.getByLabel(label, { exact: true }));
  for (const label of ['Protocol', 'Server', 'Port', 'User name', 'Password', 'Folder']) {
    check(await field(label).isVisible(), `Another server asks for its ${label.toLowerCase()}`);
  }
  await field('Protocol').selectOption('ftp');
  check(await form.getByText('FTP sends the password unencrypted.').isVisible() && await form.getByLabel('Port', { exact: true }).getAttribute('placeholder') === '21',
    'FTP: port 21 by default, and it says the password goes unencrypted');
  await form.getByLabel('Server', { exact: true }).fill('backup.example.com');
  await form.getByLabel('User name', { exact: true }).fill('old');
  check(await page.getByRole('button', { name: 'Refresh', exact: true }).isDisabled()
    && await page.locator('.bk-restore-note').last().textContent() === 'Enter the server, then press Refresh.',
    'Refresh waits for the password');
  // Every listing back - the destination's too: it is not shown here.
  await page.locator('.bk-restore-actions button:has-text("Upload backup"):enabled').waitFor({ timeout: 120000 });
  await sleep(500);
  check(await page.locator('.bk-accounts').count() === 0 && await page.locator('.bk-restore-note').last().textContent() === 'Enter the server, then press Refresh.',
    'nothing listed until the server is reached - not what the destination listed before');
  const unnamed = await page.locator('.bk-restore-step button:visible').evaluateAll((buttons) => buttons.filter((b) => !b.textContent.trim() && !b.getAttribute('aria-label')).length);
  check(unnamed === 0, `no button drawn without words (${unnamed})`);
  const tile = page.getByRole('radio', { name: /Another server/ });
  const background = (radio) => radio.evaluate((el) => getComputedStyle(el).backgroundColor);
  await page.mouse.move(0, 0);
  await sleep(300);
  const [chosenBg, otherBg] = [await background(tile), await background(page.getByRole('radio', { name: /This server/ }))];
  await tile.hover();
  await sleep(300);
  const hoveredBg = await background(tile);
  check(chosenBg !== otherBg && hoveredBg === chosenBg, `the chosen source stays as it is under the mouse (${chosenBg}, hovered ${hoveredBg}; others ${otherBg})`);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: `${OUT}/another-server-light-en.png` });
  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  if (made) {
    const gone = await api('DELETE', `/maintenance/user-backups?backup_file=${encodeURIComponent(made.backup_file)}`);
    console.log(`${gone.ok ? 'PASS' : 'FAIL'}  the backup made for this check is deleted again (${gone.status})`);
    ok &&= gone.ok;
  }
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
