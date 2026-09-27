// The daemon's buttons, and the switch turned off while the daemon installs.
//
//     node upload-scan-daemon.mjs [out-dir]
//
//   - upload scanning on, the daemon stopped behind the panel's back: the
//     Malware page says so and offers "Start the daemon", which starts it;
//   - the daemon's package removed: "Install the daemon" installs it in the
//     background. The switch is turned off while that runs - from a second
//     client, an administrator in another tab, because the page waits for
//     the install - and once the install is done the daemon it enabled is
//     stopped and disabled again.
//     A reinstall from apt's cache takes seconds, so while it runs apt's
//     index update is held for 25 s by a hook of this test's own: the switch
//     goes off inside that window every time, not when the timing allows.
//
// Which road the switch's own stop takes depends on how the panel reaches
// the helper, and the run says which it saw. Over the socket the helper
// takes one call at a time, and the stop waits behind the install. Through
// sudo - the verbs an install cut over with helper-cutover.sh does not send
// over the socket, or any call once the socket gives up - it runs at once,
// finds no daemon to stop, and the install then enables one: only the
// install's second look at the switch stops it.
// Ends with upload scanning on and the daemon running. Runs on the box, as
// root: it stops the daemon with systemctl, removes its package with apt,
// and writes (and removes) the apt hook.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/upload-scan-daemon';
mkdirSync(OUT, { recursive: true });
const SLOW_APT = '/etc/apt/apt.conf.d/99snpanel-e2e-slow-update';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, ...args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); } catch (e) { return String(e.stdout || '').trim(); } };
const units = () => ['is-active', 'is-enabled'].map((q) => `${q}: ${run('systemctl', q, 'clamav-daemon.socket', 'clamav-daemon').split('\n').join('/')}`).join(', ');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (test, ms) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (test()) return true; await sleep(200); }
  return test();
};
const settingSays = (want) => {
  try { return JSON.parse(readFileSync('/var/lib/snpanel/panel-settings.json', 'utf8')).malware_upload_scan_enabled === want; } catch { return false; }
};

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, options = {}) => context.request.fetch(`${BASE}/api${path}`, {
  method, ...options, headers: { 'X-CSRF-Token': await csrf(), ...(options.headers || {}) }, timeout: 180000,
});
const status = async () => (await (await api('GET', '/malware/status')).json());
const until = async (what, test, minutes) => {
  const deadline = Date.now() + minutes * 60 * 1000;
  for (;;) {
    const s = await status();
    if (test(s)) return s;
    if (Date.now() > deadline) { console.log(`  gave up waiting for ${what}`); return s; }
    await sleep(5000);
  }
};

const page = await context.newPage();
page.on('dialog', (d) => d.accept());
const malware = async () => {
  await page.goto(`${BASE}/malware`, { waitUntil: 'networkidle' });
  return page.locator('.malware-uploads');
};

try {
  await api('POST', '/malware/upload-scan', { data: { enabled: true } });
  let s = await until('the daemon', (x) => x.clamd_running, 8);
  check(s.enabled && s.upload_scan_enabled && s.clamd_running, 'start: uploads scanned, the daemon running');

  // ---------------------------------------------------------------- stopped
  run('systemctl', 'disable', '--now', 'clamav-daemon.socket', 'clamav-daemon');
  let block = await malware();
  check(await block.getByText('ClamAV daemon stopped', { exact: true }).isVisible(), 'a daemon stopped behind the panel\'s back shows as stopped');
  const start = block.getByRole('button', { name: 'Start the daemon' });
  check(await start.isVisible(), 'with a button to start it');
  await page.screenshot({ path: `${OUT}/daemon-stopped-light-en.png`, fullPage: true });
  await start.click();
  await page.waitForResponse((r) => r.url().endsWith('/api/malware/upload-scan'), { timeout: 60000 });
  await sleep(1000);
  check(run('systemctl', 'is-active', 'clamav-daemon') === 'active' && run('systemctl', 'is-enabled', 'clamav-daemon') === 'enabled',
    `the button starts it and enables it at boot (${units()})`);
  s = await until('the daemon', (x) => x.clamd_running, 5);
  block = await malware();
  check(await block.getByText('ClamAV daemon running', { exact: true }).isVisible()
    && await block.getByRole('button', { name: /the daemon/ }).count() === 0,
  'once it answers: running, and no button');

  // ---------------------------------------------------------------- the race
  run('apt-get', 'remove', '-y', '-q', 'clamav-daemon');
  s = await status();
  check(!s.clamd_installed && existsSync('/usr/bin/clamscan'), 'the daemon\'s package removed, clamscan kept');
  block = await malware();
  const install = block.getByRole('button', { name: 'Install the daemon' });
  check(await block.getByText('ClamAV daemon not installed', { exact: true }).isVisible() && await install.isVisible(),
    'a missing daemon shows as not installed, with a button to install it');
  await page.screenshot({ path: `${OUT}/daemon-missing-light-en.png`, fullPage: true });
  writeFileSync(SLOW_APT, 'APT::Update::Pre-Invoke { "sleep 25"; };\n');
  const installAnswer = page.waitForResponse((r) => r.url().endsWith('/api/malware/upload-scan'), { timeout: 900000 });
  await install.click();
  const aptRunning = await waitFor(() => run('pgrep', '-x', 'apt-get') !== '', 60000);
  // Off from a second client. The flag is written before any helper call,
  // so the settings say off at once, whichever road the stop then takes.
  const off = api('POST', '/malware/upload-scan', { data: { enabled: false } });
  const persisted = await waitFor(() => settingSays(false), 10000);
  check(aptRunning && persisted && !existsSync('/usr/sbin/clamd'), 'the switch went off while the install ran');
  await off;
  const stopRanFirst = !existsSync('/usr/sbin/clamd');
  console.log(`  the switch's own stop ran ${stopRanFirst
    ? 'before the install finished (the helper reached through sudo): only the second look can stop the daemon'
    : 'after the install, queued behind it on the helper socket'}`);
  await installAnswer;

  // Done when the daemon is installed and has stayed stopped for 30 s.
  const deadline = Date.now() + 10 * 60 * 1000;
  let quietSince = 0;
  while (Date.now() < deadline) {
    const installed = existsSync('/usr/sbin/clamd');
    const stopped = run('systemctl', 'is-active', 'clamav-daemon') !== 'active';
    if (installed && stopped) {
      quietSince ||= Date.now();
      if (Date.now() - quietSince > 30000) break;
    } else {
      quietSince = 0;
    }
    await sleep(3000);
  }
  check(existsSync('/usr/sbin/clamd'), 'the install finished');
  check(run('systemctl', 'is-active', 'clamav-daemon') !== 'active'
    && run('systemctl', 'is-active', 'clamav-daemon.socket') !== 'active'
    && run('systemctl', 'is-enabled', 'clamav-daemon') === 'disabled',
  `and the daemon it enabled was stopped and disabled again (${units()})`);
} finally {
  rmSync(SLOW_APT, { force: true });
  // Back to the default: uploads scanned, the daemon running.
  await api('POST', '/malware/upload-scan', { data: { enabled: true } }).catch(() => {});
  const s = await until('the daemon', (x) => x.clamd_running, 8).catch(() => ({}));
  console.log(`  restored: upload scanning ${s.upload_scan_enabled}, daemon running ${s.clamd_running}`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
