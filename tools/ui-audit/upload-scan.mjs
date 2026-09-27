// The File Manager upload switch, and the ClamAV daemon that goes with it.
//
//     node upload-scan.mjs [out-dir]
//
// Uses the EICAR test file - the anti-virus industry's harmless standard
// sample, detected by every engine - uploaded to one of admin's sites:
//   - with upload scanning on (the default) it is refused;
//   - turned off on the Malware page, it is accepted, and the daemon is
//     stopped and disabled at boot;
//   - turned on again, the daemon is installed if missing and started, and
//     the upload is refused again - through the daemon, in a moment;
//   - turned off once more, the daemon is stopped and disabled.
// It ends with upload scanning on, the default. Runs on the box, as root: it
// reads systemctl for the daemon's state.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/upload-scan';
mkdirSync(OUT, { recursive: true });
// Split so this file is not itself the sample.
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const NAME = 'uiprobe-eicar.txt';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const systemctl = (...args) => { try { return execFileSync('systemctl', args, { encoding: 'utf8' }).trim(); } catch (e) { return String(e.stdout || '').trim(); } };

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, options = {}) => context.request.fetch(`${BASE}/api${path}`, {
  method, ...options, headers: { 'X-CSRF-Token': await csrf(), ...(options.headers || {}) }, timeout: 180000,
});
const status = async () => (await (await api('GET', '/malware/status')).json());

const sites = await (await api('GET', '/websites')).json();
const site = (sites.items || sites).find((s) => s.domain === 'static.snpanel.deb13') || (sites.items || sites)[0];
const upload = async () => {
  const started = Date.now();
  const res = await api('POST', `/maintenance/files/${site.id}/upload?path=`, {
    multipart: { file: { name: NAME, mimeType: 'text/plain', buffer: Buffer.from(EICAR) } },
  });
  const body = await res.text();
  return { status: res.status(), body, ms: Date.now() - started };
};
const remove = () => api('DELETE', `/maintenance/files/${site.id}?path=${encodeURIComponent(NAME)}`);

const page = await context.newPage();
page.on('dialog', (d) => d.accept());
const flip = async (on) => {
  await page.goto(`${BASE}/malware`, { waitUntil: 'networkidle' });
  const box = page.getByLabel('Scan File Manager uploads');
  if ((await box.isChecked()) !== on) await box.click();
  await page.waitForFunction((want) => {
    const el = document.querySelector('.malware-uploads input[type="checkbox"]');
    return el && el.checked === want;
  }, on, { timeout: 60000 });
  await page.waitForTimeout(1000);
};

try {
  let s = await status();
  check(s.enabled && s.upload_scan_enabled === true, `the scanner is on and uploads are scanned by default (installed daemon: ${s.clamd_installed})`);
  // What checked the first upload: the daemon, if it was already running.
  const firstBy = s.clamd_running ? 'the daemon' : 'clamscan';

  // ---------------------------------------------------------------- on: refused
  const refusedOneShot = await upload();
  check(refusedOneShot.status === 400 && /Malware detected/.test(refusedOneShot.body),
    `with scanning on, EICAR is refused by ${firstBy} (${refusedOneShot.status}, ${refusedOneShot.ms} ms: ${refusedOneShot.body.slice(0, 90)})`);

  // ---------------------------------------------------------------- off: accepted
  await flip(false);
  s = await status();
  check(s.upload_scan_enabled === false, 'the switch turns upload scanning off');
  await page.screenshot({ path: `${OUT}/malware-uploads-off-light-en.png`, fullPage: true });
  const accepted = await upload();
  check(accepted.status === 200, `with scanning off, the same file is accepted (${accepted.status}, ${accepted.ms} ms)`);
  await remove();
  if (s.clamd_installed) {
    check(systemctl('is-active', 'clamav-daemon') !== 'active' && systemctl('is-enabled', 'clamav-daemon') === 'disabled',
      'and the daemon is stopped and disabled at boot');
  }

  // ---------------------------------------------------------------- on again: the daemon
  await flip(true);
  s = await status();
  check(s.upload_scan_enabled === true, 'the switch turns upload scanning back on');
  // Installing it, if it was missing, and loading the signatures take a while.
  const deadline = Date.now() + 8 * 60 * 1000;
  while (!s.clamd_running && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5000));
    s = await status();
  }
  check(s.clamd_installed && s.clamd_running, `the daemon is installed and running (${s.detail})`);
  check(systemctl('is-enabled', 'clamav-daemon') === 'enabled', 'and enabled at boot');
  await page.goto(`${BASE}/malware`, { waitUntil: 'networkidle' });
  await page.screenshot({ path: `${OUT}/malware-uploads-on-light-en.png`, fullPage: true });
  const refusedDaemon = await upload();
  check(refusedDaemon.status === 400 && /Malware detected/.test(refusedDaemon.body),
    `EICAR is refused through the daemon (${refusedDaemon.status}, ${refusedDaemon.ms} ms, against ${refusedOneShot.ms} ms by ${firstBy} at the start)`);

  // ---------------------------------------------------------------- off again: the daemon goes
  await flip(false);
  check(systemctl('is-active', 'clamav-daemon') !== 'active', `turning it off stops the daemon (${systemctl('is-active', 'clamav-daemon')})`);
  check(systemctl('is-enabled', 'clamav-daemon') === 'disabled', `and disables it at boot (${systemctl('is-enabled', 'clamav-daemon')})`);
} finally {
  await remove().catch(() => {});
  // Back to the default: uploads scanned.
  await api('POST', '/malware/upload-scan', { data: { enabled: true } }).catch(() => {});
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
