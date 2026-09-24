// The two parts that load on demand still load, and still work.
//
//     node lazy-parts.mjs
//
// The page snapshots cover what a page shows when it opens. They do not open
// the terminal or the standalone editor, which are now fetched only when
// asked for - so this does:
//
//   * the standalone editor window mounts ace and shows the file;
//   * the Websites page's terminal button mounts xterm.
//
// And it checks the split did what it was for: a plain page load must not
// fetch either chunk.
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await logIn(context);

const sites = await (await context.request.get(`${BASE}/api/websites`)).json();
const site = (Array.isArray(sites) ? sites : sites.items || sites.websites || [])[0];
if (!site) throw new Error('no website on this box to open');

let ok = true;
const check = (cond, pass, fail) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${cond ? pass : fail}`); ok &&= cond; };

// 1. A plain page load fetches neither heavy chunk.
{
  const page = await context.newPage();
  const fetched = [];
  page.on('request', (r) => { if (/\/assets\/(CodeEditor|Terminal)-/.test(r.url())) fetched.push(r.url()); });
  await page.goto(`${BASE}/website`, { waitUntil: 'networkidle' });
  check(fetched.length === 0, 'opening Websites fetches neither the editor nor the terminal', `fetched ${fetched.join(', ')}`);

  // 2. The terminal, on demand.
  await page.getByRole('button', { name: `Open terminal for ${site.domain}` }).click();
  const xterm = await page.locator('.xterm').first().waitFor({ timeout: 15000 }).then(() => true, () => false);
  check(xterm, 'the terminal mounts xterm when opened', 'no .xterm element after opening the terminal');
  check(fetched.some((u) => /Terminal-/.test(u)), 'and fetched its chunk to do it', 'the terminal chunk was never requested');
  await page.close();
}

// 3. The standalone editor.
{
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  const url = `${BASE}/filemanager?view=editor&website_id=${site.id}&path=${encodeURIComponent('public_html/index.php')}`;
  await page.goto(url, { waitUntil: 'networkidle' });
  const ace = await page.locator('.ace_editor').first().waitFor({ timeout: 15000 }).then(() => true, () => false);
  check(ace, 'the standalone editor mounts ace', 'no .ace_editor element in the editor window');
  check(errors.length === 0, 'without a page error', errors.join(' | '));
  await page.close();
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
