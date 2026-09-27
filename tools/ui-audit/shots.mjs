// shots.mjs - screenshots of chosen pages at one width, theme and locale.
//
//   PANEL_BASE=https://<ip>:2222 LOGIN_FILE=login-deb13t.txt \
//   WIDTH=390 THEME=light LOCALE=en node shots.mjs <out-dir> <page> ...
//
// A page is a name from capture.mjs's ROUTES, or name=/route. "login" shots
// the sign-in page before logging in. Each line printed says whether the page
// is wider than the window, and how many console errors it logged.
import { chromium } from 'playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import { BASE, ROUTES } from './capture.mjs';
import { totp } from './totp.mjs';

// Whoever the login file names - the administrator, or a customer - with a
// code from the authenticator secret when the file has one. A code already
// used in its 30 seconds is refused, so a refusal waits for the next one.
async function logIn(context) {
  const text = readFileSync(process.env.LOGIN_FILE || '/root/login.txt', 'utf8');
  const username = /^User: (.+)$/m.exec(text)?.[1]?.trim() || 'admin';
  const password = /^Password: (.+)$/m.exec(text)?.[1]?.trim();
  const secret = /^TOTP: (.+)$/m.exec(text)?.[1]?.trim();
  // With HOST_MAP only the browser can resolve the name, so the same API
  // call is made from a page on the panel's own origin.
  const page = hostMap ? await context.newPage() : null;
  if (page) await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const form = { username, password };
    if (secret) form.otp = totp(secret);
    let status;
    let body;
    if (page) {
      ({ status, body } = await page.evaluate(async (f) => {
        const res = await fetch('/api/auth/login', { method: 'POST', body: new URLSearchParams(f), credentials: 'include' });
        return { status: res.status, body: await res.json().catch(() => ({})) };
      }, form));
    } else {
      const res = await context.request.post(`${BASE}/api/auth/login`, { form });
      status = res.status();
      body = await res.json().catch(() => ({}));
    }
    if (status === 200 && body.access_token) { if (page) await page.close(); return; }
    if (!secret) throw new Error(`login failed: HTTP ${res.status()}`);
    await new Promise((r) => setTimeout(r, 30000 - (Date.now() % 30000) + 500));
  }
  throw new Error('login failed with the authenticator code');
}

const out = process.argv[2];
const wanted = process.argv.slice(3);
const width = Number(process.env.WIDTH || 1440);
const mobile = width < 600;
const theme = process.env.THEME || 'light';
const locale = process.env.LOCALE || 'en';
mkdirSync(out, { recursive: true });

// HOST_MAP=name=ip: reach the panel by its hostname, the way passkeys need,
// without DNS. PANEL_BASE then names the hostname.
const hostMap = process.env.HOST_MAP;
const browser = await chromium.launch(hostMap
  ? { args: [`--host-resolver-rules=MAP ${hostMap.split('=')[0]} ${hostMap.split('=')[1]}`] }
  : {});
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width, height: mobile ? 844 : 900 },
  isMobile: mobile,
  hasTouch: mobile,
});
await context.addInitScript(([t, l]) => {
  try {
    localStorage.setItem('snpanel-theme', t);
    localStorage.setItem('snpanel-locale', l);
  } catch {}
}, [theme, locale]);

async function shoot(page, name) {
  const file = `${out}/${name}-${width}-${theme}-${locale}.png`;
  await page.screenshot({ path: file, fullPage: true });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  // Which elements reach past the window, the innermost first: the ones
  // whose children all fit are the ones that set the width.
  if (overflow > 0) {
    const culprits = await page.evaluate(() => {
      const width = document.documentElement.clientWidth;
      const wide = [...document.querySelectorAll('body *')].filter((el) => el.getBoundingClientRect().right > width + 1);
      const innermost = wide.filter((el) => ![...el.children].some((c) => wide.includes(c)));
      return innermost.slice(0, 6).map((el) => `${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? `.${el.className.trim().split(/\s+/).join('.')}` : ''} right=${Math.round(el.getBoundingClientRect().right)} w=${Math.round(el.getBoundingClientRect().width)}`);
    });
    console.log(`  overflow by: ${culprits.join(' | ')}`);
  }
  return { file, overflow };
}

if (wanted.includes('login')) {
  const page = await context.newPage();
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  const { file, overflow } = await shoot(page, 'login');
  console.log(`login          ${file} overflow=${overflow}px`);
  await page.close();
}

await logIn(context);
// name=/route@First button@Second: open the route, then click each named
// control in turn - a tab, a row, a button - before the shot.
for (const item of wanted.filter((w) => w !== 'login')) {
  const [name, spec] = item.includes('=') ? [item.slice(0, item.indexOf('=')), item.slice(item.indexOf('=') + 1)] : [item, ROUTES[item]];
  // machinectl splits arguments at spaces, so a label's spaces come as '~'.
  const [route, ...clicks] = spec.split('@').map((part) => part.replaceAll('~', ' '));
  const page = await context.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(900);
  for (const text of clicks) {
    // select=Option text: pick that option in whichever select offers it.
    if (text.startsWith('select=')) {
      const label = text.slice('select='.length);
      try {
        await page.locator('select').filter({ has: page.locator('option', { hasText: label }) }).first().selectOption({ label });
      } catch (e) {
        errors.push(`could not select "${label}": ${String(e).split('\n')[0]}`);
      }
      await page.waitForTimeout(900);
      continue;
    }
    // hover=Name: rest the pointer on that control, for a shot of its hover
    // state. The last step, since any later click moves the pointer away.
    const hover = text.startsWith('hover=');
    const name = hover ? text.slice('hover='.length) : text;
    const byRole = page.getByRole('button', { name }).or(page.getByRole('tab', { name })).or(page.getByRole('link', { name }));
    const target = (await byRole.count()) ? byRole.first() : page.getByText(name, { exact: false }).first();
    try {
      if (hover) await target.hover({ timeout: 5000 });
      else await target.click({ timeout: 5000 });
    } catch (e) {
      errors.push(`could not ${hover ? 'hover' : 'click'} "${name}": ${String(e).split('\n')[0]}`);
    }
    await page.waitForTimeout(hover ? 400 : 900);
  }
  const { file, overflow } = await shoot(page, name);
  console.log(`${name.padEnd(14)} ${file} overflow=${overflow}px errors=${errors.length}${errors.length ? ` ${errors[0].slice(0, 140)}` : ''}`);
  await page.close();
}
await browser.close();
