// bisect.mjs - which block of a page makes it wider than the window: hide
// each candidate in turn and measure again. Same environment as shots.mjs.
//   ... node bisect.mjs /route 'selector'
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { BASE } from './capture.mjs';
import { totp } from './totp.mjs';

const [route, selector] = process.argv.slice(2);
const hostMap = process.env.HOST_MAP;
const browser = await chromium.launch(hostMap ? { args: [`--host-resolver-rules=MAP ${hostMap.split('=')[0]} ${hostMap.split('=')[1]}`] } : {});
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: Number(process.env.WIDTH || 390), height: 844 }, isMobile: true, hasTouch: true });
await context.addInitScript(([l]) => { try { localStorage.setItem('snpanel-locale', l); } catch {} }, [process.env.LOCALE || 'en']);
const page = await context.newPage();
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
const text = readFileSync(process.env.LOGIN_FILE, 'utf8');
const form = { username: /^User: (.+)$/m.exec(text)[1].trim(), password: /^Password: (.+)$/m.exec(text)[1].trim() };
const secret = /^TOTP: (.+)$/m.exec(text)?.[1]?.trim();
if (secret) form.otp = totp(secret);
await page.evaluate(async (f) => fetch('/api/auth/login', { method: 'POST', body: new URLSearchParams(f), credentials: 'include' }), form);
await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(800);
const report = await page.evaluate((sel) => {
  const doc = document.documentElement;
  const width = () => doc.scrollWidth - doc.clientWidth;
  const out = [`whole page: ${width()}px`];
  for (const el of document.querySelectorAll(sel)) {
    const before = el.style.display;
    el.style.display = 'none';
    out.push(`without ${el.tagName.toLowerCase()}.${String(el.className).trim().split(/\s+/).join('.')} (${(el.textContent || '').trim().slice(0, 30)}): ${width()}px`);
    el.style.display = before;
  }
  return out;
}, selector);
console.log(report.join('\n'));
await browser.close();
