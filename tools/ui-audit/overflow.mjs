// Which elements stick out past the right edge of a narrow screen.
//
//     node overflow.mjs <path> [width] [locale]
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const [path = '/', width = '390', locale = 'en'] = process.argv.slice(2);
const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: Number(width), height: 844 }, locale: 'en-US' });
await context.addInitScript((l) => { try { localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
await logIn(context);
const page = await context.newPage();
await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(500);
const found = await page.evaluate(() => {
  const vw = document.documentElement.clientWidth;
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.right <= vw + 0.5) continue;
    // Report only the outermost offenders: skip an element whose parent also sticks out.
    const pr = el.parentElement?.getBoundingClientRect();
    if (pr && pr.right > vw + 0.5) continue;
    const cls = typeof el.className === 'string' ? el.className : '';
    out.push(`${el.tagName.toLowerCase()}${cls ? '.' + cls.trim().split(/\s+/).join('.') : ''}  right=${r.right.toFixed(1)} width=${r.width.toFixed(1)}  "${(el.textContent || '').trim().slice(0, 50)}"`);
  }
  // The first offender's ancestors: who lets it out.
  const first = [...document.querySelectorAll('body *')].find((el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.right > vw + 0.5 && !(el.parentElement && el.parentElement.getBoundingClientRect().right > vw + 0.5);
  });
  const chain = [];
  for (let el = first?.parentElement; el && chain.length < 6; el = el.parentElement) {
    const s = getComputedStyle(el);
    chain.push(`${el.tagName.toLowerCase()}.${(typeof el.className === 'string' ? el.className : '').trim().split(/\s+/).join('.')}  display=${s.display} overflow-x=${s.overflowX} width=${el.getBoundingClientRect().width.toFixed(1)} min-width=${s.minWidth}`);
  }
  return { vw, scroll: document.documentElement.scrollWidth, out: out.slice(0, 15), chain };
});
console.log(`viewport ${found.vw}, scrollWidth ${found.scroll}`);
for (const line of found.out) console.log('  ' + line);
for (const line of found.chain) console.log('    in ' + line);
await browser.close();
