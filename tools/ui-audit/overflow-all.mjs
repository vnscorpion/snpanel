// Every page at three widths and in both languages: is the document wider
// than the window, and which elements stick out?
//
//     node overflow-all.mjs
import { chromium } from 'playwright';
import { BASE, ROUTES, logIn } from './capture.mjs';

const WIDTHS = [1440, 1024, 390];
const LOCALES = ['en', 'vi'];
const browser = await chromium.launch();
let bad = 0;
for (const locale of LOCALES) {
  for (const width of WIDTHS) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, locale: 'en-US' });
    await context.addInitScript((l) => { try { localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
    await logIn(context);
    const page = await context.newPage();
    for (const [name, route] of Object.entries({ ...ROUTES, mcp: '/ai-assistants', waf: '/waf' })) {
      await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(400);
      const r = await page.evaluate(() => {
        const vw = document.documentElement.clientWidth;
        const sw = document.documentElement.scrollWidth;
        const out = [];
        for (const el of document.querySelectorAll('body *')) {
          const b = el.getBoundingClientRect();
          if (b.width === 0 || b.right <= vw + 0.5) continue;
          const pb = el.parentElement?.getBoundingClientRect();
          if (pb && pb.right > vw + 0.5) continue;
          // Inside a box that scrolls on its own is fine.
          let scroller = el.parentElement;
          let contained = false;
          while (scroller && scroller !== document.body) {
            const cs = getComputedStyle(scroller);
            if (/(auto|scroll|hidden)/.test(cs.overflowX) && scroller.getBoundingClientRect().right <= vw + 0.5) { contained = true; break; }
            scroller = scroller.parentElement;
          }
          if (contained) continue;
          const cls = typeof el.className === 'string' ? el.className.trim().split(/\s+/).slice(0, 3).join('.') : '';
          out.push(`${el.tagName.toLowerCase()}${cls ? '.' + cls : ''} right=${Math.round(b.right)}`);
        }
        return { vw, sw, out: out.slice(0, 4) };
      });
      if (r.sw > r.vw + 1 || r.out.length) {
        bad++;
        console.log(`${locale} ${width} ${name}: document ${r.sw}px in ${r.vw}px; ${r.out.join(' | ')}`);
      }
    }
    await context.close();
  }
}
await browser.close();
console.log(bad ? `${bad} page(s) overflow` : 'no page overflows');
