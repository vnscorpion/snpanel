// The Restore tab as it looks: the whole tab, in English and Vietnamese, and
// Another server's form - pictures only, nothing restored.
//
//     node restore-look.mjs [out-dir] [width]      (LOGIN_FILE: the administrator's)
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/restore-look';
const WIDTH = Number(process.argv[3] || 1440);
mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch();
for (const locale of ['en', 'vi']) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: WIDTH, height: 900 }, locale: 'en-US' });
  await context.addInitScript((l) => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
  await logIn(context);
  const page = await context.newPage();
  await page.goto(`${BASE}/backups`, { waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: locale === 'vi' ? 'Khôi phục' : 'Restore' }).click();
  await page.locator('.bk-restore').waitFor();
  await page.waitForTimeout(2500);
  await page.evaluate(() => document.querySelectorAll('.app-toast-stack, .loading').forEach((el) => { el.style.display = 'none'; }));
  const tab = page.locator('.backup-tab-panel');
  await tab.screenshot({ path: `${OUT}/restore-${locale}-${WIDTH}.png` });
  console.log(`saved ${OUT}/restore-${locale}-${WIDTH}.png`);
  // Another server: its form, before it is reached.
  await page.getByRole('radio').nth(2).click();
  await page.locator('.bk-connection').waitFor();
  await page.mouse.move(0, 0);
  await page.waitForTimeout(500);
  await tab.screenshot({ path: `${OUT}/another-${locale}-${WIDTH}.png` });
  console.log(`saved ${OUT}/another-${locale}-${WIDTH}.png`);
  await context.close();
}
await browser.close();
