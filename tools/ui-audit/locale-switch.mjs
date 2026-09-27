// The language switch changes the language, and the choice survives a reload.
//
//     node locale-switch.mjs
//
// English is what a browser that says en-US gets. Pressing the switch must
// put the page into Vietnamese without a reload; reloading must keep it
// there; pressing again must bring English back.
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US' });
await logIn(context);
const page = await context.newPage();

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= cond; };
// A string the Malware page shows whenever the scanner is installed, in both
// languages. Required, not optional: a check that skips when its string is
// missing passes on a page that shows nothing.
const EN = 'Level 1 — Scheduled scans', VI = 'Cấp 1 — Quét theo lịch';
const present = (text) => page.getByText(text, { exact: true }).first().isVisible().catch(() => false);

await page.goto(`${BASE}/malware`, { waitUntil: 'networkidle' });
const lang0 = await page.evaluate(() => document.documentElement.lang);
check(lang0 === 'en', `an en-US browser starts in English (lang=${lang0})`);
check(await present(EN), `the page shows "${EN}" in English`);

await page.getByRole('button', { name: 'Switch language to Tiếng Việt' }).click();
await page.waitForTimeout(300);
const lang1 = await page.evaluate(() => document.documentElement.lang);
check(lang1 === 'vi', `the switch puts the page into Vietnamese (lang=${lang1})`);
check(await page.getByRole('button', { name: 'Chuyển ngôn ngữ sang English' }).isVisible(), 'the switch now offers English, in Vietnamese');
check(await present(VI), `"${EN}" became "${VI}" without a reload`);

await page.reload({ waitUntil: 'networkidle' });
const lang2 = await page.evaluate(() => document.documentElement.lang);
check(lang2 === 'vi', `the choice survives a reload (lang=${lang2})`);

await page.getByRole('button', { name: 'Chuyển ngôn ngữ sang English' }).click();
await page.waitForTimeout(300);
const lang3 = await page.evaluate(() => document.documentElement.lang);
check(lang3 === 'en', `pressing again brings English back (lang=${lang3})`);

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
