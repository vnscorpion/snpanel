// The server's messages in the viewer's language.
//
//     node server-messages.mjs
//
// The API answers in English; the panel shows its messages in Vietnamese
// through src/i18n/vi-server.js, which it downloads only for a viewer who
// reads Vietnamese. What is checked, on the running panel:
//
//   - The Application addon's summary - English in the Rust since the panel
//     made English its language - reads in English, and after the switch
//     in the Python's own Vietnamese, word for word: the catalogue arrived
//     and the page drew again without a reload.
//   - A refusal from the server - a blocklist URL that is not http(s), which
//     changes nothing - arrives as a toast in the language on screen, both
//     ways.
//   - The malware status line and the IPv6 line on the settings page, which
//     pages show as the server wrote them, are Vietnamese.
//   - Nothing throws on the way.
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US' });
await logIn(context);
const page = await context.newPage();
const thrown = [];
page.on('pageerror', (e) => thrown.push(String(e)));

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const visible = (text) => page.getByText(text, { exact: true }).first().isVisible().catch(() => false);
const anyVisible = async (texts) => {
  for (const text of texts) if (await visible(text)) return text;
  return null;
};

const SUMMARY_EN = 'Runs Node.js apps, containers and Docker Compose projects, served on a domain through Nginx.';
const SUMMARY_VI = 'Chạy ứng dụng Node.js, container và Docker Compose, đưa ra domain qua Nginx.';
const URL_EN = 'URL must start with http:// or https://';
const URL_VI = 'URL phải bắt đầu bằng http:// hoặc https://';
const MALWARE_VI = [
  'Chưa cài trình quét. Bật để panel tự cài đặt.',
  'Đã cài trình quét nhưng đang tắt.',
  'Đang quét theo lịch. Bảo vệ thời gian thực (cấp 2) chưa chạy.',
  'Đang quét, hoạt động bình thường.',
];
const IPV6_VI = [
  'Không đọc được trạng thái IPv6 của máy chủ.',
  'VPS của bạn không có địa chỉ IPv6 nên không thể dùng tính năng này. Liên hệ nhà cung cấp để được cấp IPv6, sau đó bật lại.',
  'Website và panel đang nhận kết nối qua cả IPv4 và IPv6.',
  'VPS có IPv6. Bật để website và panel nhận thêm kết nối IPv6.',
];

async function refuseBlocklist(expected) {
  await page.goto(`${BASE}/firewall`, { waitUntil: 'networkidle' });
  const input = page.locator('.fw-url-form input');
  await input.fill('ftp://example.com/list.txt');
  await page.locator('.fw-url-form button[type="submit"]').click();
  const toast = page.getByRole('alert');
  await toast.waitFor({ timeout: 10000 }).catch(() => {});
  const text = (await toast.textContent().catch(() => '')) || '';
  check(text.includes(expected), `the refusal reads "${expected}" (toast: ${JSON.stringify(text.slice(0, 120))})`);
}

// English first.
await page.goto(`${BASE}/addons`, { waitUntil: 'networkidle' });
check(await visible(SUMMARY_EN), 'the Application addon reads in English');
await refuseBlocklist(URL_EN);

// The switch, without a reload.
await page.goto(`${BASE}/addons`, { waitUntil: 'networkidle' });
const loads = [];
page.on('request', (r) => { if (/vi-server-[\w-]+\.js$/.test(r.url())) loads.push(r.url()); });
await page.getByRole('button', { name: 'Switch language to Tiếng Việt' }).click();
await page.getByText(SUMMARY_VI, { exact: true }).first().waitFor({ timeout: 10000 }).catch(() => {});
check(await visible(SUMMARY_VI), "after the switch it reads in the Python's own Vietnamese");
check(!(await visible(SUMMARY_EN)), 'and the English is gone');
check(loads.length === 1, `the server catalogue was downloaded once, on the switch (${loads.length})`);

await refuseBlocklist(URL_VI);

await page.goto(`${BASE}/malware`, { waitUntil: 'networkidle' });
const malware = await anyVisible(MALWARE_VI);
check(!!malware, `the malware status line is Vietnamese (${malware})`);

await page.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });
const ipv6 = await anyVisible(IPV6_VI);
check(!!ipv6, `the IPv6 line is Vietnamese (${ipv6 && ipv6.slice(0, 60)})`);

// Back to English, where the same line is English again.
await page.getByRole('button', { name: 'Chuyển ngôn ngữ sang English' }).click();
await page.waitForTimeout(300);
check(!(await anyVisible(IPV6_VI)), 'switching back leaves no Vietnamese IPv6 line');

check(thrown.length === 0, `nothing threw (${thrown.join(' | ').slice(0, 200)})`);
await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
