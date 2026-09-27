// Compare screenshots pixel by pixel.
//
//     node pixel-diff.mjs <a.png> <b.png> [<a.png> <b.png> ...]
//
// For each pair prints the sizes and how many pixels differ; exits 1 if any
// pair differs. A refactor that means to change nothing on screen should
// leave every pair at 0. With DIFF_OUT=<dir>, each differing pair also gets
// an image there: the second screenshot faded, the differing pixels red.
import { chromium } from 'playwright';
import { readFileSync, writeFileSync } from 'node:fs';

const files = process.argv.slice(2);
if (files.length === 0 || files.length % 2) {
  console.error('usage: node pixel-diff.mjs <a.png> <b.png> [...]');
  process.exit(2);
}
const browser = await chromium.launch();
const page = await browser.newPage();
let same = true;
for (let i = 0; i < files.length; i += 2) {
  const [a, b] = [files[i], files[i + 1]].map((f) => `data:image/png;base64,${readFileSync(f).toString('base64')}`);
  const result = await page.evaluate(async ([srcA, srcB, wantImage]) => {
    const load = (src) => new Promise((ok, fail) => { const img = new Image(); img.onload = () => ok(img); img.onerror = fail; img.src = src; });
    const [ia, ib] = await Promise.all([load(srcA), load(srcB)]);
    if (ia.width !== ib.width || ia.height !== ib.height) {
      return { size: `${ia.width}x${ia.height} vs ${ib.width}x${ib.height}`, differing: -1 };
    }
    const pixels = (img) => {
      const c = document.createElement('canvas');
      c.width = img.width; c.height = img.height;
      const ctx = c.getContext('2d');
      ctx.drawImage(img, 0, 0);
      return ctx.getImageData(0, 0, img.width, img.height).data;
    };
    const pa = pixels(ia);
    const pb = pixels(ib);
    let differing = 0;
    let box = null;
    for (let p = 0; p < pa.length; p += 4) {
      if (pa[p] !== pb[p] || pa[p + 1] !== pb[p + 1] || pa[p + 2] !== pb[p + 2] || pa[p + 3] !== pb[p + 3]) {
        differing += 1;
        const x = (p / 4) % ia.width;
        const y = Math.floor(p / 4 / ia.width);
        box = box ? [Math.min(box[0], x), Math.min(box[1], y), Math.max(box[2], x), Math.max(box[3], y)] : [x, y, x, y];
      }
    }
    let image = null;
    if (differing > 0 && wantImage) {
      const c = document.createElement('canvas');
      c.width = ia.width; c.height = ia.height;
      const ctx = c.getContext('2d');
      ctx.globalAlpha = 0.25;
      ctx.drawImage(ib, 0, 0);
      ctx.globalAlpha = 1;
      const overlay = ctx.getImageData(0, 0, ia.width, ia.height);
      for (let p = 0; p < pa.length; p += 4) {
        if (pa[p] !== pb[p] || pa[p + 1] !== pb[p + 1] || pa[p + 2] !== pb[p + 2] || pa[p + 3] !== pb[p + 3]) {
          overlay.data[p] = 255; overlay.data[p + 1] = 0; overlay.data[p + 2] = 0; overlay.data[p + 3] = 255;
        }
      }
      ctx.putImageData(overlay, 0, 0);
      image = c.toDataURL('image/png');
    }
    return { size: `${ia.width}x${ia.height}`, differing, box, image };
  }, [a, b, !!process.env.DIFF_OUT]);
  const ok = result.differing === 0;
  same &&= ok;
  const where = result.box ? ` in x ${result.box[0]}-${result.box[2]}, y ${result.box[1]}-${result.box[3]}` : '';
  if (result.image) {
    const file = `${process.env.DIFF_OUT}/diff-${i / 2 + 1}.png`;
    writeFileSync(file, Buffer.from(result.image.split(',')[1], 'base64'));
    console.log(`      wrote ${file}`);
  }
  console.log(`${ok ? 'SAME' : 'DIFF'}  ${files[i]}  ${files[i + 1]}  ${result.size}  ${result.differing === -1 ? 'sizes differ' : `${result.differing} pixels differ${where}`}`);
}
await browser.close();
process.exit(same ? 0 : 1);
