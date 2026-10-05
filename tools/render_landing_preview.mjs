// A social-sharing card made from the existing font and real, fictional-data UI capture.
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import path from "node:path";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const root = path.resolve(import.meta.dirname, "..");
const site = path.join(root, "landingpage");
const encoded = async (file, type) =>
  `data:${type};base64,${(await readFile(path.join(site, file))).toString("base64")}`;
const font = await encoded("fonts/Manrope-Variable.woff2", "font/woff2");
const screen = await encoded("assets/product-chat.png", "image/png");
const star = await encoded("favicon.svg", "image/svg+xml");
const browser = await chromium.launch({
  executablePath:
    process.env.CHROME_PATH ??
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  headless: true,
});
try {
  const page = await browser.newPage({
    viewport: { width: 1200, height: 630 },
    deviceScaleFactor: 1,
  });
  await page.setContent(`<!doctype html><html lang="en"><meta charset="utf-8"><style>
 @font-face{font-family:Manrope;src:url(${font})}*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;overflow:hidden;background:#eff3ed;color:#294637;font-family:Manrope,sans-serif;position:relative}.copy{position:absolute;left:70px;top:54px;width:680px}.brand{display:flex;align-items:center;gap:12px;font-size:36px;font-weight:800;letter-spacing:-2px}.brand img{width:35px;height:35px}h1{font-size:64px;line-height:1.07;letter-spacing:-3px;margin:58px 0 26px;font-weight:650}p{font-size:27px;line-height:1.5;margin:0;color:#587061}.small{font-size:20px;margin-top:35px}.screen{position:absolute;right:78px;top:43px;height:544px;border:5px solid #c2d8c7;border-radius:28px;overflow:hidden;box-shadow:0 24px 55px #29463723}.screen img{display:block;height:100%;width:auto}.ring{position:absolute;width:490px;height:490px;right:-80px;top:75px;border:2px solid #c9dbca;border-radius:50%}.ring.inner{width:590px;height:590px;right:-130px;top:25px}
 </style><div class="ring"></div><div class="ring inner"></div><main class="copy"><div class="brand">elo.now<img src="${star}" alt=""></div><h1>Private team<br>communication.</h1><p>Encrypted conversations.<br>Your infrastructure.</p><p class="small">Open source</p></main><div class="screen"><img src="${screen}" alt="A fictional Studio North team preparing a product launch in elo.now"></div></html>`);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForFunction(() =>
    [...document.images].every((i) => i.complete && i.naturalWidth),
  );
  await page.screenshot({ path: path.join(site, "assets/social-preview.png") });
} finally {
  await browser.close();
}
console.log("Created 1200 × 630 social preview from existing product assets.");
