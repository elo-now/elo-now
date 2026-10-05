// Local layout/link/asset review. Serves only public landing/store artifacts.
import {createRequire} from 'node:module';
import {createServer} from 'node:http';
import {readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
const require=createRequire(import.meta.url);
const {chromium}=require('playwright');
const root=path.resolve(import.meta.dirname,'..');
const port=Number(process.env.LANDING_REVIEW_PORT ?? 1438);
const server=createServer(async(req,res)=>{
  const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
  const prefix=pathname.startsWith('/store/')?'release/store':'landingpage';
  const relative=pathname.startsWith('/store/')?pathname.slice(7):pathname.slice(1);
  const file=path.resolve(root,prefix,relative.endsWith('/')?relative+'index.html':relative||'index.html');
  if(!file.startsWith(path.join(root,prefix)+path.sep)){res.writeHead(403);res.end();return;}
  try{const types={'.html':'text/html','.css':'text/css','.png':'image/png','.svg':'image/svg+xml','.woff2':'font/woff2','.json':'application/json','.js':'text/javascript','.mp3':'audio/mpeg'};res.setHeader('Content-Type',types[path.extname(file)]??'application/octet-stream');res.end(await readFile(file));}catch{res.writeHead(404);res.end();}
});
await new Promise(resolve=>server.listen(port,'127.0.0.1',resolve));
const browser=await chromium.launch({executablePath:process.env.CHROME_PATH??'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
const page=await browser.newPage();
const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400)errors.push(`${r.status()} ${r.url()}`)});
const results=[];
try{
for(const width of [320,390,768,1440])for(const route of ['/','/light/','/dark/','/privacy/','/terms/','/support/','/delete-account/','/community/']){
  await page.setViewportSize({width,height:900});await page.goto(`http://127.0.0.1:${port}${route}`);await page.evaluate(()=>document.fonts.ready);
  // Force lazy images to load before the completeness check and full-page capture.
  await page.locator('img').evaluateAll(images=>images.forEach(image=>image.loading='eager'));
  await page.waitForFunction(()=>[...document.images].every(image=>image.complete));
  const check=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,broken:[...document.images].filter(image=>!image.naturalWidth).map(image=>image.src),h1:document.querySelectorAll('h1').length}));
  results.push({width,route,...check});
  if(check.overflow||check.broken.length||check.h1!==1)throw new Error(JSON.stringify(results.at(-1)));
  if(width===1440&&route==='/')await page.screenshot({path:'/private/tmp/elo-landing-desktop.png',fullPage:true});
  if(width===390&&route==='/')await page.screenshot({path:'/private/tmp/elo-landing-phone.png',fullPage:true});
  if(width===390&&route==='/')await page.screenshot({path:'/private/tmp/elo-landing-phone-hero.png'});
  if(width===1440&&route==='/')await page.screenshot({path:'/private/tmp/elo-landing-desktop-hero.png'});
  if(width===390&&route==='/light/')await page.screenshot({path:'/private/tmp/elo-landing-light.png',fullPage:true});
  if(width===1440&&route==='/privacy/')await page.screenshot({path:'/private/tmp/elo-landing-privacy.png',fullPage:true});
}
if (!process.argv.includes('--landing-only')) {
  await page.setViewportSize({width:1600,height:1000});await page.goto(`http://127.0.0.1:${port}/store/`);await page.screenshot({path:path.join(root,'release/store/preview.png'),fullPage:true});
}
if(errors.length)throw new Error(errors.join('\n'));
await writeFile('/private/tmp/elo-landing-review.json',JSON.stringify(results,null,2)+'\n');console.log(`Passed ${results.length} responsive page checks; no broken images, overflow or browser errors.`);
}finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
