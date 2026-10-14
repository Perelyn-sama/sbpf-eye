// Optional browser QA: npm install --no-save playwright, then set BROWSER_EXECUTABLE
// to a Chromium browser, or run `npx playwright install chromium`.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const server = spawn(process.execPath,['server.mjs'],{env:{...process.env,PORT:'0',SBPF_EYE_BIN:process.env.SBPF_EYE_BIN||resolve('bridge/target/debug/sbpf-eye-web-bridge')},stdio:['ignore','pipe','inherit']});
let browser;
try {
  const base=await new Promise((resolve,reject)=>{server.stdout.on('data',d=>{const url=d.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];if(url)resolve(url);});server.once('error',reject);server.once('exit',code=>reject(Error(`server exit ${code}`)));});
  browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXECUTABLE?{executablePath:process.env.BROWSER_EXECUTABLE}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);
  await page.setInputFiles('#file','../samples/hello_solana_native_program.so');
  await page.waitForFunction(()=>document.querySelector('#engine').textContent==='Analysis ready');
  assert.equal(await page.locator('#ninstructions').innerText(),'2786');
  await page.click('nav [data-view="sections"]');
  await page.getByRole('button',{name:'.text',exact:true}).click();
  await page.getByRole('button',{name:'Show related symbols',exact:true}).click();
  assert.match(await page.locator('#content').innerText(),/Symbols for .text/);
  await page.click('nav [data-view="functions"]');
  await page.locator('[data-action="function"]').first().click();
  assert.match(await page.locator('#content').innerText(),/FUNCTION #0/);
  await page.locator('[data-action="instruction"]').first().click();
  assert.ok(await page.locator('.byte-selected').count()>=8);
  await page.getByRole('button',{name:'Open Hex Viewer',exact:true}).click();
  assert.equal(await page.locator('#heading').innerText(),'Hex Viewer');
  await page.click('nav [data-view="relocations"]');
  await page.locator('[data-action="relocation"]').first().click();
  await page.getByRole('button',{name:'Target bytes',exact:true}).click();
  assert.ok(await page.locator('.byte-selected').count()>0);
  await page.click('nav [data-view="blocks"]');
  await page.locator('svg g[data-action="block"]').first().click();
  await page.getByRole('button',{name:'Show instructions',exact:true}).click();
  assert.match(await page.locator('#heading').innerText(),/Disassembly/);
  await page.click('nav [data-view="blocks"]');
  await page.screenshot({path:process.env.SCREENSHOT_PATH||'/tmp/sbpf-eye-cfg.png',fullPage:true});
  await page.setInputFiles('#file',{name:'broken.elf',mimeType:'application/octet-stream',buffer:Buffer.from([1,2,3])});
  await page.waitForFunction(()=>document.querySelector('#engine').textContent==='Inspection ready');
  await page.click('nav [data-view="hex"]');
  assert.match(await page.locator('.hex').innerText(),/01 02 03/);
  // A real malformed fixture still exposes valid assembly when sbpf-eye rejects its header.
  const odd=await readFile('../samples/hello_solana_asm_program.so');odd[7]=9;
  await page.setInputFiles('#file',{name:'unusual.elf',mimeType:'application/octet-stream',buffer:odd});
  await page.waitForFunction(()=>document.querySelector('#filepill').textContent.startsWith('unusual.elf') && document.querySelector('#engine').textContent==='Inspection ready');
  assert.equal(await page.locator('#ninstructions').innerText(),'4');
  await page.setViewportSize({width:390,height:844});
  await page.click('nav [data-view="instructions"]');
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth), 'Mobile layout must not overflow horizontally');
  await page.screenshot({path:'/tmp/sbpf-eye-mobile.png',fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('Browser QA passed: upload, sections/symbols, functions, blocks, CFG, disassembly/hex, relocations, malformed input, mobile rendering.');
} finally {
  await browser?.close();if(server.exitCode==null){server.kill();await once(server,'exit');}
}
