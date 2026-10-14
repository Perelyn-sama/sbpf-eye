import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { parseELF, dumpHex, parsePaste } from './public/elf.js';
import { browserFallback } from './public/api/report.js';
import { instructionIds, pageForId, inRanges, hexWord } from './public/navigation.js';

let server, base;
async function startServer(extraEnv = {}) {
  const child = spawn(process.execPath, ['server.mjs'], { env: { ...process.env, PORT: '0', SBPF_EYE_BIN: process.env.SBPF_EYE_BIN || resolve('bridge/target/debug/sbpf-eye-web-bridge'), ...extraEnv }, stdio: ['ignore','pipe','pipe'] });
  let stderr = ''; child.stderr.on('data', d => { stderr += d; });
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Server did not start')), 10000);
    child.stdout.on('data', data => { const url = data.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0]; if (url) { clearTimeout(timer); resolve(url); } });
    child.once('error', reject);
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Server exited: ${code}: ${stderr}`)); });
  });
  return { server: child, base: url };
}
before(async () => { ({ server, base } = await startServer()); });
after(async () => { if (server && server.exitCode == null) { server.kill(); await once(server, 'exit'); } });
async function analyze(bytes) {
  const res = await fetch(base+'/api/analyze', { method: 'POST', body: bytes });
  assert.equal(res.status,200);const result=await res.json();assert.equal(result.ok,true,JSON.stringify(result));return result.json;
}
test('existing paste and browser fallback utilities', async () => {
  const bytes=await readFile('../samples/hello_solana_asm_program.so');
  assert.equal(parseELF(bytes).isBPF,true);assert.ok(parseELF(bytes).sections.length>0);
  assert.deepEqual(parsePaste('7f 45 4c 46'),Uint8Array.from([127,69,76,70]));
  assert.deepEqual(parsePaste('f0VMRg=='),Uint8Array.from([127,69,76,70]));
  assert.equal(dumpHex(bytes,0,16).length,1);assert.throws(()=>parseELF(new Uint8Array(12)));
});
test('HTTP report and function/block/instruction/file navigation use real fixture data', async () => {
  const bytes=await readFile('../samples/hello_solana_native_program.so');const report=await analyze(bytes);
  assert.equal(report.schemaVersion,1);assert.equal(report.analysis.instructionCount,report.instructions.length);
  assert.equal(report.instructions[0].engine,'blueshift');
  for (const f of report.analysis.functions) {
    const ids=instructionIds(report,{kind:'function',id:f.id});
    assert.ok(ids.length>0);
    for (const id of ids) assert.ok(report.instructions[id].functionIds.includes(f.id));
    for (const blockId of f.blocks) {
      for (const id of instructionIds(report,{kind:'block',id:blockId})) assert.ok(ids.includes(id));
    }
  }
  const last=report.instructions.at(-1);assert.ok(pageForId(instructionIds(report,null),last.id)>0);
  assert.equal(last.bytes,[...bytes.subarray(last.location.fileOffset,last.location.fileOffset+last.length)].map(b=>b.toString(16).padStart(2,'0')).join(' '));
  assert.equal(inRanges(last.location.fileOffset,[{offset:last.location.fileOffset,length:last.length}]),true);
  assert.equal(inRanges(last.location.fileOffset+last.length,[{offset:last.location.fileOffset,length:last.length}]),false);
  assert.equal(hexWord('0xfffffffffffffffe'),'0xfffffffffffffffe');
});
test('malformed input returns stage errors, not a transport error',async()=>{
  const report=await analyze(new Uint8Array([1,2,3]));assert.equal(report.fileSize,3);assert.equal(report.header,null);
  assert.ok(report.stages.some(s=>s.status==='error'));assert.equal(report.analysis,null);
});
test('static assets and size limit', async()=>{
  const response=await fetch(base+'/');assert.equal(response.status,200);assert.match(await response.text(),/Control Flow/);
  const script=await fetch(base+'/api/report.js');assert.equal(script.status,200);
  const res=await fetch(base+'/api/analyze',{method:'POST',body:new Uint8Array(8*1024*1024+1)});assert.equal(res.status,413);
});

test('subprocess failure retains genuine low-level checkpoint', async () => {
  const other = await startServer({ SBPF_EYE_BIN: process.execPath,
    SBPF_EYE_ARGS_JSON: JSON.stringify([resolve('bridge/tests/checkpoint-exit.mjs'), '{file}']),
    REAL_BRIDGE: resolve('bridge/target/debug/sbpf-eye-web-bridge') });
  try {
    const bytes = await readFile('../samples/hello_solana_asm_program.so');
    const response = await fetch(other.base+'/api/analyze', { method:'POST', body:bytes });
    const result = await response.json();
    assert.equal(result.ok,true);assert.equal(result.exitCode,17);
    assert.equal(result.json.instructions.length,4);assert.ok(result.json.sections.length>0);
    assert.equal(result.json.analysis,null);
    assert.ok(result.json.stages.some(s=>s.name==='analysis' && s.status==='error' && s.message.includes('checkpoint retained')));
  } finally { other.server.kill();await once(other.server,'exit'); }
});

test('bridge-unavailable fallback uses the same address wire types', async () => {
  const bytes = await readFile('../samples/hello_solana_asm_program.so');
  const report = browserFallback(bytes, 'Bridge unavailable');
  assert.equal(report.schemaVersion, 1);
  assert.equal(typeof report.header.entry, 'string');
  assert.ok(report.sections.every(s => typeof s.offset === 'string' && typeof s.size === 'string'));
  assert.ok(report.segments.every(s => typeof s.virtualAddress === 'string'));
  assert.ok(report.symbols.every(s => typeof s.value === 'string'));
  assert.ok(report.relocations.every(r => typeof r.offset === 'string'));
  assert.equal(report.analysis, null);
  assert.equal(report.stages[0].status, 'error');
});
