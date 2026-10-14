import { parsePaste } from './elf.js';
import { analyze } from './api/report.js';
import { PAGE_SIZE, instructionIds, pageForId, inRanges, hexWord as fmt } from './navigation.js';

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mono = value => `<span class="mono">${esc(value)}</span>`;
const button = (action, id, label) => `<button class="link" data-action="${action}" data-id="${id}">${esc(label)}</button>`;
const card = (title, body, right = '') => `<div class="card"><div class="cardhead">${esc(title)}<span class="muted">${esc(right)}</span></div>${body}</div>`;
const pairs = values => `<div class="cardbody pairs">${Object.entries(values).map(([key,value]) => `<div class="pair"><span>${esc(key)}</span><strong>${esc(value ?? '—')}</strong></div>`).join('')}</div>`;
let report = null, bytes = null, filename = '', active = 'overview', page = 0;
let filter = null, selectedInstruction = null, selectedBlock = null, selectedSection = null, selectedRelocation = null;
let hexOffset = 0, highlights = [], request = null;
const views = {
  overview: ['Overview', 'Binary structure and independent analysis stages.'],
  sections: ['ELF Explorer · Sections', 'Section metadata, raw file bytes, and related symbols.'],
  segments: ['ELF Explorer · Segments', 'Program headers and loadable memory ranges.'],
  symbols: ['ELF Explorer · Symbols', 'Symbol tables as recorded in the binary.'],
  relocations: ['ELF Explorer · Relocations', 'Relocation records and mapped targets. No relocations are applied.'],
  instructions: ['Disassembly', 'Raw instruction bytes, decoded assembly, and analysis references.'],
  functions: ['Functions', 'Discovered functions, block membership, call edges, and stack estimates.'],
  blocks: ['Control Flow', 'Interactive basic-block graph and instruction navigation.'],
  hex: ['Hex Viewer', 'Exact uploaded bytes at file offsets.'],
};
function notice(message, type = '') { $('notice').textContent = message; $('notice').className = 'notice ' + type; }
function table(headers, rows) {
  return `<div class="table-scroll"><table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function paged(items, headers, row) {
  const pages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  page = Math.min(page, pages - 1);
  return `<div class="toolbar pagination">${button('page', Math.max(0,page-1), '← Previous')}<span>${items.length} entries · page ${page+1} / ${pages}</span>${button('page', Math.min(pages-1,page+1), 'Next →')}</div>` + table(headers, items.slice(page*PAGE_SIZE,(page+1)*PAGE_SIZE).map(row));
}
function sectionName(index) { return report.sections.find(s => s.index === index)?.name ?? `#${index}`; }
function updateCounts() {
  const values = { nsections: report?.sections.length, nsegments: report?.segments.length, nsymbols: report?.symbols.length,
    nrelocations: report?.relocations.length, nfunctions: report?.analysis?.functions.length, nblocks: report?.analysis?.blocks.length,
    ninstructions: report?.stages.some(s => s.name === 'decode' && ['ok','partial'].includes(s.status)) ? report.instructions.length : null };
  for (const [id,value] of Object.entries(values)) $(id).textContent = value ?? '—';
}
async function load(input, name) {
  if (input.length > 8*1024*1024) { notice('8 MiB maximum binary size', 'error'); return; }
  request?.abort();
  const controller = new AbortController(); request = controller;
  bytes = input; filename = name; report = null; page = hexOffset = 0;
  filter = selectedInstruction = selectedBlock = selectedSection = selectedRelocation = null; highlights = [];
  $('filepill').textContent = `${name} · ${(bytes.length/1024).toFixed(1)} KiB`;
  $('engine').textContent = 'Inspecting…'; updateCounts(); notice('Inspecting structure, decoding instructions, and running static analysis…'); render('overview');
  try {
    const result = await analyze(input, controller.signal);
    if (request !== controller) return;
    report = result;
    const failed = report.stages.filter(s => ['error','partial'].includes(s.status));
    $('engine').textContent = report.analysis ? 'Analysis ready' : 'Inspection ready';
    const warningCount = report.diagnostics.length;
    notice(failed.length || warningCount ? `${failed.length} partial/failed stage(s), ${warningCount} warning(s). Successful results remain available; see Overview.` : 'Inspection ready. Loader validation and relocation application have not been performed.', failed.length || warningCount ? '' : 'success');
    updateCounts(); render(active);
  } catch (error) { if (error.name !== 'AbortError') notice(error.message, 'error'); }
}
$('file').addEventListener('change', async e => { const f = e.target.files?.[0]; if (f) await load(new Uint8Array(await f.arrayBuffer()), f.name); });
$('pasteToggle').onclick = () => { $('pastePanel').hidden = !$('pastePanel').hidden; };
$('loadPaste').onclick = () => { try { load(parsePaste($('paste').value), 'pasted-binary.elf'); } catch(e) { notice(e.message,'error'); } };
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', async e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if(f) await load(new Uint8Array(await f.arrayBuffer()), f.name); });
document.querySelectorAll('nav button').forEach(b => b.onclick = () => { page = 0; render(b.dataset.view); });

function overview() {
  const a = report.analysis, h = report.header;
  const decoded = report.stages.some(s => s.name === 'decode' && ['ok','partial'].includes(s.status));
  let html = `<div class="stats">${[['File size',bytes.length+' B'],['sBPF version',report.sbpfVersion == null ? 'Unknown' : `v${report.sbpfVersion} (ELF flags)`],['Instructions',decoded ? report.instructions.length : '—'],['Functions',a?.functions.length ?? '—'],['Basic blocks',a?.blocks.length ?? '—'],['Relocations',report.relocations.length]].map(([k,v]) => `<div class="stat"><div class="value">${esc(v)}</div><div class="label">${esc(k)}</div></div>`).join('')}</div>`;
  if (h) html += card('ELF HEADER', pairs({ Format: `ELF${h.class === 2 ? 64 : 32} / ${h.endian}-endian`, Machine: `${h.machine} (${[247,263].includes(h.machine) ? 'BPF / sBPF' : 'other'})`, 'ELF type': h.elfType,
    'Entry virtual address': fmt(h.entry), 'Flags (raw)': fmt(h.flags), 'Program table file offset': fmt(h.programOffset), 'Section table file offset': fmt(h.sectionOffset),
    'OS ABI': h.osAbi, 'Header size': h.headerSize, 'Section entries (parsed / declared)': `${report.sections.length} / ${h.sectionCount}`, 'Segment entries (parsed / declared)': `${report.segments.length} / ${h.programCount}` }));
  html += card('ANALYSIS STAGES', table(['Stage','Engine','Status','Details'],report.stages.map(s => [esc(s.name),esc(s.engine),`<span class="${['error','partial'].includes(s.status)?'warning':''}">${esc(s.status)}</span>`,esc(s.message || '—')])));
  if (report.diagnostics.length) html += card('WARNINGS', table(['Stage','Details'],report.diagnostics.map(d => [esc(d.stage),esc(d.message)])));
  if (a) html += card('ANALYSIS SCOPE', pairs({ Reachability: a.reachabilityBasis, 'Stack usage': 'Static estimate for fixed frames only; not runtime consumption', 'Compiler comparison': 'Available in the sbpf-eye CLI', 'Compute-unit profiling': 'Not available from the current analysis API' }));
  return html;
}
function sectionDetail(s) {
  const related = report.symbols.filter(x => x.sectionIndex === s.index);
  return card(`SECTION ${s.name}`, pairs({ Type: s.sectionType, 'File offset': fmt(s.offset), 'Virtual address': fmt(s.address), Size: BigInt(s.size).toString(), Flags: fmt(s.flags), Alignment: fmt(s.alignment), Link: s.link, Info: s.info, 'Entry size': fmt(s.entrySize), 'File-backed': s.fileRange ? 'Yes' : 'No', 'Related symbols': related.length }) +
    `<div class="cardbody">${s.fileRange ? button('sectionBytes',s.index,'Inspect section bytes') : '<p>No file-backed payload. NOBITS occupies memory only.</p>'}${button('sectionSymbols',s.index,'Show related symbols')}</div>`);
}
function relocationDetail(r) {
  return card(`RELOCATION #${r.id}`,pairs({ Type: r.typeName, 'Recorded offset': fmt(r.offset), 'Target section': r.target ? sectionName(r.target.sectionIndex) : 'Unresolved',
    'Section offset': fmt(r.target?.sectionOffset), 'Virtual address': fmt(r.target?.virtualAddress), 'File offset': fmt(r.target?.fileOffset), Mapping: r.mappingNote }) +
    `<div class="cardbody">${button('recordBytes',r.id,'Record bytes')}${r.target?.fileOffset != null ? button('relocationBytes',r.id,'Target bytes') : ''}${r.instructionId != null ? button('instruction',r.instructionId,'Associated instruction') : ''}</div>`);
}
function functionDetail(f) {
  return card(`FUNCTION #${f.id}`,pairs({ 'Entry .text offset': fmt(f.entryPc), 'Entry block': f.entryBlock, 'Block count': f.blocks.length,
    'Reachable via CFG from .text+0 (excludes calls)': f.reachableByControlFlow ? 'Yes' : 'No', 'Local stack estimate': f.stack.localEstimate == null ? 'Unavailable' : `${f.stack.localEstimate} B`, 'Stack model': f.stack.model }) +
    `<div class="cardbody">Blocks: ${f.blocks.map(id=>button('block',id,`#${id}`)).join(' ')}<br>Call edges: ${f.callees.map(id=>button('function',id,`→ function #${id}`)).join(' ') || 'None discovered'}</div>`);
}
function blockDetail(b) {
  return card(`BLOCK #${b.id}`, pairs({ 'Start .text offset': fmt(b.startPc), 'End .text offset (exclusive)': fmt(b.endPc), Terminator: b.terminator }) +
    `<div class="cardbody">${button('blockInstructions',b.id,'Show instructions')}<br>Successors: ${b.successors.map(id=>button('block',id,`#${id}`)).join(' ') || 'None'}<br>Predecessors: ${b.predecessors.map(id=>button('block',id,`#${id}`)).join(' ') || 'None'}<br>Functions: ${b.functionIds.map(id=>button('function',id,`#${id}`)).join(' ') || 'Unassigned'}</div>`);
}
function instructionDetail(i) {
  return card(`INSTRUCTION · .text+${fmt(i.pc)}`, pairs({ Assembly: i.text, 'Virtual address': fmt(i.location.virtualAddress), 'File offset': fmt(i.location.fileOffset), 'Byte length': i.length,
    'Opcode byte': fmt(i.encoding.opcodeByte), 'Register byte': fmt(i.encoding.registerByte), 'Encoded offset': i.encoding.offset, 'Encoded immediate': i.encoding.immediate }) +
    `<div class="cardbody">${button('instructionBytes',i.id,'Open Hex Viewer')}${i.blockId != null ? button('block',i.blockId,`Block #${i.blockId}`) : ''}${i.functionIds.map(id=>button('function',id,`Function #${id}`)).join('')}${i.relocationIds.map(id=>button('relocation',id,`Relocation #${id}`)).join('')}</div>`);
}
function hexView() {
  const end = Math.min(bytes.length, hexOffset+256);
  const rows = [];
  for (let p=hexOffset;p<end;p+=16) {
    const part = bytes.slice(p, Math.min(p+16,end));
    const cells = [...part].map((b,i)=>`<span class="${inRanges(p+i,highlights)?'byte-selected':''}" title="File ${fmt(p+i)}">${b.toString(16).padStart(2,'0')}</span>`).join(' ');
    const sections = report?.sections.filter(s=>s.fileRange && p < s.fileRange.offset+s.fileRange.length && p+16>s.fileRange.offset).map(s=>s.name).join(', ') || '';
    rows.push(`<div class="hexrow"><span class="mono">${fmt(p)}</span><span>${cells}</span><span class="muted">${esc([...part].map(b=>b>=32&&b<127?String.fromCharCode(b):'·').join(''))}</span></div><div class="hexsections">${esc(sections)}</div>`);
  }
  return card(`RAW BYTES · FILE OFFSET ${fmt(hexOffset)}`, `<div class="cardbody"><div class="toolbar"><input id="jumpHex" aria-label="Hexadecimal file offset" value="${fmt(hexOffset)}">${button('hexJump',0,'Jump to file offset')}${button('hexPage',-256,'← Previous')}${button('hexPage',256,'Next →')}</div><div class="hex">${rows.join('') || '<p>No file bytes at this offset.</p>'}</div></div>`);
}
function graph(blocks) {
  const visible = blocks.slice(page*PAGE_SIZE, page*PAGE_SIZE+120);
  const pos = new Map(visible.map((b,i)=>[b.id,{x:30+(i%4)*220,y:30+Math.floor(i/4)*100}]));
  const edges = (report.analysis?.cfg || []).filter(e=>pos.has(e.from)&&pos.has(e.to));
  return card('CONTROL-FLOW GRAPH', `<div class="cardbody"><p>Click a block; drag to pan, scroll to zoom. Shows up to 120 nodes from the current table page. Edges outside this view remain in the successor/predecessor lists.</p><div class="toolbar">${button('graphReset',0,'Reset view')}</div><svg id="cfg" role="img" aria-label="Interactive control-flow graph" viewBox="0 0 930 600" data-height="600"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#63b2ff"/></marker></defs>${edges.map(e=>{const a=pos.get(e.from),b=pos.get(e.to);return `<path d="M${a.x+85},${a.y+55} C${a.x+85},${a.y+85} ${b.x+85},${b.y-25} ${b.x+85},${b.y}" fill="none" stroke="#52738e" marker-end="url(#arrow)"/>`;}).join('')}${visible.map(b=>{const p=pos.get(b.id);return `<g tabindex="0" role="button" aria-label="Block ${b.id}" data-action="block" data-id="${b.id}" transform="translate(${p.x},${p.y})"><rect width="170" height="55" rx="7" fill="${b.id===selectedBlock?'#254d70':'#182c3d'}" stroke="#63b2ff"/><text x="12" y="22" fill="#e5ebf3">Block #${b.id}</text><text x="12" y="42" fill="#9ab4ca">${fmt(b.startPc)} → ${fmt(b.endPc)}</text></g>`;}).join('')}</svg></div>`);
}
function render(view) {
  active = view; const [title,subtitle] = views[view];
  $('heading').textContent = title; $('subtitle').textContent = subtitle; $('crumb').textContent = view.toUpperCase(); $('subheading').textContent = filename || 'ELF INSPECTION WORKSPACE';
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  if (!bytes) { $('content').innerHTML = '<div class="empty"><div class="emptyicon">◈</div><h2>Load a binary to begin.</h2><p>Open a Solana ELF .so or paste hex/base64 bytes.</p><label class="primary" for="file">Choose a binary</label></div>'; return; }
  if (!report) { $('content').innerHTML = view==='hex' ? hexView() : card('INSPECTING', '<div class="cardbody">Analysis is running. The raw bytes are available in Hex Viewer.</div>'); return; }
  let html = '';
  const a = report.analysis;
  if (view==='overview') html = overview();
  if (view==='sections') {
    html = card('SECTION HEADERS',paged(report.sections,['#','Name','Type','File offset','Size','Virtual address','Flags'],s=>[s.index,button('section',s.index,s.name||'<unnamed>'),s.sectionType,mono(fmt(s.offset)),BigInt(s.size).toString(),mono(fmt(s.address)),mono(fmt(s.flags))]));
    const s = report.sections.find(s=>s.index===selectedSection); if(s) html=sectionDetail(s)+html;
  }
  if (view==='segments') html=card('PROGRAM HEADERS',paged(report.segments,['#','Type','File offset','Virtual address','File size','Memory size','Flags'],s=>[button('segment',s.index,`#${s.index}`),s.segmentType,mono(fmt(s.offset)),mono(fmt(s.virtualAddress)),BigInt(s.fileSize).toString(),BigInt(s.memorySize).toString(),fmt(s.flags)]));
  if (view==='symbols') {
    const items=filter?.kind==='section'?report.symbols.filter(s=>s.sectionIndex===filter.id):report.symbols;
    html=(filter?.kind==='section'?`<div class="toolbar">Symbols for ${esc(sectionName(filter.id))} ${button('clearFilter',0,'Show all')}</div>`:'')+card('SYMBOL TABLES',paged(items,['#','Name','Table','Value','Size','Binding / type','Section'],s=>[s.id,button('symbol',s.id,s.name||'<unnamed>'),esc(sectionName(s.tableIndex)),mono(fmt(s.value)),BigInt(s.size).toString(),`${s.binding} / ${s.symbolType}`,button('section',s.sectionIndex,sectionName(s.sectionIndex))]));
  }
  if (view==='relocations') {
    html=card('RELOCATION RECORDS',paged(report.relocations,['#','Table','Recorded offset','Type','Symbol','Addend','Target'],r=>[button('relocation',r.id,`#${r.id}`),esc(sectionName(r.tableIndex)),mono(fmt(r.offset)),esc(r.typeName),esc(report.symbols.find(s=>s.id===r.symbolId)?.name||`#${r.symbolIndex}`),esc(r.addend??'—'),r.target?esc(`${sectionName(r.target.sectionIndex)}+${fmt(r.target.sectionOffset)}`):'Unresolved']));
    const r=report.relocations.find(r=>r.id===selectedRelocation); if(r) html=relocationDetail(r)+html;
  }
  if (view==='functions') html=a?card('DISCOVERED FUNCTIONS',paged(a.functions,['Function','Entry .text offset','Blocks','Stack estimate','Reachable via CFG¹'],f=>[button('function',f.id,`#${f.id}`),mono(fmt(f.entryPc)),f.blocks.length,f.stack.localEstimate==null?'Unavailable':`${f.stack.localEstimate} B`,f.reachableByControlFlow?'Yes':'No']))+card('¹ REACHABILITY',`<div class="cardbody">${esc(a.reachabilityBasis)}</div>`):unavailable('analysis');
  if (view==='blocks') {
    if (!a) html=unavailable('analysis');
    else {
      const items=filter?.kind==='function'?a.blocks.filter(b=>b.functionIds.includes(filter.id)):a.blocks;
      html=`<div class="toolbar"><label for="graphFunction">Function scope</label><select id="graphFunction"><option value="">All blocks</option>${a.functions.map(f=>`<option value="${f.id}" ${filter?.kind==='function'&&filter.id===f.id?'selected':''}>Function #${f.id}</option>`).join('')}</select></div>`;
      html+=graph(items)+card('BASIC BLOCKS',paged(items,['Block','Start .text offset','End (exclusive)','Successors','Predecessors'],b=>[button('block',b.id,`#${b.id}`),fmt(b.startPc),fmt(b.endPc),b.successors.map(id=>button('block',id,`#${id}`)).join(' '),b.predecessors.map(id=>button('block',id,`#${id}`)).join(' ')]));
      const b=a.blocks.find(b=>b.id===selectedBlock); if(b) html=blockDetail(b)+html;
      html+=card('REACHABILITY',`<div class="cardbody">${esc(a.reachabilityBasis)}</div>`);
    }
  }
  if (view==='instructions') {
    if (filter?.kind==='function') {const f=a?.functions.find(f=>f.id===filter.id);if(f)html+=functionDetail(f);}
    if (filter?.kind==='block') {const b=a?.blocks.find(b=>b.id===filter.id);if(b)html+=blockDetail(b);}
    const ids=instructionIds(report,filter), items=ids.map(id=>report.instructions[id]);
    html+=`<div class="toolbar">${filter?button('clearFilter',0,'Show all instructions'):''}</div>`;
    html+=card('DISASSEMBLY',paged(items,['.text byte offset','Virtual address','File offset','Raw bytes','Opcode','Operands','References'],i=>[button('instruction',i.id,fmt(i.pc)),mono(fmt(i.location.virtualAddress)),mono(fmt(i.location.fileOffset)),`<span class="instruction-bytes">${esc(i.bytes)}</span>`,esc(i.opcode),esc(i.operands),i.symbolIds.map(id=>esc(report.symbols[id]?.name)).join(' ')+(i.relocationIds.map(id=>button('relocation',id,`rel #${id}`)).join(' '))]));
    if(!items.length)html+=unavailable('decode');
    const i=report.instructions.find(i=>i.id===selectedInstruction); if(i){html=instructionDetail(i)+hexView()+html;}
  }
  if (view==='hex') {
    const s=report.sections.find(s=>s.index===selectedSection); if(s)html+=sectionDetail(s);
    html+=hexView();
  }
  $('content').innerHTML=html;
  if($('graphFunction'))$('graphFunction').onchange=e=>{filter=e.target.value===''?null:{kind:'function',id:Number(e.target.value)};page=0;render('blocks');};
  if(view==='instructions' && selectedInstruction!=null) $('content').querySelector(`[data-action="instruction"][data-id="${selectedInstruction}"]`)?.closest('tr')?.classList.add('selected-row');
  wireGraph();
}
function unavailable(stage) {
  const s=report.stages.find(s=>s.name===stage);
  return card('ANALYSIS AVAILABILITY',`<div class="cardbody">${esc(s?.message||'No results for this selection. See Overview for stage details.')}</div>`);
}
function jumpHex(offset,ranges=[]) {
  hexOffset=Math.max(0,Math.min(bytes.length,Math.floor(offset/16)*16)); highlights=ranges; render('hex');
}
function selectInstruction(id) {
  const i=report.instructions[id]; if(!i)return;
  if(!instructionIds(report,filter).includes(id))filter=null;
  selectedInstruction=id;page=pageForId(instructionIds(report,filter),id);
  hexOffset=Math.floor((i.location.fileOffset??0)/16)*16;
  highlights=i.location.fileOffset==null?[]:[{offset:i.location.fileOffset,length:i.length}];
  render('instructions');
}
$('content').addEventListener('click',event=>{
  const el=event.target.closest('[data-action]');if(!el)return;
  const id=Number(el.dataset.id),action=el.dataset.action;
  if(action==='page'){page=id;render(active);}
  if(action==='clearFilter'){filter=null;page=0;render(active);}
  if(action==='section'){selectedSection=id;page=pageForId(report.sections.map(s=>s.index),id);render('sections');}
  if(action==='sectionSymbols'){filter={kind:'section',id};page=0;render('symbols');}
  if(action==='sectionBytes'){const s=report.sections.find(s=>s.index===id);if(s?.fileRange)jumpHex(s.fileRange.offset);}
  if(action==='segment'){const s=report.segments.find(s=>s.index===id);if(s?.fileRange)jumpHex(s.fileRange.offset);else notice('This segment has no valid file-backed range.');}
  if(action==='symbol'){const s=report.symbols.find(s=>s.id===id);if(s?.location?.fileOffset!=null)jumpHex(s.location.fileOffset,[{offset:s.location.fileOffset,length:1}]);else notice('This symbol has no resolved file-backed definition.');}
  if(action==='relocation'){selectedRelocation=id;page=pageForId(report.relocations.map(r=>r.id),id);render('relocations');}
  if(action==='recordBytes'){const r=report.relocations[id];jumpHex(r.recordRange.offset,[r.recordRange]);}
  if(action==='relocationBytes'){const r=report.relocations[id];if(r.target?.fileOffset!=null)jumpHex(r.target.fileOffset,r.highlightRanges);}
  if(action==='function'){filter={kind:'function',id};selectedInstruction=null;page=0;render('instructions');}
  if(action==='block'){selectedBlock=id;const b=report.analysis?.blocks.find(b=>b.id===id);if(filter?.kind==='function'&&!b?.functionIds.includes(filter.id))filter=null;page=0;render('blocks');}
  if(action==='blockInstructions'){filter={kind:'block',id};selectedInstruction=null;page=0;render('instructions');}
  if(action==='instruction')selectInstruction(id);
  if(action==='instructionBytes'){const i=report.instructions[id];if(i.location.fileOffset!=null)jumpHex(i.location.fileOffset,[{offset:i.location.fileOffset,length:i.length}]);}
  if(action==='hexPage')jumpHex(hexOffset+id,highlights);
  if(action==='hexJump'){const value=$('jumpHex').value.trim();if(/^(0x)?[0-9a-f]+$/i.test(value)){const n=BigInt(value.startsWith('0x')?value:'0x'+value);if(n<=BigInt(bytes.length))jumpHex(Number(n),highlights);else notice('File offset is outside the uploaded bytes.');}else notice('Enter a hexadecimal file offset.');}
  if(action==='graphReset'){const svg=$('cfg');svg.setAttribute('viewBox',`0 0 930 ${svg.dataset.height}`);}
});
$('content').addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target.matches('g[data-action]')){e.preventDefault();e.target.dispatchEvent(new MouseEvent('click',{bubbles:true}));}});
function wireGraph() {
  const svg=$('cfg');if(!svg)return;
  svg.addEventListener('wheel',e=>{e.preventDefault();const b=svg.viewBox.baseVal,f=e.deltaY>0?1.15:0.87;if(b.width*f<100||b.width*f>20000)return;svg.setAttribute('viewBox',`${b.x} ${b.y} ${b.width*f} ${b.height*f}`);},{passive:false});
  let drag=null;
  svg.onpointerdown=e=>{if(e.target.closest('[data-action]'))return;drag={x:e.clientX,y:e.clientY,bx:svg.viewBox.baseVal.x,by:svg.viewBox.baseVal.y};svg.setPointerCapture(e.pointerId);};
  svg.onpointermove=e=>{if(!drag)return;const b=svg.viewBox.baseVal,rect=svg.getBoundingClientRect();svg.setAttribute('viewBox',`${drag.bx-(e.clientX-drag.x)*b.width/rect.width} ${drag.by-(e.clientY-drag.y)*b.height/rect.height} ${b.width} ${b.height}`);};
  svg.onpointerup=()=>{drag=null;};svg.onpointercancel=()=>{drag=null;};
}
render('overview');
