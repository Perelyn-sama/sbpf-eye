export const PAGE_SIZE = 200;
export function instructionIds(report, selection) {
  if (selection?.kind === 'block') return report.analysis?.blocks.find(b => b.id === selection.id)?.instructionIds || [];
  if (selection?.kind === 'function') {
    const f = report.analysis?.functions.find(f => f.id === selection.id);
    return [...new Set((f?.blocks || []).flatMap(id => report.analysis.blocks.find(b => b.id === id)?.instructionIds || []))].sort((a, b) => a - b);
  }
  return report.instructions.map(i => i.id);
}
export function pageForId(ids, id) { return Math.max(0, Math.floor(ids.indexOf(id) / PAGE_SIZE)); }
export function inRanges(offset, ranges) { return ranges.some(r => offset >= r.offset && offset < r.offset + r.length); }
export function hexWord(value) { return value == null ? '—' : '0x' + BigInt(value).toString(16).padStart(4, '0'); }
