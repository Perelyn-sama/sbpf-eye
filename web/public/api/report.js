import { parseELF } from '../elf.js';
const word = value => '0x' + BigInt(value).toString(16);
/** @typedef {import('../types/report').Report} Report */
/** @returns {Promise<Report>} */
export async function analyze(bytes, signal) {
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: bytes, signal,
    });
    const result = await response.json();
    if (!response.ok || !result.ok || result.json?.schemaVersion !== 1) {
      throw new Error(result.error || result.stderr || 'The Rust bridge did not return a supported report');
    }
    return result.json;
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    return browserFallback(bytes, error.message);
  }
}
export function browserFallback(bytes, reason) {
  const report = {
    schemaVersion: 1, fileSize: bytes.length, header: null, sections: [], segments: [], symbols: [],
    relocations: [], instructions: [], analysis: null, sbpfVersion: null,
    stages: [{ name: 'bridge', engine: 'bridge', status: 'error', message: reason }], diagnostics: [],
  };
  // Preserve the original standalone browser inspector when the local bridge is unavailable.
  try {
    const elf = parseELF(bytes);
    report.header = { ...elf.header, elfType: elf.header.type, class: 2, endian: 'little', osAbi: bytes[7], entry: word(elf.header.entry), programOffset: word(elf.header.programOffset), sectionOffset: word(elf.header.sectionOffset), engine: 'browserFallback' };
    report.sections = elf.sections.map(s => ({ ...s, engine: 'browserFallback', sectionType: s.type, offset: word(s.offset), size: word(s.size), address: word(s.address), flags: word(s.flags), alignment: word(s.alignment), entrySize: word(s.entrySize),
      fileRange: s.type === 8 || s.type === 0 ? null : { offset: s.offset, length: s.size } }));
    report.segments = elf.segments.map(s => ({ ...s, engine: 'browserFallback', segmentType: s.type, virtualAddress: word(s.vaddr), physicalAddress: word(s.paddr), offset: word(s.offset), fileSize: word(s.fileSize), memorySize: word(s.memorySize), alignment: word(s.alignment),
      fileRange: s.offset + s.fileSize <= bytes.length ? { offset: s.offset, length: s.fileSize } : null }));
    report.symbols = elf.symbols.map((s, id) => ({ ...s, id, engine: 'browserFallback', symbolType: s.type, value: word(s.value), size: word(s.size),
      tableIndex: elf.sections.find(x => x.name === s.table)?.index, location: null }));
    report.relocations = elf.relocations.map((r, id) => ({ ...r, id, engine: 'browserFallback', relocationType: r.type, offset: word(r.offset),
      tableIndex: elf.sections.find(x => x.name === r.section)?.index, recordRange: { offset: r.entryOffset, length: r.addend == null ? 16 : 24 },
      target: null, instructionId: null, symbolId: null, highlightRanges: [], mappingNote: 'Build the Rust bridge to resolve address domains safely.' }));
    report.stages.push({ name: 'browser.structure', engine: 'browserFallback', status: 'ok', message: 'Fallback only; Rust engines unavailable' });
  } catch (error) {
    report.stages.push({ name: 'browser.structure', engine: 'browserFallback', status: 'error', message: error.message });
  }
  return report;
}
