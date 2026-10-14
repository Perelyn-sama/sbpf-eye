/** Wire schema v1. Rust bridge/src/models.rs is authoritative. */
export type Word = string; // Hexadecimal u64; use BigInt, never Number for addresses.
export type Engine = 'blueshift' | 'objectFallback' | 'sbpfEye' | 'bridge' | 'browserFallback';
export interface ByteRange { offset: number; length: number }
export interface Location { sectionIndex: number; sectionOffset: Word; fileOffset: number | null; virtualAddress: Word | null }
export interface Header { engine: Engine; class: number; endian: string; osAbi: number; elfType: number; machine: number; version: number; entry: Word; programOffset: Word; sectionOffset: Word; flags: number; headerSize: number; programEntrySize: number; programCount: number; sectionEntrySize: number; sectionCount: number; sectionNamesIndex: number }
export interface Section { index: number; name: string; engine: Engine; sectionType: number; flags: Word; address: Word; offset: Word; size: Word; link: number; info: number; alignment: Word; entrySize: Word; fileRange: ByteRange | null }
export interface Segment { index: number; engine: Engine; segmentType: number; flags: number; offset: Word; virtualAddress: Word; physicalAddress: Word; fileSize: Word; memorySize: Word; alignment: Word; fileRange: ByteRange | null }
export interface Symbol { id: number; index: number; tableIndex: number; engine: Engine; name: string; value: Word; size: Word; binding: number; symbolType: number; visibility: number; sectionIndex: number; location: Location | null }
export interface Relocation { id: number; index: number; tableIndex: number; engine: Engine; offset: Word; relocationType: number; typeName: string; symbolIndex: number; symbolId: number | null; addend: string | null; recordRange: ByteRange; target: Location | null; instructionId: number | null; highlightRanges: ByteRange[]; mappingNote: string }
export interface Instruction { id: number; engine: Engine; pc: number; length: number; location: Location; bytes: string; opcode: string; operands: string; text: string; encoding: { opcodeByte: number; registerByte: number; offset: number; immediate: number }; blockId: number | null; functionIds: number[]; symbolIds: number[]; relocationIds: number[] }
export interface Block { id: number; startPc: number; endPc: number; instructionIds: number[]; successors: number[]; predecessors: number[]; terminator: string; functionIds: number[] }
export interface Function { id: number; entryPc: number; entryBlock: number; blocks: number[]; instructionRanges: ByteRange[]; reachableByControlFlow: boolean; callees: number[]; stack: { model: string; localEstimate: number | null; rawNegativeR10Offset: number } }
export interface Edge { from: number; to: number }
export interface EyeAnalysis { engine: Engine; instructionCount: number; functions: Function[]; blocks: Block[]; cfg: Edge[]; callGraph: Edge[]; reachabilityBasis: string }
export interface Stage { name: string; engine: Engine; status: string; message: string | null }
export interface Report { schemaVersion: 1; fileSize: number; header: Header | null; sections: Section[]; segments: Segment[]; symbols: Symbol[]; relocations: Relocation[]; instructions: Instruction[]; analysis: EyeAnalysis | null; sbpfVersion: number | null; stages: Stage[]; diagnostics: { stage: string; engine: Engine; severity: string; message: string }[] }
