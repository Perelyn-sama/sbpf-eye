//! Stable wire models. ELF 64-bit words serialize as hex strings, never lossy JS numbers.
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex(pub u64);
impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{:x}", self.0))
    }
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Engine {
    Blueshift,
    ObjectFallback,
    SbpfEye,
    Bridge,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub name: String,
    pub engine: Engine,
    pub status: String,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub stage: String,
    pub engine: Engine,
    pub severity: String,
    pub message: String,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ByteRange {
    pub offset: usize,
    pub length: usize,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub engine: Engine,
    pub class: u8,
    pub endian: String,
    pub os_abi: u8,
    pub elf_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: Hex,
    pub program_offset: Hex,
    pub section_offset: Hex,
    pub flags: u32,
    pub header_size: u16,
    pub program_entry_size: u16,
    pub program_count: u16,
    pub section_entry_size: u16,
    pub section_count: u16,
    pub section_names_index: u16,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub index: usize,
    pub name: String,
    pub engine: Engine,
    pub section_type: u32,
    pub flags: Hex,
    pub address: Hex,
    pub offset: Hex,
    pub size: Hex,
    pub link: u32,
    pub info: u32,
    pub alignment: Hex,
    pub entry_size: Hex,
    pub file_range: Option<ByteRange>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Segment {
    pub index: usize,
    pub engine: Engine,
    pub segment_type: u32,
    pub flags: u32,
    pub offset: Hex,
    pub virtual_address: Hex,
    pub physical_address: Hex,
    pub file_size: Hex,
    pub memory_size: Hex,
    pub alignment: Hex,
    pub file_range: Option<ByteRange>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub section_index: usize,
    pub section_offset: Hex,
    pub file_offset: Option<usize>,
    pub virtual_address: Option<Hex>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Symbol {
    pub id: usize,
    pub index: usize,
    pub table_index: usize,
    pub engine: Engine,
    pub name: String,
    pub value: Hex,
    pub size: Hex,
    pub binding: u8,
    pub symbol_type: u8,
    pub visibility: u8,
    pub section_index: u16,
    pub location: Option<Location>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Relocation {
    pub id: usize,
    pub index: usize,
    pub table_index: usize,
    pub engine: Engine,
    pub offset: Hex,
    pub relocation_type: u32,
    pub type_name: String,
    pub symbol_index: u32,
    pub symbol_id: Option<usize>,
    pub addend: Option<String>,
    pub record_range: ByteRange,
    pub target: Option<Location>,
    pub instruction_id: Option<usize>,
    pub highlight_ranges: Vec<ByteRange>,
    pub mapping_note: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Encoding {
    pub opcode_byte: u8,
    pub register_byte: u8,
    pub offset: i16,
    pub immediate: i32,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Instruction {
    pub id: usize,
    pub engine: Engine,
    pub pc: usize,
    pub length: usize,
    pub location: Location,
    pub bytes: String,
    pub opcode: String,
    pub operands: String,
    pub text: String,
    pub encoding: Encoding,
    pub block_id: Option<usize>,
    pub function_ids: Vec<usize>,
    pub symbol_ids: Vec<usize>,
    pub relocation_ids: Vec<usize>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub id: usize,
    pub start_pc: usize,
    pub end_pc: usize,
    pub instruction_ids: Vec<usize>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub terminator: String,
    pub function_ids: Vec<usize>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackUsage {
    pub model: String,
    pub local_estimate: Option<usize>,
    pub raw_negative_r10_offset: usize,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    pub id: usize,
    pub entry_pc: usize,
    pub entry_block: usize,
    pub blocks: Vec<usize>,
    pub instruction_ranges: Vec<ByteRange>,
    pub reachable_by_control_flow: bool,
    pub callees: Vec<usize>,
    pub stack: StackUsage,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Edge {
    pub from: usize,
    pub to: usize,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EyeAnalysis {
    pub engine: Engine,
    pub instruction_count: usize,
    pub functions: Vec<Function>,
    pub blocks: Vec<Block>,
    pub cfg: Vec<Edge>,
    pub call_graph: Vec<Edge>,
    pub reachability_basis: String,
}
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u32,
    pub file_size: usize,
    pub header: Option<Header>,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub instructions: Vec<Instruction>,
    pub analysis: Option<EyeAnalysis>,
    pub sbpf_version: Option<u32>,
    pub stages: Vec<Stage>,
    pub diagnostics: Vec<Diagnostic>,
}
impl Report {
    pub fn stage(&mut self, name: &str, engine: Engine, status: &str, message: Option<String>) {
        self.stages.push(Stage {
            name: name.into(),
            engine,
            status: status.into(),
            message,
        });
    }
    pub fn warn(&mut self, stage: &str, engine: Engine, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            stage: stage.into(),
            engine,
            severity: "warning".into(),
            message: message.into(),
        });
    }
}
