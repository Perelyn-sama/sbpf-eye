use sbpf_common::inst_param::Number;
use sbpf_common::{instruction::Instruction, opcode::Opcode};
use sbpf_disassembler::elf_header::E_MACHINE_SBPF;
use sbpf_disassembler::program::Program;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::{fs::File, io::Read};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub struct BinaryInfo {
    size: usize,
    ix_count: usize,
    text_section_size: usize,
}

impl BinaryInfo {
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn ix_count(&self) -> usize {
        self.ix_count
    }

    pub fn text_section_size(&self) -> usize {
        self.text_section_size
    }
}

#[derive(Debug)]
pub struct ProgramAnalysis {
    binary_info: BinaryInfo,
    instructions: Vec<InstructionMetadata>,
    blocks: Vec<BasicBlock>,
    functions: Vec<Function>,
}

impl ProgramAnalysis {
    pub fn binary_info(&self) -> BinaryInfo {
        self.binary_info
    }

    pub fn instructions(&self) -> &[InstructionMetadata] {
        &self.instructions
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }
}

#[derive(Debug)]
pub struct InstructionMetadata {
    pc: usize,
    len: usize,
    ix: Instruction,
}

impl InstructionMetadata {
    pub fn pc(&self) -> usize {
        self.pc
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn instruction(&self) -> &Instruction {
        &self.ix
    }
}

#[derive(Debug)]
pub struct BasicBlock {
    id: usize,
    start_pc: usize,
    end_pc_exclusive: usize,
    terminator: Terminator,
    successors: Vec<usize>,
    predecessors: BTreeSet<usize>,
}

impl BasicBlock {
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn start_pc(&self) -> usize {
        self.start_pc
    }

    pub fn end_pc_exclusive(&self) -> usize {
        self.end_pc_exclusive
    }

    pub fn terminator(&self) -> &Terminator {
        &self.terminator
    }

    pub fn successors(&self) -> &[usize] {
        &self.successors
    }

    pub fn predecessors(&self) -> &BTreeSet<usize> {
        &self.predecessors
    }
}

#[derive(Debug)]
pub enum Terminator {
    Exit,
    Jump { target: usize },
    Branch { target: usize, fallthrough: usize },
    Fallthrough { next: usize },
    Unreachable,
}

impl Terminator {
    fn successor_pcs(&self) -> Vec<usize> {
        match self {
            Terminator::Exit | Terminator::Unreachable => vec![],

            Terminator::Jump { target } => vec![*target],

            Terminator::Branch {
                target,
                fallthrough,
            } => {
                if target == fallthrough {
                    vec![*target]
                } else {
                    vec![*target, *fallthrough]
                }
            }

            Terminator::Fallthrough { next } => vec![*next],
        }
    }
}

#[derive(Debug)]
pub struct Function {
    id: usize,
    entry_pc: usize,
    entry_block: usize,
    blocks: Vec<usize>,
    // NOTE: does not include calls
    reachable_from_program_entry: bool,
    callees: BTreeSet<usize>,
    local_stack_usage: usize,
}

impl Function {
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn entry_pc(&self) -> usize {
        self.entry_pc
    }

    pub fn entry_block(&self) -> usize {
        self.entry_block
    }

    pub fn blocks(&self) -> &[usize] {
        &self.blocks
    }

    pub fn reachable_from_program_entry(&self) -> bool {
        self.reachable_from_program_entry
    }

    pub fn callees(&self) -> &BTreeSet<usize> {
        &self.callees
    }

    pub fn local_stack_usage(&self) -> usize {
        self.local_stack_usage
    }
}

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Disassembler(#[from] sbpf_disassembler::errors::DisassemblerError),

    #[error(transparent)]
    Sbpf(#[from] sbpf_common::errors::SBPFError),

    #[error("Instruction metadata does not exist")]
    InvalidIxMeta,

    #[error("Program count does not exist")]
    InvalidPc { pc: usize },

    #[error("Basic block does not exist")]
    InvalidBB,

    #[error("No text section found in program")]
    InvalidTextSection,
}

pub fn get_binary_info(path: &str) -> Result<BinaryInfo, AnalyzerError> {
    Ok(analyze_program(path)?.binary_info)
}

fn extract_program_from_file(path: &str) -> Result<(Program, usize), AnalyzerError> {
    let mut file = File::open(path)?;
    let mut b = vec![];
    file.read_to_end(&mut b)?;
    Ok((Program::from_bytes(&b)?, b.len()))
}

pub fn analyze_program(path: &str) -> Result<ProgramAnalysis, AnalyzerError> {
    let (program, program_size) = extract_program_from_file(path)?;

    let text_section = &program
        .section_header_entries
        .iter()
        .find(|sect| sect.label == ".text\0")
        .ok_or(AnalyzerError::InvalidTextSection)?
        .data;

    let text_section_size = text_section.len();

    let is_sbpf_v2 =
        program.elf_header.e_flags == 0x02 && program.elf_header.e_machine == E_MACHINE_SBPF;

    let ixs_meta = extract_instructions(text_section, is_sbpf_v2)?;
    let func_entries = extract_function_entries(&ixs_meta)?;
    let bbs = extract_basic_blocks(&ixs_meta, &func_entries)?;
    let funcs = extract_functions(&bbs, &func_entries, &ixs_meta)?;

    let ix_count = ixs_meta.len();

    Ok(ProgramAnalysis {
        binary_info: BinaryInfo {
            size: program_size,
            ix_count,
            text_section_size,
        },
        instructions: ixs_meta,
        blocks: bbs,
        functions: funcs,
    })
}

fn is_stack_access(ins: &Instruction) -> bool {
    let is_mem = matches!(
        ins.opcode,
        Opcode::Stb
            | Opcode::Sth
            | Opcode::Stw
            | Opcode::Stdw
            | Opcode::Stxb
            | Opcode::Stxh
            | Opcode::Stxw
            | Opcode::Stxdw
            | Opcode::Ldxb
            | Opcode::Ldxh
            | Opcode::Ldxw
            | Opcode::Ldxdw
    );

    let is_r10 = ins.dst.as_ref().map(|r| r.n == 10).unwrap_or(false)
        || ins.src.as_ref().map(|r| r.n == 10).unwrap_or(false);

    is_mem && is_r10
}

fn extract_instructions(
    text_section: &[u8],
    is_sbpf_v2: bool,
) -> Result<Vec<InstructionMetadata>, AnalyzerError> {
    let mut pc = 0;
    let mut ixs: Vec<InstructionMetadata> = Vec::new();

    while pc < text_section.len() {
        let remaining = text_section.len() - pc;

        let window_len = if remaining >= 16 {
            16
        } else if remaining >= 8 {
            8
        } else {
            break;
        };

        let window = &text_section[pc..pc + window_len];

        let ix = if is_sbpf_v2 {
            Instruction::from_bytes_sbpf_v2(window)?
        } else {
            Instruction::from_bytes(window)?
        };

        let ix_span_len = ix.span.len();

        let ix_metadata = InstructionMetadata {
            pc: pc,
            len: ix_span_len,
            ix: ix,
        };

        pc += ix_span_len;

        ixs.push(ix_metadata);
    }

    Ok(ixs)
}

fn extract_basic_blocks(
    ixs_meta: &[InstructionMetadata],
    func_entrypoints: &BTreeSet<usize>,
) -> Result<Vec<BasicBlock>, AnalyzerError> {
    let last_ix = ixs_meta.last().ok_or(AnalyzerError::InvalidIxMeta)?;
    let text_end_pc = last_ix.pc + last_ix.len;

    let ix_by_pc = ixs_meta
        .iter()
        .map(|meta| (meta.pc, meta))
        .collect::<BTreeMap<_, _>>();

    let mut leaders_pcs = BTreeSet::<usize>::new();
    leaders_pcs.insert(0);
    for pc in func_entrypoints {
        leaders_pcs.insert(*pc);
    }

    let mut bbs: Vec<BasicBlock> = Vec::new();
    for meta in ixs_meta {
        if meta.ix.is_jump() {
            let current_slot = meta.pc as isize / 8;
            let off = &meta
                .ix
                .off
                .as_ref()
                .ok_or(AnalyzerError::InvalidIxMeta)?
                .as_ref()
                .right()
                .ok_or(AnalyzerError::InvalidIxMeta)?;
            let target_slot = current_slot + 1 + **off as isize;

            if target_slot >= 0 {
                let target_pc = (target_slot * 8) as usize;
                if ix_by_pc.contains_key(&target_pc) {
                    leaders_pcs.insert(target_pc);
                }
            }

            let ix_after_jump_pc = meta.pc + meta.len;
            if ix_by_pc.contains_key(&ix_after_jump_pc) {
                leaders_pcs.insert(ix_after_jump_pc);
            }
        }
    }

    // TODO: can I reuse this?
    let jump_target_pc = |ix_meta: &InstructionMetadata| -> Option<usize> {
        let current_slot = ix_meta.pc as isize / 8;
        let off = *&ix_meta.ix.off.as_ref()?.as_ref().right()?;
        let target_slot = current_slot + 1 + *off as isize;

        if target_slot < 0 {
            return None;
        }

        let target_pc = target_slot as usize * 8;

        ix_by_pc.contains_key(&target_pc).then_some(target_pc)
    };

    let leaders: Vec<usize> = leaders_pcs.into_iter().collect();
    let bb_by_pc = leaders
        .iter()
        .copied()
        .enumerate()
        .map(|(id, pc)| (pc, id))
        .collect::<BTreeMap<_, _>>();

    for i in 0..leaders.len() {
        let start = leaders[i];

        let end = leaders.get(i + 1).copied().unwrap_or(text_end_pc);

        let last = ixs_meta
            .iter()
            .take_while(|meta| meta.pc < end)
            .last()
            .ok_or(AnalyzerError::InvalidIxMeta)?;

        let terminator = match last.ix.opcode {
            Opcode::Exit => Terminator::Exit,
            Opcode::Ja => {
                let target =
                    jump_target_pc(last).ok_or(AnalyzerError::InvalidPc { pc: last.pc })?;
                Terminator::Jump { target }
            }

            _ if last.ix.is_jump() => {
                let target =
                    jump_target_pc(last).ok_or(AnalyzerError::InvalidPc { pc: last.pc })?;
                let fallthrough = last.pc + last.len;

                if !ix_by_pc.contains_key(&fallthrough) {
                    return Err(AnalyzerError::InvalidPc { pc: last.pc });
                }

                Terminator::Branch {
                    target,
                    fallthrough,
                }
            }
            _ => {
                let next = last.pc + last.len;
                if ix_by_pc.contains_key(&next) {
                    Terminator::Fallthrough { next }
                } else if next == text_end_pc {
                    Terminator::Unreachable
                } else {
                    return Err(AnalyzerError::InvalidPc { pc: last.pc });
                }
            }
        };

        let successors = terminator
            .successor_pcs()
            .into_iter()
            .filter_map(|pc| bb_by_pc.get(&pc).copied())
            .collect::<Vec<_>>();

        bbs.push(BasicBlock {
            id: i,
            start_pc: start,
            end_pc_exclusive: end,
            terminator: terminator,
            successors,
            predecessors: BTreeSet::new(),
        })
    }

    for i in 0..bbs.len() {
        let mut predecessors = BTreeSet::new();

        for (id, bb) in bbs.iter().enumerate() {
            for successor in &bb.successors {
                if *successor == i {
                    predecessors.insert(id);
                }
            }
        }

        bbs[i].predecessors = predecessors;
    }

    Ok(bbs)
}

fn reach_bb(
    bbs: &[BasicBlock],
    entry_id: usize,
    func_entries_bbs: Option<&BTreeSet<usize>>,
) -> Vec<usize> {
    let mut reached = Vec::new();
    let mut visited = BTreeSet::new();
    let mut to_visit = vec![entry_id];

    while let Some(id) = to_visit.pop() {
        if visited.contains(&id) {
            continue;
        }

        visited.insert(id);
        reached.push(id);

        for successor in &bbs[id].successors {
            if !visited.contains(successor)
                && !func_entries_bbs
                    .as_ref()
                    .is_some_and(|entries| entries.contains(successor))
            {
                to_visit.push(*successor);
            }
        }
    }

    reached
}

fn extract_function_entries(
    ixs_meta: &[InstructionMetadata],
) -> Result<BTreeSet<usize>, AnalyzerError> {
    let last_ix = ixs_meta.last().ok_or(AnalyzerError::InvalidIxMeta)?;
    let text_end_pc = last_ix.pc + last_ix.len;

    let calls = ixs_meta
        .iter()
        .filter(|meta| meta.ix.opcode == Opcode::Call && !meta.ix.is_syscall())
        .collect::<Vec<&InstructionMetadata>>();

    let instruction_starts = ixs_meta.iter().map(|meta| meta.pc).collect::<BTreeSet<_>>();

    // TODO: use count for call graph later
    let mut incoming_call_counts = BTreeMap::<usize, usize>::new();

    for call in &calls {
        let imm = match call
            .ix
            .imm
            .as_ref()
            .ok_or(AnalyzerError::InvalidIxMeta)?
            .as_ref()
            .right()
            .ok_or(AnalyzerError::InvalidIxMeta)?
        {
            Number::Int(n) => *n,
            _ => return Err(AnalyzerError::InvalidIxMeta),
        };

        let target_pc = call.pc as i64 + 8 + imm * 8;

        if target_pc >= 0
            && target_pc < text_end_pc as i64
            && instruction_starts.contains(&(target_pc as usize))
            && imm != -1
        {
            *incoming_call_counts.entry(target_pc as usize).or_default() += 1;
        }
    }

    let mut func_entrypoints = BTreeSet::<usize>::new();
    func_entrypoints.insert(0);
    func_entrypoints.extend(incoming_call_counts.keys().copied());

    Ok(func_entrypoints)
}

fn extract_functions(
    bbs: &[BasicBlock],
    func_entries: &BTreeSet<usize>,
    ixs_meta: &[InstructionMetadata],
) -> Result<Vec<Function>, AnalyzerError> {
    let mut funcs = Vec::new();

    let bb_by_pc = bbs
        .iter()
        .map(|bbs| (bbs.start_pc, bbs))
        .collect::<BTreeMap<_, _>>();

    let mut leader_bbs = Vec::new();

    let func_entry_bbs = func_entries
        .iter()
        .filter_map(|pc| bb_by_pc.get(pc).map(|bb| bb.id))
        .collect::<BTreeSet<_>>();

    for pc in func_entries {
        let bb = bb_by_pc.get(pc).ok_or(AnalyzerError::InvalidBB)?;
        leader_bbs.push(bb);
    }

    let live_blocks = reach_bb(bbs, 0, None)
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    for (id, leader_bb) in leader_bbs.iter().enumerate() {
        let blocks = reach_bb(&bbs, leader_bb.id, Some(&func_entry_bbs));

        let mut local_stack_usage = 0;

        for block_id in &blocks {
            let bb = &bbs[*block_id];
            debug_assert_eq!(bb.id, *block_id);

            let start = bb.start_pc();
            let end = bb.end_pc_exclusive();

            let ixs: Vec<&Instruction> = ixs_meta
                .iter()
                .filter(|ix_meta| ix_meta.pc >= start && ix_meta.pc < end)
                .map(|ix_meta| &ix_meta.ix)
                .collect();

            let bb_stack_usage = ixs
                .iter()
                .filter(|ix| is_stack_access(ix))
                .filter_map(|ix| ix.off.as_ref())
                .filter_map(|off| off.as_ref().right())
                .filter(|off| **off < 0)
                .map(|off| (-off) as usize)
                .max()
                .unwrap_or(0);

            local_stack_usage = local_stack_usage.max(bb_stack_usage);
        }

        funcs.push(Function {
            id,
            entry_pc: leader_bb.start_pc,
            entry_block: leader_bb.id,
            blocks,
            reachable_from_program_entry: live_blocks.contains(&leader_bb.id),
            callees: BTreeSet::new(),
            local_stack_usage,
        });
    }

    let func_id_by_pc = funcs
        .iter()
        .map(|func| (func.entry_pc as usize, func.id))
        .collect::<BTreeMap<usize, usize>>();

    for i in 0..funcs.len() {
        let callees = extract_function_callees(&funcs[i].blocks, bbs, func_entries, ixs_meta)?
            .iter()
            .filter_map(|pc| *&func_id_by_pc.get(pc).map(|bb| *bb))
            .collect();

        funcs[i].callees = callees;
    }

    Ok(funcs)
}

fn extract_function_callees(
    blocks: &[usize],
    bbs: &[BasicBlock],
    func_entries: &BTreeSet<usize>,
    ixs_meta: &[InstructionMetadata],
) -> Result<BTreeSet<usize>, AnalyzerError> {
    let bb_by_block_id = bbs.iter().map(|bb| (bb.id, bb)).collect::<BTreeMap<_, _>>();

    let bbs = blocks
        .iter()
        .filter_map(|bb_id| *&bb_by_block_id.get(bb_id).map(|bb| *bb))
        .collect::<Vec<&BasicBlock>>();

    let ixs_by_bb_id: BTreeMap<usize, Vec<&InstructionMetadata>> = bbs
        .iter()
        .map(|bb| {
            let ixs_in_bb = ixs_meta
                .iter()
                .filter(|ix| ix.pc >= bb.start_pc && ix.pc < bb.end_pc_exclusive)
                .collect::<Vec<_>>();
            let id = bb.id;
            (id, ixs_in_bb)
        })
        .collect();

    let ixs_in_func = ixs_by_bb_id
        .values()
        .cloned()
        .flatten()
        .collect::<Vec<&InstructionMetadata>>();

    let calls = ixs_in_func
        .iter()
        .copied()
        .filter(|meta| meta.ix.opcode == Opcode::Call && !meta.ix.is_syscall())
        .collect::<Vec<&InstructionMetadata>>();

    let mut res = BTreeSet::new();

    for call in &calls {
        let imm = match call
            .ix
            .imm
            .as_ref()
            .ok_or(AnalyzerError::InvalidIxMeta)?
            .as_ref()
            .right()
            .ok_or(AnalyzerError::InvalidIxMeta)?
        {
            Number::Int(n) => *n,
            _ => return Err(AnalyzerError::InvalidIxMeta),
        };

        if imm != -1 {
            let target_pc = (call.pc as i64 + 8 + imm * 8) as usize;

            if func_entries.contains(&target_pc) {
                res.insert(target_pc);
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ix(pc: usize, opcode: Opcode, dst: u8, src: u8, off: i16, imm: i32) -> InstructionMetadata {
        let mut bytes = vec![opcode.into(), src << 4 | dst];
        bytes.extend_from_slice(&off.to_le_bytes());
        bytes.extend_from_slice(&imm.to_le_bytes());

        let ix = Instruction::from_bytes(&bytes).unwrap();

        InstructionMetadata {
            pc,
            len: ix.span.len(),
            ix,
        }
    }

    fn extract_test_functions(ixs_meta: &[InstructionMetadata]) -> Vec<Function> {
        let entries = extract_function_entries(ixs_meta).unwrap();
        let bbs = extract_basic_blocks(ixs_meta, &entries).unwrap();
        extract_functions(&bbs, &entries, ixs_meta).unwrap()
    }

    #[test]
    fn local_stack_usage_is_max_negative_r10_offset_per_function() {
        let ixs_meta = vec![
            ix(0, Opcode::Stw, 10, 0, -8, 0),
            ix(8, Opcode::Ldxw, 1, 10, -32, 0),
            ix(16, Opcode::Stw, 10, 0, 128, 0),
            ix(24, Opcode::Call, 0, 0, 0, 1),
            ix(32, Opcode::Exit, 0, 0, 0, 0),
            ix(40, Opcode::Stxdw, 10, 1, -64, 0),
            ix(48, Opcode::Exit, 0, 0, 0, 0),
        ];

        let funcs = extract_test_functions(&ixs_meta);

        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].entry_pc(), 0);
        assert_eq!(funcs[0].local_stack_usage(), 32);
        assert_eq!(funcs[1].entry_pc(), 40);
        assert_eq!(funcs[1].local_stack_usage(), 64);
    }

    #[test]
    fn local_stack_usage_is_zero_without_negative_r10_memory_accesses() {
        let ixs_meta = vec![
            ix(0, Opcode::Stw, 1, 0, -128, 0),
            ix(8, Opcode::Stw, 10, 0, 8, 0),
            ix(16, Opcode::Exit, 0, 0, 0, 0),
        ];

        let funcs = extract_test_functions(&ixs_meta);

        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].local_stack_usage(), 0);
    }
}
