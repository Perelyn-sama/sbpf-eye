use sbpf_common::inst_param::Number;
use sbpf_common::{instruction::Instruction, opcode::Opcode};
use sbpf_disassembler::elf_header::E_MACHINE_SBPF;
use sbpf_disassembler::program::Program;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::{fs::File, io::Read};

fn main() {
    // dbg!(get_binary_info("samples/hello_solana_native_program.so"));
    dbg!(get_binary_info("samples/hello_solana_pinocchio_program.so"));
    // dbg!(get_binary_info("samples/hello_solana_asm_program.so"));
}

pub fn is_stack_access(ins: &Instruction) -> bool {
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

#[derive(Debug, Clone, Copy)]
pub struct BinaryInfo {
    pub size: usize,
    pub ix_count: usize,
    pub text_section_size: usize,
    pub max_stack_offset: usize,
}

pub fn get_binary_info(path: &str) -> BinaryInfo {
    let mut file = File::open(path).unwrap();
    let mut b = vec![];
    file.read_to_end(&mut b).unwrap();
    let program = Program::from_bytes(&b).unwrap();
    let text_section = program
        .section_header_entries
        .iter()
        .filter(|sect| sect.label == ".text\0")
        .collect::<Vec<_>>()[0]
        .data
        .clone();

    let size = b.len();
    let text_section_size = text_section.len();

    let is_sbpf_v2 =
        program.elf_header.e_flags == 0x02 && program.elf_header.e_machine == E_MACHINE_SBPF;

    let ixs_meta = extract_instructions(text_section, is_sbpf_v2);
    let func_entries = extract_function_entries(&ixs_meta);
    let bbs = extract_basic_blocks(&ixs_meta, &func_entries);
    let _functions = extract_functions(&bbs, &func_entries);

    let ix_count = ixs_meta.len();

    let ixs = program.to_ixs().unwrap().0;
    let max_stack_offset = ixs
        .iter()
        .filter(|ix| is_stack_access(ix))
        .filter_map(|ix| ix.off.clone())
        .filter_map(|off| off.right())
        .filter(|off| *off < 0)
        .map(|off| (-off) as usize)
        .max()
        .unwrap_or(0);

    BinaryInfo {
        size,
        ix_count,
        text_section_size,
        max_stack_offset,
    }
}

#[derive(Debug)]
pub struct InstructionMetadata {
    pub pc: usize,
    pub len: usize,
    pub ix: Instruction,
}

pub fn extract_instructions(text_section: Vec<u8>, is_sbpf_v2: bool) -> Vec<InstructionMetadata> {
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
            Instruction::from_bytes_sbpf_v2(window).unwrap()
        } else {
            Instruction::from_bytes(window).unwrap()
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

    ixs
}

pub fn extract_basic_blocks(
    ixs_meta: &Vec<InstructionMetadata>,
    func_entrypoints: &BTreeSet<usize>,
) -> Vec<BasicBlock> {
    let last_ix = ixs_meta.last().unwrap();
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
            let off = &meta.ix.off.as_ref().unwrap().clone().unwrap_right();
            let target_slot = current_slot + 1 + *off as isize;

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

    let jump_target_pc = |ix: &InstructionMetadata| -> Option<usize> {
        let current_slot = ix.pc as isize / 8;
        let off = *ix.ix.off.as_ref().unwrap().as_ref().right().unwrap();
        let target_slot = current_slot + 1 + off as isize;

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
            .unwrap();

        let terminator = match last.ix.opcode {
            Opcode::Exit => Terminator::Exit,
            Opcode::Ja => {
                let target = jump_target_pc(last).unwrap();
                Terminator::Jump { target }
            }

            _ if last.ix.is_jump() => {
                let target = jump_target_pc(last).unwrap();
                let fallthrough = last.pc + last.len;

                if !ix_by_pc.contains_key(&fallthrough) {
                    panic!("conditional jump has invalid fallthrough as pc {}", last.pc);
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
                    panic!(
                        "non-terminal block has invalid fallthrough at pc {}",
                        last.pc
                    );
                }
            }
        };

        let successors = terminator
            .successor_pcs()
            .into_iter()
            .map(|pc| *bb_by_pc.get(&pc).unwrap())
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

    //  if i is in bb.successors insert id in predecessors
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

    bbs
}

pub fn reach_bb(
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

fn extract_function_entries(ixs_meta: &Vec<InstructionMetadata>) -> BTreeSet<usize> {
    let last_ix = ixs_meta.last().unwrap();
    let text_end_pc = last_ix.pc + last_ix.len;

    let calls = ixs_meta
        .iter()
        .filter(|meta| meta.ix.opcode == Opcode::Call && !meta.ix.is_syscall())
        .collect::<Vec<&InstructionMetadata>>();

    let instruction_starts = ixs_meta.iter().map(|meta| meta.pc).collect::<BTreeSet<_>>();

    // TODO: use count for call graph later
    let mut incoming_call_counts = BTreeMap::<usize, usize>::new();

    for call in calls {
        let imm = match call.ix.imm.as_ref().unwrap().as_ref().right().unwrap() {
            Number::Int(n) => *n,
            _ => panic!("expected call imm int"),
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

    func_entrypoints
}

fn extract_functions(bbs: &[BasicBlock], func_entries: &BTreeSet<usize>) -> Vec<Function> {
    let mut funcs = Vec::new();

    let bb_by_pc = bbs
        .iter()
        .map(|bbs| (bbs.start_pc, bbs))
        .collect::<BTreeMap<_, _>>();

    let mut leader_bbs = Vec::new();

    let func_entry_bbs = func_entries
        .iter()
        .map(|pc| bb_by_pc.get(pc).unwrap().id)
        .collect::<BTreeSet<_>>();

    for pc in func_entries {
        let bb = bb_by_pc.get(pc).unwrap();
        leader_bbs.push(bb);
    }

    let live_blocks = reach_bb(bbs, 0, None)
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    for (id, leader_bb) in leader_bbs.iter().enumerate() {
        funcs.push(Function {
            id,
            entry_pc: leader_bb.start_pc as u64,
            entry_block: leader_bb.id,
            blocks: reach_bb(&bbs, leader_bb.id, Some(&func_entry_bbs)),
            reachable_from_program_entry: live_blocks.contains(&leader_bb.id),
        });
    }

    funcs
}

#[derive(Debug)]
pub struct BasicBlock {
    pub id: usize,
    pub start_pc: usize,
    pub end_pc_exclusive: usize,
    pub terminator: Terminator,
    pub successors: Vec<usize>,
    pub predecessors: BTreeSet<usize>,
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
    pub fn successor_pcs(&self) -> Vec<usize> {
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
    pub id: usize,
    pub entry_pc: u64,
    pub entry_block: usize,
    pub blocks: Vec<usize>,
    // NOTE: does not include calls
    pub reachable_from_program_entry: bool,
}
