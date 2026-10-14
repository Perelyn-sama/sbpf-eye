//! Higher-level algorithms remain in sbpf-eye. This module only normalizes their output.
use crate::{blueshift::safe_section_copy, errors::guarded, models::*};
use std::collections::BTreeMap;

pub fn analyze(path: &str, report: &mut Report) {
    if report.sbpf_version.is_none() || !safe_section_copy(report, report.file_size) {
        report.stage(
            "analysis",
            Engine::SbpfEye,
            "skipped",
            Some("Unsupported version or unsafe upstream ELF section-copy preconditions".into()),
        );
        return;
    }
    let analysis = match guarded(|| sbpf_eye::analyze_program(path)) {
        Ok(a) => a,
        Err(e) => {
            report.stage("analysis", Engine::SbpfEye, "error", Some(e));
            return;
        }
    };
    let boundaries: Vec<_> = report
        .instructions
        .iter()
        .map(|i| (i.pc, i.length))
        .collect();
    let eye_boundaries: Vec<_> = analysis
        .instructions()
        .iter()
        .map(|i| (i.pc(), i.len()))
        .collect();
    if boundaries != eye_boundaries {
        let first = boundaries
            .iter()
            .zip(&eye_boundaries)
            .position(|(a, b)| a != b)
            .unwrap_or(boundaries.len().min(eye_boundaries.len()));
        report.warn("reconciliation", Engine::Bridge, format!("Instruction boundary/count discrepancy: Blueshift={}, sbpf-eye={}; first difference at index {first}: {:?} versus {:?}. Only matching instructions are linked. A trailing partial slot is ignored by sbpf-eye but reported by the bridge.", boundaries.len(), eye_boundaries.len(), boundaries.get(first), eye_boundaries.get(first)));
    }
    let eye_by_pc: BTreeMap<_, _> = analysis
        .instructions()
        .iter()
        .map(|i| (i.pc(), i.len()))
        .collect();
    let info = analysis.binary_info();
    let fixed_stack = matches!(info.stack_model(), sbpf_eye::StackModel::FixedFrame);
    let functions: Vec<_> = analysis
        .functions()
        .iter()
        .map(|f| Function {
            id: f.id(),
            entry_pc: f.entry_pc(),
            entry_block: f.entry_block(),
            blocks: f.blocks().to_vec(),
            instruction_ranges: f
                .blocks()
                .iter()
                .filter_map(|id| analysis.blocks().get(*id))
                .map(|b| ByteRange {
                    offset: b.start_pc(),
                    length: b.end_pc_exclusive() - b.start_pc(),
                })
                .collect(),
            reachable_by_control_flow: f.reachable_from_program_entry(),
            callees: f.callees().iter().copied().collect(),
            stack: StackUsage {
                model: format!("{:?}", info.stack_model()),
                local_estimate: fixed_stack.then_some(f.local_stack_usage()),
                raw_negative_r10_offset: f.local_stack_usage(),
            },
        })
        .collect();
    let mut blocks: Vec<_> = analysis
        .blocks()
        .iter()
        .map(|b| Block {
            id: b.id(),
            start_pc: b.start_pc(),
            end_pc: b.end_pc_exclusive(),
            instruction_ids: vec![],
            successors: b.successors().to_vec(),
            predecessors: b.predecessors().iter().copied().collect(),
            terminator: format!("{:?}", b.terminator()),
            function_ids: vec![],
        })
        .collect();
    for f in &functions {
        for id in &f.blocks {
            if let Some(b) = blocks.get_mut(*id) {
                b.function_ids.push(f.id);
            }
        }
    }
    // Both instruction and block ranges are ordered. No O(instructions * blocks) scan.
    let mut block_index = 0;
    for ix in &mut report.instructions {
        while block_index < blocks.len() && blocks[block_index].end_pc <= ix.pc {
            block_index += 1;
        }
        if eye_by_pc.get(&ix.pc) != Some(&ix.length) {
            continue;
        }
        if let Some(b) = blocks.get_mut(block_index)
            && ix.pc >= b.start_pc
            && ix.pc + ix.length <= b.end_pc
        {
            b.instruction_ids.push(ix.id);
            ix.block_id = Some(b.id);
            ix.function_ids = b.function_ids.clone();
        }
    }
    let cfg = blocks
        .iter()
        .flat_map(|b| {
            b.successors.iter().map(move |to| Edge {
                from: b.id,
                to: *to,
            })
        })
        .collect();
    let call_graph = functions
        .iter()
        .flat_map(|f| {
            f.callees.iter().map(move |to| Edge {
                from: f.id,
                to: *to,
            })
        })
        .collect();
    report.analysis = Some(EyeAnalysis { engine: Engine::SbpfEye, instruction_count: analysis.instructions().len(), functions, blocks, cfg, call_graph,
        reachability_basis: "sbpf-eye control-flow reachability from .text+0; excludes call edges and does not use ELF e_entry. Unreachable is not proof of dead code.".into() });
    report.stage("analysis", Engine::SbpfEye, "ok", None);
    if !fixed_stack {
        report.warn("stack", Engine::SbpfEye, "Dynamic/unknown stack model: local stack estimate unavailable; raw negative r10 offset is retained only as a diagnostic.");
    }
    if let (Some(h), Some(text)) = (
        &report.header,
        report.sections.iter().find(|s| s.name == ".text"),
    ) && h.entry.0 != text.address.0
    {
        report.warn("analysis", Engine::SbpfEye, "ELF entry differs from .text start. sbpf-eye's discovery/reachability is rooted at .text+0; inspect the ELF entry separately.");
    }
}
