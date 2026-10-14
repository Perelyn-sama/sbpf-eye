pub mod addresses;
mod blueshift;
mod elf;
mod errors;
mod eye;
pub mod models;
use models::*;

/// Input bytes and path must refer to the same immutable upload. The CLI enforces this.
pub fn inspect(bytes: &[u8], path: &str) -> Report {
    inspect_with_checkpoint(bytes, path, |_| {})
}

/// Emit low-level results before running the higher-level engine.
pub fn inspect_with_checkpoint(
    bytes: &[u8],
    path: &str,
    checkpoint: impl FnOnce(&Report),
) -> Report {
    let mut report = Report {
        schema_version: 1,
        file_size: bytes.len(),
        ..Report::default()
    };
    match elf::inspect(bytes, &mut report) {
        Ok(()) => {
            report.stage("structure.header", Engine::ObjectFallback, "ok", None);
            blueshift::inspect(bytes, &mut report);
        }
        Err(e) => report.stage("structure.header", Engine::ObjectFallback, "error", Some(e)),
    }
    blueshift::decode(bytes, &mut report);
    references(&mut report);
    report.stage("analysis", Engine::SbpfEye, "pending", None);
    checkpoint(&report);
    report.stages.pop();
    eye::analyze(path, &mut report);
    report.stage("loaderValidation", Engine::Bridge, "notImplemented", None);
    report.stage(
        "relocationApplication",
        Engine::Bridge,
        "notImplemented",
        None,
    );
    report
}
fn references(report: &mut Report) {
    let mut by_location = std::collections::BTreeMap::new();
    for i in &report.instructions {
        by_location.insert((i.location.section_index, i.pc as u64), i.id);
    }
    for s in &report.symbols {
        if let Some(l) = &s.location
            && let Some(id) = by_location.get(&(l.section_index, l.section_offset.0))
        {
            report.instructions[*id].symbol_ids.push(s.id);
        }
    }
    for r in &mut report.relocations {
        let Some(target) = &r.target else {
            continue;
        };
        let Some(section) = report
            .sections
            .iter()
            .find(|s| s.index == target.section_index)
        else {
            continue;
        };
        let relative = target.section_offset.0;
        let id = by_location
            .range(..=(target.section_index, relative))
            .next_back()
            .filter(|((section, pc), id)| {
                *section == target.section_index
                    && relative < *pc + report.instructions[**id].length as u64
            })
            .map(|(_, id)| *id);
        r.instruction_id = id;
        if let Some(id) = id {
            report.instructions[id].relocation_ids.push(r.id);
        }
        let Some(offset) = target.file_offset else {
            r.mapping_note = "Target is not file-backed (e.g. NOBITS)".into();
            continue;
        };
        let ix = id.map(|id| &report.instructions[id]);
        // Relocation field widths, not loader patching. Unknown kinds have a location only.
        let spans: Vec<(usize, usize)> = match r.relocation_type {
            1 | 8 if ix.is_some_and(|i| i.pc as u64 == relative && i.length == 16) => {
                vec![(4, 4), (12, 4)]
            }
            10 if ix.is_some_and(|i| i.pc as u64 == relative && i.encoding.opcode_byte == 0x85) => {
                vec![(4, 4)]
            }
            2 => vec![(0, 8)],
            3 | 4 => vec![(0, 4)],
            8 if id.is_none() => vec![(0, 8)],
            _ => vec![],
        };
        if let Some(range) = section.file_range {
            for (delta, length) in spans {
                if let Some(start) = offset.checked_add(delta)
                    && start
                        .checked_add(length)
                        .is_some_and(|end| end <= range.offset + range.length)
                {
                    r.highlight_ranges.push(ByteRange {
                        offset: start,
                        length,
                    });
                }
            }
        }
    }
}
