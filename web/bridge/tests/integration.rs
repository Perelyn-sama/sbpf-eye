use sbpf_disassembler::program::Program;
use sbpf_eye_web_bridge::{addresses::*, inspect, models::*};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SEQ: AtomicU64 = AtomicU64::new(0);
fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples")
            .join(name),
    )
    .unwrap()
}
fn asm() -> Vec<u8> {
    fixture("hello_solana_asm_program.so")
}
fn run(bytes: &[u8]) -> Report {
    let path = std::env::temp_dir().join(format!(
        "eye-bridge-test-{}-{}.so",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    let report = inspect(bytes, path.to_str().unwrap());
    fs::remove_file(path).unwrap();
    report
}
fn put16(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn sh(report: &Report, index: usize) -> usize {
    let h = report.header.as_ref().unwrap();
    h.section_offset.0 as usize + index * h.section_entry_size as usize
}

#[test]
fn real_corpus_matches_blueshift_and_eye_and_links_file_bytes() {
    for name in [
        "hello_solana_asm_program.so",
        "hello_solana_native_program.so",
        "hello_solana_pinocchio_program.so",
        "account_data_pinocchio_program.so",
    ] {
        let bytes = fixture(name);
        let report = run(&bytes);
        let upstream = Program::from_bytes(&bytes).unwrap();
        assert_eq!(report.sections.len(), upstream.section_headers.len());
        for (section, raw) in report.sections.iter().zip(&upstream.section_headers) {
            assert_eq!(section.offset.0, raw.sh_offset);
            assert_eq!(section.size.0, raw.sh_size);
            assert_eq!(section.engine, Engine::Blueshift);
        }
        let (decoded, _, _) = upstream.to_ixs_raw().unwrap();
        assert_eq!(report.instructions.len(), decoded.len(), "{name}");
        let eye = report.analysis.as_ref().unwrap();
        assert!(!eye.functions.is_empty());
        assert!(!eye.blocks.is_empty());
        assert_eq!(eye.instruction_count, decoded.len());
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.stage == "reconciliation")
        );
        for (i, raw) in report.instructions.iter().zip(&decoded) {
            assert_eq!(i.length, raw.span.len());
            assert_eq!(i.engine, Engine::Blueshift);
            let offset = i.location.file_offset.unwrap();
            let expected = bytes[offset..offset + i.length]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(i.bytes, expected);
            let b = &eye.blocks[i.block_id.unwrap()];
            assert!(b.instruction_ids.contains(&i.id));
            assert!(i.pc >= b.start_pc && i.pc + i.length <= b.end_pc);
            for id in &i.function_ids {
                assert!(eye.functions[*id].blocks.contains(&b.id));
            }
        }
        for f in &eye.functions {
            for id in &f.blocks {
                assert!(eye.blocks[*id].function_ids.contains(&f.id));
            }
        }
    }
}
#[test]
fn relocations_have_targets_and_split_lddw_highlights() {
    let report = run(&asm());
    assert!(!report.relocations.is_empty());
    for r in &report.relocations {
        assert_eq!(r.engine, Engine::Blueshift);
        let target = r.target.as_ref().unwrap();
        let i = &report.instructions[r.instruction_id.unwrap()];
        assert_eq!(target.file_offset, i.location.file_offset);
        assert!(i.relocation_ids.contains(&r.id));
        if r.relocation_type == 10 {
            assert_eq!(
                r.highlight_ranges,
                vec![ByteRange {
                    offset: target.file_offset.unwrap() + 4,
                    length: 4
                }]
            );
        }
    }
    let report = run(&fixture("hello_solana_native_program.so"));
    assert!(
        report
            .relocations
            .iter()
            .any(|r| r.highlight_ranges.len() == 2)
    );
    assert!(
        report
            .relocations
            .iter()
            .any(|r| r.instruction_id.is_none())
    );
}
#[test]
fn no_relocations_is_a_successful_stage() {
    let report = run(&fixture("account_data_pinocchio_program.so"));
    assert!(report.relocations.is_empty());
    assert!(report.analysis.is_some());
    assert!(!report.instructions.is_empty());
}
#[test]
fn static_analysis_error_does_not_discard_disassembly() {
    let mut bytes = asm();
    let original = run(&bytes);
    let i = original.instructions.last().unwrap();
    let offset = i.location.file_offset.unwrap();
    bytes[offset..offset + 8].copy_from_slice(&[0x05, 0, 0xff, 0x7f, 0, 0, 0, 0]);
    let report = run(&bytes);
    assert!(report.analysis.is_none());
    assert_eq!(report.instructions.len(), original.instructions.len());
    assert_eq!(report.sections.len(), original.sections.len());
    assert!(
        report
            .stages
            .iter()
            .any(|s| s.name == "analysis" && s.status == "error")
    );
}
#[test]
fn unknown_relocation_preserves_other_stages_and_raw_record() {
    let mut bytes = asm();
    let original = run(&bytes);
    let r = &original.relocations[0];
    put32(&mut bytes, r.record_range.offset + 8, 999);
    let report = run(&bytes);
    assert_eq!(report.relocations[0].relocation_type, 999);
    assert_eq!(report.relocations[0].engine, Engine::ObjectFallback);
    assert_eq!(report.instructions.len(), original.instructions.len());
    assert!(!report.symbols.is_empty());
    assert!(report.analysis.is_none());
    assert!(
        report
            .stages
            .iter()
            .any(|s| s.name == "blueshift.relocations" && s.status == "error")
    );
}
#[test]
fn invalid_opcode_keeps_decoded_prefix_and_structure() {
    let mut bytes = asm();
    let original = run(&bytes);
    let last = original
        .instructions
        .last()
        .unwrap()
        .location
        .file_offset
        .unwrap();
    bytes[last] = 0xff;
    let report = run(&bytes);
    assert_eq!(report.instructions.len(), original.instructions.len() - 1);
    assert!(!report.sections.is_empty());
    assert!(!report.relocations.is_empty());
    assert!(
        report
            .stages
            .iter()
            .any(|s| s.name == "decode" && s.status == "partial")
    );
}
#[test]
fn malformed_headers_keep_independent_program_headers_and_hex_input_size() {
    for bytes in [vec![], vec![0x7f, 69, 76, 70], vec![0; 100]] {
        let report = run(&bytes);
        assert!(report.header.is_none());
        assert_eq!(report.file_size, bytes.len());
        assert!(report.analysis.is_none());
    }
    let mut bytes = asm();
    put64(&mut bytes, 40, u64::MAX);
    let report = run(&bytes);
    assert!(report.header.is_some());
    assert!(!report.segments.is_empty());
    assert!(report.sections.is_empty());
}
#[test]
fn loader_like_header_rejection_still_allows_structural_inspection_and_decode() {
    let mut bytes = asm();
    bytes[7] = 9;
    let report = run(&bytes);
    assert_eq!(
        report.header.as_ref().unwrap().engine,
        Engine::ObjectFallback
    );
    assert!(!report.sections.is_empty());
    assert!(!report.instructions.is_empty());
    assert!(report.analysis.is_none());
}
#[test]
fn nobits_has_no_file_mapping_even_when_offset_overlaps_code() {
    let mut bytes = asm();
    let original = run(&bytes);
    let data = original
        .sections
        .iter()
        .find(|s| s.name == ".rodata")
        .unwrap();
    let header_offset = sh(&original, data.index);
    put32(&mut bytes, header_offset + 4, 8);
    let report = run(&bytes);
    let section = &report.sections[data.index];
    assert!(section.file_range.is_none());
    assert!(
        section_location(section, 0, 3)
            .unwrap()
            .file_offset
            .is_none()
    );
    assert!(!report.instructions.is_empty());
}
#[test]
fn relocatable_offsets_are_section_relative_and_rela_addends_are_signed() {
    let mut bytes = asm();
    let original = run(&bytes);
    let r = &original.relocations[0];
    let text = original
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .unwrap();
    put16(&mut bytes, 16, 1);
    let rel_header = sh(&original, r.table_index);
    put32(&mut bytes, rel_header + 44, text.index as u32);
    put64(&mut bytes, r.record_range.offset, 8);
    let report = run(&bytes);
    let target = report.relocations[0].target.as_ref().unwrap();
    assert_eq!(target.section_offset.0, 8);
    assert_eq!(target.file_offset, Some(text.offset.0 as usize + 8));
    assert!(target.virtual_address.is_none());
    put32(&mut bytes, rel_header + 4, 4);
    put64(&mut bytes, rel_header + 32, 24);
    put64(&mut bytes, rel_header + 56, 24);
    put64(&mut bytes, r.record_range.offset + 16, (-7i64) as u64);
    let report = run(&bytes);
    assert_eq!(report.relocations[0].addend.as_deref(), Some("-7"));
    assert_eq!(report.relocations[0].engine, Engine::ObjectFallback);
}
#[test]
fn address_conversion_rejects_overflow_ambiguity_and_end_boundary() {
    let report = run(&asm());
    let s = report.sections.iter().find(|s| s.name == ".text").unwrap();
    assert!(section_location(s, s.size.0, 3).is_none());
    assert!(file_range(u64::MAX, 8, 1024).is_none());
    let mut shifted = s.clone();
    shifted.address = Hex(0x100000000);
    shifted.offset = Hex(0x100);
    shifted.file_range = Some(ByteRange {
        offset: 0x100,
        length: s.size.0 as usize,
    });
    let loc = virtual_location(&[shifted.clone()], 0x100000008, 3).unwrap();
    assert_eq!(loc.file_offset, Some(0x108));
    assert_eq!(loc.section_offset.0, 8);
    assert!(virtual_location(&[shifted.clone(), shifted], 0x100000008, 3).is_none());
}
#[test]
fn unknown_version_is_reported_without_guessing_and_u64_is_lossless() {
    let mut bytes = asm();
    put32(&mut bytes, 48, 99);
    put64(&mut bytes, 24, u64::MAX - 1);
    let report = run(&bytes);
    assert!(report.sbpf_version.is_none());
    assert!(report.instructions.is_empty());
    assert!(report.analysis.is_none());
    assert!(
        serde_json::to_string(&report)
            .unwrap()
            .contains("0xfffffffffffffffe")
    );
}
#[test]
fn truncated_final_slot_disagreement_is_visible() {
    let mut bytes = asm();
    let original = run(&bytes);
    let text = original
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .unwrap();
    put64(&mut bytes, sh(&original, text.index) + 32, text.size.0 + 1);
    let report = run(&bytes);
    assert!(report.analysis.is_some());
    assert!(
        report
            .stages
            .iter()
            .any(|s| s.name == "decode" && s.status == "partial")
    );
    // Counts agree because both retained the complete prefix; trailing bytes are not hidden.
    assert_eq!(
        report.instructions.len(),
        report.analysis.unwrap().instruction_count
    );
}

#[test]
fn v2_uses_blueshift_compatibility_decoder_and_suppresses_dynamic_stack_estimate() {
    let mut bytes = asm();
    let original = run(&bytes);
    let text = original
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .unwrap();
    put16(&mut bytes, 18, 263);
    put32(&mut bytes, 48, 2);
    let start = text.offset.0 as usize;
    for chunk in bytes[start..start + text.size.0 as usize]
        .as_chunks_mut::<8>()
        .0
    {
        chunk.copy_from_slice(&[0xb7, 0, 0, 0, 0, 0, 0, 0]);
    }
    bytes[start..start + 8].copy_from_slice(&[0x8c, 0x10, 0, 0, 0, 0, 0, 0]);
    let end = start + text.size.0 as usize;
    bytes[end - 8..end].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    let report = run(&bytes);
    assert_eq!(report.sbpf_version, Some(2));
    assert_eq!(report.instructions[0].opcode, "ldxw");
    assert_eq!(report.instructions[0].encoding.opcode_byte, 0x8c);
    assert_eq!(report.instructions[0].bytes.split(' ').next(), Some("8c"));
    let analysis = report.analysis.unwrap();
    assert_eq!(analysis.instruction_count, report.instructions.len());
    assert!(
        analysis
            .functions
            .iter()
            .all(|f| f.stack.local_estimate.is_none())
    );
}

#[test]
fn sectionless_binary_preserves_headers_and_segments() {
    let mut bytes = asm();
    put64(&mut bytes, 40, 0);
    put16(&mut bytes, 60, 0);
    put16(&mut bytes, 62, 0);
    put32(&mut bytes, 48, 3);
    let report = run(&bytes);
    assert!(report.header.is_some());
    assert_eq!(report.segments.len(), 3);
    assert!(report.sections.is_empty());
    assert!(report.analysis.is_none());
    assert!(
        report
            .stages
            .iter()
            .any(|s| s.name == "decode" && s.status == "skipped")
    );
}
