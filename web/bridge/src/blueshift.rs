//! Blueshift adapters. Use component APIs so one rejected table cannot erase another.
use crate::{addresses::*, errors::guarded, models::*};
use object::{Endianness, read::elf::ElfFile64};
use sbpf_common::instruction::{AsmFormat, Instruction as Decoded};
use sbpf_disassembler::{
    elf_header::ELFHeader, program_header::ProgramHeader, relocation::Relocation as BsRelocation,
    section_header::SectionHeader,
};

pub fn inspect(bytes: &[u8], report: &mut Report) {
    let file = match ElfFile64::<Endianness>::parse(bytes) {
        Ok(f) => f,
        Err(e) => {
            report.stage(
                "blueshift.structure",
                Engine::Blueshift,
                "error",
                Some(e.to_string()),
            );
            return;
        }
    };
    match guarded(|| ELFHeader::from_elf_file(&file)) {
        Ok(h) => {
            report.header = Some(Header {
                engine: Engine::Blueshift,
                class: h.ei_class,
                endian: "little".into(),
                os_abi: h.ei_osabi,
                elf_type: h.e_type,
                machine: h.e_machine,
                version: h.e_version,
                entry: Hex(h.e_entry),
                program_offset: Hex(h.e_phoff),
                section_offset: Hex(h.e_shoff),
                flags: h.e_flags,
                header_size: h.e_ehsize,
                program_entry_size: h.e_phentsize,
                program_count: h.e_phnum,
                section_entry_size: h.e_shentsize,
                section_count: h.e_shnum,
                section_names_index: h.e_shstrndx,
            });
            report.stage("blueshift.header", Engine::Blueshift, "ok", None);
        }
        Err(e) => report.stage("blueshift.header", Engine::Blueshift, "error", Some(e)),
    }
    match guarded(|| ProgramHeader::from_elf_file(&file)) {
        Ok(headers) => {
            for (s, h) in report.segments.iter_mut().zip(headers) {
                // ProgramFlags masks unknown bits. Preserve those bits from structural parsing.
                if s.flags & !7 != 0 {
                    continue;
                }
                *s = Segment {
                    index: s.index,
                    engine: Engine::Blueshift,
                    segment_type: h.p_type as u32,
                    flags: h.p_flags.0,
                    offset: Hex(h.p_offset),
                    virtual_address: Hex(h.p_vaddr),
                    physical_address: Hex(h.p_paddr),
                    file_size: Hex(h.p_filesz),
                    memory_size: Hex(h.p_memsz),
                    alignment: Hex(h.p_align),
                    file_range: file_range(h.p_offset, h.p_filesz, bytes.len()),
                };
            }
            report.stage("blueshift.segments", Engine::Blueshift, "ok", None);
        }
        Err(e) => report.stage("blueshift.segments", Engine::Blueshift, "error", Some(e)),
    }
    // Upstream copies every payload, including NOBITS, and indexes section-name data.
    // Gate its unchecked slicing/allocation; raw headers remain inspectable regardless.
    if safe_section_copy(report, bytes.len()) {
        match guarded(|| SectionHeader::from_elf_file(&file)) {
            Ok((headers, entries)) => {
                report.sections = headers
                    .into_iter()
                    .zip(entries)
                    .enumerate()
                    .map(|(index, (h, entry))| {
                        let section_type = h.sh_type as u32;
                        Section {
                            index,
                            name: entry.label.trim_end_matches('\0').into(),
                            engine: Engine::Blueshift,
                            section_type,
                            flags: Hex(h.sh_flags),
                            address: Hex(h.sh_addr),
                            offset: Hex(h.sh_offset),
                            size: Hex(h.sh_size),
                            link: h.sh_link,
                            info: h.sh_info,
                            alignment: Hex(h.sh_addralign),
                            entry_size: Hex(h.sh_entsize),
                            file_range: if matches!(section_type, 0 | 8) {
                                None
                            } else {
                                file_range(
                                    entry.offset as u64,
                                    entry.data.len() as u64,
                                    bytes.len(),
                                )
                            },
                        }
                    })
                    .collect();
                report.stage("blueshift.sections", Engine::Blueshift, "ok", None);
            }
            Err(e) => report.stage("blueshift.sections", Engine::Blueshift, "error", Some(e)),
        }
    } else {
        report.stage(
            "blueshift.sections",
            Engine::Blueshift,
            "skipped",
            Some("Unsafe upstream section-copy preconditions; structural fallback retained".into()),
        );
    }
    if report.header.as_ref().is_some_and(|h| h.endian == "little") {
        match guarded(|| BsRelocation::from_elf_file(&file)) {
            Ok(relocations) => {
                let dyn_table = report
                    .sections
                    .iter()
                    .find(|s| {
                        s.name == ".rel.dyn"
                            && s.section_type == 9
                            && matches!(s.entry_size.0, 0 | 16)
                    })
                    .map(|s| s.index);
                if let Some(table) = dyn_table {
                    for (r, bs) in report
                        .relocations
                        .iter_mut()
                        .filter(|r| r.table_index == table)
                        .zip(relocations)
                    {
                        if r.offset.0 == bs.offset
                            && r.relocation_type == bs.rel_type as u32
                            && r.symbol_index == bs.symbol_index
                        {
                            r.engine = Engine::Blueshift;
                            r.offset = Hex(bs.offset);
                            r.relocation_type = bs.rel_type as u32;
                        }
                    }
                }
                report.stage(
                    "blueshift.relocations",
                    Engine::Blueshift,
                    "ok",
                    Some(".rel.dyn supported types; other records retained by fallback".into()),
                );
            }
            Err(e) => report.stage("blueshift.relocations", Engine::Blueshift, "error", Some(e)),
        }
    }
}
pub fn safe_section_copy(report: &Report, file_size: usize) -> bool {
    let Some(h) = &report.header else {
        return false;
    };
    !report.sections.is_empty()
        && (h.section_names_index as usize) < report.sections.len()
        && report
            .sections
            .iter()
            .all(|s| s.section_type != 8 && file_range(s.offset.0, s.size.0, file_size).is_some())
        && report
            .sections
            .iter()
            .try_fold(0u64, |n, s| n.checked_add(s.size.0))
            .is_some_and(|n| n <= 64 * 1024 * 1024)
}

pub fn decode(bytes: &[u8], report: &mut Report) {
    let Some(h) = &report.header else {
        report.stage(
            "decode",
            Engine::Blueshift,
            "skipped",
            Some("No ELF header".into()),
        );
        return;
    };
    let elf_type = h.elf_type;
    let machine = h.machine;
    let version = h.flags;
    let supported = h.endian == "little"
        && ((machine == 247 && matches!(version, 0 | 3)) || (machine == 263 && version <= 2));
    if !supported {
        report.stage(
            "decode",
            Engine::Blueshift,
            "skipped",
            Some(format!(
                "Unsupported or uncertain machine/version combination: {machine}/{version}"
            )),
        );
        return;
    }
    report.sbpf_version = Some(version);
    if version != 0 {
        report.warn("decode", Engine::Blueshift, "Version comes from ELF flags. Blueshift 0.1.9 has a v2 opcode compatibility path, not complete version-specific ISA validation.");
    }
    let text_sections: Vec<_> = report
        .sections
        .iter()
        .filter(|s| s.name == ".text")
        .collect();
    if text_sections.len() != 1 {
        report.stage(
            "decode",
            Engine::Blueshift,
            "skipped",
            Some("Expected one unambiguous .text section".into()),
        );
        return;
    }
    let section = text_sections[0].clone();
    let Some(range) = section.file_range else {
        report.stage(
            "decode",
            Engine::Blueshift,
            "skipped",
            Some(".text has no valid file-backed payload".into()),
        );
        return;
    };
    let data = &bytes[range.offset..range.offset + range.length];
    let mut pc = 0;
    let mut error = None;
    while pc < data.len() {
        if data.len() - pc < 8 {
            error = Some(format!(
                "Trailing {} bytes at .text+0x{pc:x}",
                data.len() - pc
            ));
            break;
        }
        // Bounded window avoids v2's whole-tail copy on every instruction.
        let window = &data[pc..(pc + 16).min(data.len())];
        let decoded = guarded(|| {
            if version == 2 {
                Decoded::from_bytes_sbpf_v2(window)
            } else {
                Decoded::from_bytes(window)
            }
        });
        let ix = match decoded {
            Ok(ix) => ix,
            Err(e) => {
                error = Some(format!(".text+0x{pc:x}: {e}"));
                break;
            }
        };
        let length = ix.span.len();
        if !matches!(length, 8 | 16) || length > window.len() {
            error = Some(format!("Invalid decoder span at .text+0x{pc:x}"));
            break;
        }
        let asm = guarded(|| ix.to_asm(AsmFormat::Default));
        let text = match asm {
            Ok(text) => text,
            Err(e) => {
                report.warn(
                    "decode.format",
                    Engine::Blueshift,
                    format!(".text+0x{pc:x}: {e}"),
                );
                format!("{} <format unavailable>", ix.opcode)
            }
        };
        let (opcode, operands) = text.split_once(' ').unwrap_or((&text, ""));
        report.instructions.push(Instruction {
            id: report.instructions.len(),
            engine: Engine::Blueshift,
            pc,
            length,
            location: section_location(&section, pc as u64, elf_type).unwrap(),
            bytes: window[..length]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            opcode: opcode.into(),
            operands: operands.into(),
            text: text.clone(),
            encoding: Encoding {
                opcode_byte: window[0],
                register_byte: window[1],
                offset: i16::from_le_bytes(window[2..4].try_into().unwrap()),
                immediate: i32::from_le_bytes(window[4..8].try_into().unwrap()),
            },
            block_id: None,
            function_ids: vec![],
            symbol_ids: vec![],
            relocation_ids: vec![],
        });
        pc += length;
    }
    report.stage(
        "decode",
        Engine::Blueshift,
        if error.is_some() { "partial" } else { "ok" },
        error,
    );
}
