//! Structural fallback uses the same `object` crate as Blueshift. No loader validation.
use crate::{addresses::*, models::*};
use object::{Endianness, elf::FileHeader64, read::elf::FileHeader};

pub fn inspect(bytes: &[u8], report: &mut Report) -> Result<(), String> {
    let raw = FileHeader64::<Endianness>::parse(bytes).map_err(|e| e.to_string())?;
    let e = raw.endian().map_err(|e| e.to_string())?;
    let h = Header {
        engine: Engine::ObjectFallback,
        class: raw.e_ident.class,
        endian: if raw.e_ident.data == 1 {
            "little"
        } else {
            "big"
        }
        .into(),
        os_abi: raw.e_ident.os_abi,
        elf_type: raw.e_type.get(e),
        machine: raw.e_machine.get(e),
        version: raw.e_version.get(e),
        entry: Hex(raw.e_entry.get(e)),
        program_offset: Hex(raw.e_phoff.get(e)),
        section_offset: Hex(raw.e_shoff.get(e)),
        flags: raw.e_flags.get(e),
        header_size: raw.e_ehsize.get(e),
        program_entry_size: raw.e_phentsize.get(e),
        program_count: raw.e_phnum.get(e),
        section_entry_size: raw.e_shentsize.get(e),
        section_count: raw.e_shnum.get(e),
        section_names_index: raw.e_shstrndx.get(e),
    };
    report.header = Some(h);
    match raw.section_headers(e, bytes) {
        Ok(headers) => {
            let names_index = raw.shstrndx(e, bytes).ok();
            let names = names_index
                .and_then(|i| headers.get(i as usize))
                .and_then(|s| slice(bytes, s.sh_offset.get(e), s.sh_size.get(e)));
            for (index, s) in headers.iter().enumerate() {
                let section_type = s.sh_type.get(e);
                let range = if matches!(section_type, 0 | 8) {
                    None
                } else {
                    file_range(s.sh_offset.get(e), s.sh_size.get(e), bytes.len())
                };
                if range.is_none() && !matches!(section_type, 0 | 8) {
                    report.warn(
                        "sections",
                        Engine::ObjectFallback,
                        format!("Section {index} payload is outside the file; header retained"),
                    );
                }
                report.sections.push(Section {
                    index,
                    name: names
                        .map(|n| string(n, s.sh_name.get(e) as usize))
                        .unwrap_or_else(|| format!("section_{index}")),
                    engine: Engine::ObjectFallback,
                    section_type,
                    flags: Hex(s.sh_flags.get(e)),
                    address: Hex(s.sh_addr.get(e)),
                    offset: Hex(s.sh_offset.get(e)),
                    size: Hex(s.sh_size.get(e)),
                    link: s.sh_link.get(e),
                    info: s.sh_info.get(e),
                    alignment: Hex(s.sh_addralign.get(e)),
                    entry_size: Hex(s.sh_entsize.get(e)),
                    file_range: range,
                });
            }
            report.stage("structure.sections", Engine::ObjectFallback, "ok", None);
        }
        Err(e) => report.stage(
            "structure.sections",
            Engine::ObjectFallback,
            "error",
            Some(e.to_string()),
        ),
    }
    match raw.program_headers(e, bytes) {
        Ok(headers) => {
            report.segments = headers
                .iter()
                .enumerate()
                .map(|(index, p)| Segment {
                    index,
                    engine: Engine::ObjectFallback,
                    segment_type: p.p_type.get(e),
                    flags: p.p_flags.get(e),
                    offset: Hex(p.p_offset.get(e)),
                    virtual_address: Hex(p.p_vaddr.get(e)),
                    physical_address: Hex(p.p_paddr.get(e)),
                    file_size: Hex(p.p_filesz.get(e)),
                    memory_size: Hex(p.p_memsz.get(e)),
                    alignment: Hex(p.p_align.get(e)),
                    file_range: file_range(p.p_offset.get(e), p.p_filesz.get(e), bytes.len()),
                })
                .collect();
            report.stage("structure.segments", Engine::ObjectFallback, "ok", None);
        }
        Err(e) => report.stage(
            "structure.segments",
            Engine::ObjectFallback,
            "error",
            Some(e.to_string()),
        ),
    }
    tables(bytes, report);
    Ok(())
}
pub fn slice(bytes: &[u8], offset: u64, length: u64) -> Option<&[u8]> {
    let r = file_range(offset, length, bytes.len())?;
    bytes.get(r.offset..r.offset + r.length)
}
fn string(bytes: &[u8], offset: usize) -> String {
    let Some(rest) = bytes.get(offset..) else {
        return "<invalid string offset>".into();
    };
    String::from_utf8_lossy(&rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())])
        .into_owned()
}
fn word(bytes: &[u8], little: bool) -> u64 {
    let mut padded = [0; 8];
    if little {
        padded[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(padded)
    } else {
        padded[8 - bytes.len()..].copy_from_slice(bytes);
        u64::from_be_bytes(padded)
    }
}
fn tables(bytes: &[u8], report: &mut Report) {
    let h = report.header.as_ref().unwrap();
    let little = h.endian == "little";
    let elf_type = h.elf_type;
    // Clone metadata only; section payloads remain in the original upload.
    let sections = report.sections.clone();
    for s in sections.iter().filter(|s| matches!(s.section_type, 2 | 11)) {
        let Some(data) = slice(bytes, s.offset.0, s.size.0) else {
            continue;
        };
        let stride = s.entry_size.0;
        if stride < 24 || stride > data.len() as u64 && !data.is_empty() {
            report.warn(
                "symbols",
                Engine::ObjectFallback,
                format!("Invalid entry size in {}", s.name),
            );
            continue;
        }
        let names = sections
            .iter()
            .find(|n| n.index == s.link as usize && n.section_type == 3)
            .and_then(|n| slice(bytes, n.offset.0, n.size.0));
        for (index, chunk) in data.chunks_exact(stride as usize).enumerate() {
            let section_index = word(&chunk[6..8], little) as u16;
            let value = word(&chunk[8..16], little);
            let location = sections
                .iter()
                .find(|s| {
                    s.index == section_index as usize
                        && section_index != 0
                        && section_index < 0xff00
                })
                .and_then(|s| {
                    section_location(
                        s,
                        if elf_type == 1 {
                            Some(value)
                        } else {
                            value.checked_sub(s.address.0)
                        }?,
                        elf_type,
                    )
                });
            report.symbols.push(Symbol {
                id: report.symbols.len(),
                index,
                table_index: s.index,
                engine: Engine::ObjectFallback,
                name: names
                    .map(|n| string(n, word(&chunk[..4], little) as usize))
                    .unwrap_or_default(),
                value: Hex(value),
                size: Hex(word(&chunk[16..24], little)),
                binding: chunk[4] >> 4,
                symbol_type: chunk[4] & 15,
                visibility: chunk[5] & 3,
                section_index,
                location,
            });
        }
        if s.size.0 % stride != 0 {
            report.warn(
                "symbols",
                Engine::ObjectFallback,
                format!("Trailing partial symbol in {}", s.name),
            );
        }
    }
    for s in sections.iter().filter(|s| matches!(s.section_type, 4 | 9)) {
        let Some(data) = slice(bytes, s.offset.0, s.size.0) else {
            continue;
        };
        let minimum = if s.section_type == 4 { 24 } else { 16 };
        let stride = if s.entry_size.0 == 0 {
            minimum
        } else {
            s.entry_size.0
        };
        if stride < minimum || stride > data.len() as u64 && !data.is_empty() {
            report.warn(
                "relocations",
                Engine::ObjectFallback,
                format!("Invalid entry size in {}", s.name),
            );
            continue;
        }
        for (index, chunk) in data.chunks_exact(stride as usize).enumerate() {
            let offset = word(&chunk[..8], little);
            let info = word(&chunk[8..16], little);
            let symbol_index = (info >> 32) as u32;
            let relocation_type = info as u32;
            let target = relocation_location(&sections, elf_type, s.info, offset);
            report.relocations.push(Relocation {
                id: report.relocations.len(),
                index,
                table_index: s.index,
                engine: Engine::ObjectFallback,
                offset: Hex(offset),
                relocation_type,
                type_name: relocation_name(relocation_type),
                symbol_index,
                symbol_id: report
                    .symbols
                    .iter()
                    .find(|x| x.table_index == s.link as usize && x.index == symbol_index as usize)
                    .map(|x| x.id),
                addend: (s.section_type == 4)
                    .then(|| (word(&chunk[16..24], little) as i64).to_string()),
                record_range: ByteRange {
                    offset: s.offset.0 as usize + index * stride as usize,
                    length: minimum as usize,
                },
                mapping_note: if target.is_some() {
                    "Target location resolved; relocation not applied"
                } else {
                    "No unique section mapping (unmapped, ambiguous, or unsupported ELF type)"
                }
                .into(),
                target,
                instruction_id: None,
                highlight_ranges: vec![],
            });
        }
        if s.size.0 % stride != 0 {
            report.warn(
                "relocations",
                Engine::ObjectFallback,
                format!("Trailing partial relocation in {}", s.name),
            );
        }
    }
    report.stage(
        "symbols",
        Engine::ObjectFallback,
        "ok",
        Some("Blueshift has no public symbol-table API".into()),
    );
    report.stage("relocations.allTables", Engine::ObjectFallback, "ok", None);
}
fn relocation_name(n: u32) -> String {
    match n {
        0 => "R_BPF_NONE",
        1 => "R_BPF_64_64",
        2 => "R_BPF_64_ABS64",
        3 => "R_BPF_64_ABS32",
        4 => "R_BPF_64_NODYLD32",
        8 => "R_BPF_64_RELATIVE",
        10 => "R_BPF_64_32",
        _ => return format!("UNKNOWN({n})"),
    }
    .into()
}
