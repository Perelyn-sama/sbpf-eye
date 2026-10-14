//! Address domains are explicit: PC is a byte offset in .text, never a VM address.
use crate::models::*;
pub fn file_range(offset: u64, length: u64, file_size: usize) -> Option<ByteRange> {
    let end = offset.checked_add(length)?;
    (end <= file_size as u64).then_some(ByteRange {
        offset: offset as usize,
        length: length as usize,
    })
}
pub fn section_location(section: &Section, relative: u64, elf_type: u16) -> Option<Location> {
    if relative >= section.size.0 {
        return None;
    }
    Some(Location {
        section_index: section.index,
        section_offset: Hex(relative),
        file_offset: section
            .file_range
            .and_then(|r| r.offset.checked_add(relative as usize)),
        virtual_address: (elf_type != 1 && section.flags.0 & 2 != 0)
            .then(|| section.address.0.checked_add(relative).map(Hex))
            .flatten(),
    })
}
pub fn virtual_location(sections: &[Section], address: u64, elf_type: u16) -> Option<Location> {
    if elf_type == 1 {
        return None;
    }
    let mut candidates = sections
        .iter()
        .filter(|s| s.flags.0 & 2 != 0)
        .filter_map(|s| section_location(s, address.checked_sub(s.address.0)?, elf_type));
    let first = candidates.next()?;
    if candidates.next().is_some() {
        None
    } else {
        Some(first)
    }
}
pub fn relocation_location(
    sections: &[Section],
    elf_type: u16,
    target_index: u32,
    offset: u64,
) -> Option<Location> {
    if elf_type == 1 {
        let s = sections
            .iter()
            .find(|s| s.index == target_index as usize && s.index != 0)?;
        section_location(s, offset, elf_type)
    } else if matches!(elf_type, 2 | 3) {
        // sh_info is not a file-offset base for ET_DYN/ET_EXEC; r_offset is a VA.
        virtual_location(sections, offset, elf_type)
    } else {
        None
    }
}
