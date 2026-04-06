use std::mem;

use crate::{
    dex_err,
    error::DexError,
    file::{ClassDef, Header, MapItem},
    leb128::decode_leb128_off,
    Result,
};

// --- Checksum ----------------------------------------------------------------

/// Recalculate the Adler32 checksum (over bytes `[12..]`) and write it to `data[8..12]`.
pub fn update_checksum(data: &mut [u8]) {
    if data.len() < 12 {
        return;
    }
    let sum = adler32::adler32(&data[12..]).unwrap_or(0);
    data[8..12].copy_from_slice(&sum.to_le_bytes());
}

// --- ClassDef ----------------------------------------------------------------

const CLASS_DEF_SIZE: usize = mem::size_of::<ClassDef>();
/// Byte offset of `ClassDef.access_flags` within the `#[repr(C)]` struct.
/// Layout: class_idx(2) + pad(2) + access_flags(4) -> offset 4.
pub(crate) const CLASS_DEF_FLAGS_OFF: usize = 4;

/// Overwrite `ClassDef.access_flags` for the class at `class_def_idx`.
///
/// Returns an error if `class_def_idx` is out of range or the write would exceed the file.
pub fn patch_class_access_flags(
    data: &mut [u8],
    header: &Header,
    class_def_idx: u32,
    flags: u32,
) -> Result<()> {
    if class_def_idx >= header.class_defs_size {
        return dex_err!(DexIndexError {
            index: class_def_idx,
            max: header.class_defs_size as usize,
            item_ty: "ClassDef"
        });
    }
    let off =
        header.class_defs_off as usize + class_def_idx as usize * CLASS_DEF_SIZE + CLASS_DEF_FLAGS_OFF;
    data.get_mut(off..off + 4)
        .ok_or_else(|| {
            DexError::DexFileError(format!("class_def[{class_def_idx}] out of bounds"))
        })?
        .copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

// --- Instructions ------------------------------------------------------------

/// Byte offset of `CodeItem.insns[0]` from the start of the code item.
/// Layout: registers(2)+ins(2)+outs(2)+tries(2)+debug_off(4)+insns_size(4) = 16 bytes.
const CODE_ITEM_INSNS_OFF: usize = 16;

/// Overwrite a single instruction word (`u16`) at code-unit offset `pc` inside a code item.
pub fn patch_instruction_word(
    data: &mut [u8],
    code_off: u32,
    pc: u32,
    word: u16,
) -> Result<()> {
    if code_off == 0 {
        return Err(DexError::TruncatedFile);
    }
    let item_start = code_off as usize;
    let insns_size_off = item_start + 12;

    let insns_size = u32::from_le_bytes(
        data.get(insns_size_off..insns_size_off + 4)
            .ok_or(DexError::TruncatedFile)?
            .try_into()
            .unwrap(),
    );
    if pc >= insns_size {
        return dex_err!(BadInstructionOffset {
            opcode: "patch",
            offset: pc as usize,
            size: insns_size as usize
        });
    }

    let word_off = item_start + CODE_ITEM_INSNS_OFF + pc as usize * 2;
    data.get_mut(word_off..word_off + 2)
        .ok_or_else(|| DexError::DexFileError(format!("instruction word at {word_off} out of bounds")))?
        .copy_from_slice(&word.to_le_bytes());
    Ok(())
}

// --- Internal helpers (used by editor.rs) ------------------------------------

/// Read the DEX header from the start of `data`, or `None` if too short / misaligned.
pub(crate) fn read_header(data: &[u8]) -> Option<&Header> {
    plain::from_bytes::<Header>(data).ok()
}

/// Return the map item slice, or `None` if unavailable.
#[allow(dead_code)]
pub(crate) fn map_list(data: &[u8]) -> Option<&[MapItem]> {
    let h = read_header(data)?;
    let size_off = h.map_off as usize;
    let count = u32::from_le_bytes(data.get(size_off..size_off + 4)?.try_into().ok()?) as usize;
    let items_off = size_off + 4;
    let items_end = items_off + count * mem::size_of::<MapItem>();
    plain::slice_from_bytes::<MapItem>(data.get(items_off..items_end)?).ok()
}

/// Encode `value` as unsigned LEB128.
pub(crate) fn encode_uleb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Decode a ULEB128 at `*pos` and advance `pos`.
pub(crate) fn skip_uleb128(data: &[u8], pos: &mut usize) -> Result<u32> {
    decode_leb128_off::<u32>(data, pos)
}

/// Byte-length of the ULEB128 encoding of `value`.
#[allow(dead_code)]
pub(crate) fn uleb128_len(value: u32) -> usize {
    encode_uleb128(value).len()
}

/// Read a `u16` at `off` (little-endian).
#[allow(dead_code)]
#[inline]
pub(crate) fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

/// Read a `u32` at `off` (little-endian).
#[allow(dead_code)]
#[inline]
pub(crate) fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

/// Write a `u32` at `off` (little-endian).
#[allow(dead_code)]
#[inline]
pub(crate) fn write_u32(data: &mut [u8], off: usize, v: u32) {
    data[off..off + 4].copy_from_slice(&v.to_le_bytes());
}


// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{DexFile, DexLocation};

    const PRIME: &[u8] = include_bytes!("../../tests/prime/prime.dex");

    // -- update_checksum ------------------------------------------------------

    #[test]
    fn checksum_roundtrip() {
        let mut data = PRIME.to_vec();
        data[8] = 0xAA;
        data[9] = 0xBB;
        update_checksum(&mut data);
        assert_eq!(&data[8..12], &PRIME[8..12]);
    }

    #[test]
    fn checksum_too_short_is_noop() {
        let mut tiny = vec![0u8; 10];
        update_checksum(&mut tiny); // must not panic
    }

    #[test]
    fn checksum_exact_boundary() {
        let mut data = vec![0u8; 12];
        update_checksum(&mut data);
        let expected = adler32::adler32(&[][..]).unwrap_or(0);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), expected);
    }

    // -- patch_class_access_flags ---------------------------------------------

    #[test]
    fn patch_flags_changes_value() {
        let mut data = PRIME.to_vec();
        // Copy header bytes so we can release the borrow before mutating.
        let header_copy = data[..112].to_vec();
        let header = read_header(&header_copy).expect("valid header");

        let flags_off = header.class_defs_off as usize + CLASS_DEF_FLAGS_OFF;
        let original = u32::from_le_bytes(data[flags_off..flags_off + 4].try_into().unwrap());

        patch_class_access_flags(&mut data, header, 0, 0x0011).unwrap();

        let patched = u32::from_le_bytes(data[flags_off..flags_off + 4].try_into().unwrap());
        assert_eq!(patched, 0x0011);
        assert_ne!(patched, original);
    }

    #[test]
    fn patch_flags_out_of_bounds_errors() {
        let mut data = PRIME.to_vec();
        let header_copy = data[..112].to_vec();
        let header = read_header(&header_copy).expect("valid header");
        assert!(patch_class_access_flags(&mut data, header, 9999, 0x0001).is_err());
    }

    #[test]
    fn patch_flags_then_reparseable() {
        let mut data = PRIME.to_vec();
        let header_copy = data[..112].to_vec();
        let header = read_header(&header_copy).expect("valid header");
        patch_class_access_flags(&mut data, header, 0, 0x0011).unwrap();
        update_checksum(&mut data);
        DexFile::from_raw_parts(&data, DexLocation::InMemory)
            .expect("re-parse after patch must succeed");
    }

    // -- patch_instruction_word -----------------------------------------------

    #[test]
    fn patch_insn_word_zero_offset_errors() {
        let mut data = PRIME.to_vec();
        // code_off=0 is never valid
        assert!(patch_instruction_word(&mut data, 0, 0, 0xFFFF).is_err());
    }

    #[test]
    fn patch_insn_word_out_of_range_pc_errors() {
        // Find a real code_off from the parsed DEX, then use an out-of-range PC.
        let first_code_off = {
            let buf = PRIME.to_vec();
            let dex = DexFile::from_raw_parts(&buf, DexLocation::InMemory).unwrap();
            let cd = dex.get_class_def(0).unwrap();
            if let Some(acc) = dex.get_class_accessor(cd).unwrap() {
                acc.get_methods()
                    .unwrap()
                    .find(|m| m.code_offset != 0)
                    .map(|m| m.code_offset)
                    .unwrap_or(0)
            } else { 0 }
        };

        if first_code_off != 0 {
            let mut data = PRIME.to_vec();
            assert!(
                patch_instruction_word(&mut data, first_code_off, 99999, 0xFFFF).is_err(),
                "out-of-range PC must error"
            );
        }
    }
}
