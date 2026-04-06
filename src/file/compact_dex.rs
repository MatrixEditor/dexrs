/// CompactDex (`cdex`) magic bytes and supported version.
pub const CDEX_MAGIC: &[u8] = b"cdex";
pub const CDEX_MAGIC_VERSIONS: &[&[u8]] = &[b"001\0"];

// Compact CodeItem field constants (matching ART's CompactDexFile::CodeItem)
const FLAG_PREHEADER_REGISTERS_SIZE: u16 = 1 << 0;
const FLAG_PREHEADER_INS_SIZE: u16 = 1 << 1;
const FLAG_PREHEADER_OUTS_SIZE: u16 = 1 << 2;
const FLAG_PREHEADER_TRIES_SIZE: u16 = 1 << 3;
const FLAG_PREHEADER_INSNS_SIZE: u16 = 1 << 4;
const INSNS_COUNT_SHIFT: u32 = 5;

const FIELDS_REGISTERS_SIZE_SHIFT: u32 = 12;
const FIELDS_INS_SIZE_SHIFT: u32 = 8;
const FIELDS_OUTS_SIZE_SHIFT: u32 = 4;
const FIELDS_TRIES_SIZE_SHIFT: u32 = 0;

/// Fields decoded from a CompactDex code item (and its preheader if present).
#[derive(Debug, Clone, Copy)]
pub struct DecodedCompactCodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    /// Total instruction count in code units.
    pub insns_size: u32,
    /// Absolute byte offset within the DEX data section where instructions start.
    pub insns_off: u32,
}

/// Decodes a compact DEX code item from `data` at the given byte offset.
///
/// `offset` must point to the first byte of the compact `fields_` u16 word.
/// The preheader (if any) must be readable at `offset - N * 2`.
///
/// Returns `None` if `offset` is out of bounds for the compact code item header.
pub fn decode_compact_code_item(data: &[u8], offset: usize) -> Option<DecodedCompactCodeItem> {
    if offset + 4 > data.len() {
        return None;
    }
    let fields = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let icf = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

    let mut registers_size = ((fields as u32 >> FIELDS_REGISTERS_SIZE_SHIFT) & 0xF) as u16;
    let mut ins_size = ((fields as u32 >> FIELDS_INS_SIZE_SHIFT) & 0xF) as u16;
    let mut outs_size = ((fields as u32 >> FIELDS_OUTS_SIZE_SHIFT) & 0xF) as u16;
    let mut tries_size = ((fields as u32 >> FIELDS_TRIES_SIZE_SHIFT) & 0xF) as u16;
    let mut insns_size = (icf as u32) >> INSNS_COUNT_SHIFT;

    // Decode preheader words that precede the code item in memory.
    // The preheader pointer walks backwards from `offset` in steps of 2 bytes.
    if icf
        & (FLAG_PREHEADER_REGISTERS_SIZE
            | FLAG_PREHEADER_INS_SIZE
            | FLAG_PREHEADER_OUTS_SIZE
            | FLAG_PREHEADER_TRIES_SIZE
            | FLAG_PREHEADER_INSNS_SIZE)
        != 0
    {
        let mut pre = offset as isize;

        if icf & FLAG_PREHEADER_INSNS_SIZE != 0 {
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            let low = u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]) as u32;
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            let high = u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]) as u32;
            insns_size += low + (high << 16);
        }
        if icf & FLAG_PREHEADER_REGISTERS_SIZE != 0 {
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            registers_size +=
                u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]);
        }
        if icf & FLAG_PREHEADER_INS_SIZE != 0 {
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            ins_size += u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]);
        }
        if icf & FLAG_PREHEADER_OUTS_SIZE != 0 {
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            outs_size += u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]);
        }
        if icf & FLAG_PREHEADER_TRIES_SIZE != 0 {
            pre -= 2;
            if pre < 0 || pre as usize + 2 > data.len() {
                return None;
            }
            tries_size += u16::from_le_bytes([data[pre as usize], data[pre as usize + 1]]);
        }
    }

    // ART stores `registers_size - ins_size` in the packed field; restore it.
    registers_size += ins_size;

    // Instructions follow immediately after the 4-byte compact header.
    let insns_off = (offset + 4) as u32;

    Some(DecodedCompactCodeItem {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        insns_size,
        insns_off,
    })
}
