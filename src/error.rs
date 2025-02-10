use std::fmt::Debug;

use thiserror::Error;

use crate::file::Format;

#[derive(Error)]
pub enum DexError {
    #[error("Empty or truncated file")]
    TruncatedFile,

    #[error("Bad file magic")]
    BadFileMagic,

    #[error("Unknown dex version: {version}")]
    UnknownDexVersion { version: u32 },

    #[error("Bad file size ({actual}, expected at least {expected})")]
    FileSizeAtLeast { actual: usize, expected: usize },

    #[error("Bad file size ({actual}, expected at most {expected})")]
    FileSizeAtMost { actual: usize, expected: usize },

    #[error("Bad header size: {size}, expected {expected}")]
    BadHeaderSize { size: u32, expected: u32 },

    #[error("Unexpected endian tag: {0:x}")]
    UnexpectedEndianess(u32),

    #[error("Bad checksum: {actual:#08x}, expected {expected:#08x}")]
    BadChecksum { actual: u32, expected: u32 },

    #[error("Offset({offset}) should be within file size {size} for {section}")]
    BadOffsetTooLarge {
        offset: u32,
        size: usize,
        section: &'static str,
    },

    #[error("Offset({offset}) should be after header({header_size}) for {section}")]
    BadOffsetInHeader {
        offset: u32,
        header_size: usize,
        section: &'static str,
    },

    #[error("Offset({offset}) should be zero when size is zero for {section}")]
    BadOffsetNoSize { offset: u32, section: &'static str },

    #[error("Section end({offset}) should be within file size {size} for {section}")]
    BadSection {
        offset: u32,
        size: usize,
        section: &'static str,
    },

    #[error("{0}")]
    DexFileError(String),

    #[error("Index({index}) to {item_ty} should be less than {max}")]
    DexIndexError {
        index: u32,
        max: usize,
        item_ty: &'static str,
    },

    #[error("Bad string data({0}) does not end with a null byte!")]
    BadStringDataMissingNullByte(usize),

    #[error("{0}")]
    Mutf8DecodeError(#[from] std::string::FromUtf16Error),

    #[error("Failed to read {location}: {item_ty} at offset {offset} (array_len={array_len}) overflows with file size({file_size})")]
    DexLayoutError {
        location: String,
        offset: u32,
        item_ty: &'static str,
        array_len: usize,
        file_size: usize,
    },

    #[error(
        "Tries to access v{operand} of instruction {insn_name} which has no {operand} operand"
    )]
    OperandAccessError {
        insn_name: &'static str,
        operand: &'static str,
    },

    #[error("Failed to parse varint: {0}")]
    VarIntError(#[from] varint_simd::VarIntDecodeError),

    #[error("Bad string data({offset}) contains invalid LEB128({kind:?}) which can't be converted to a valid u32")]
    BadStringData {
        offset: usize,
        #[source]
        kind: varint_simd::VarIntDecodeError,
    },

    #[error("Encountered invalid encoded index that would overflow: index({index}) + next index({next_index}) > u32::MAX for {item_ty}")]
    BadEncodedIndex {
        index: u32,
        next_index: u32,
        item_ty: &'static str,
    },

    #[error(
        "{opcode}: Offset({offset}, relative code unit) should be within code stream size({size})"
    )]
    BadInstructionOffset {
        opcode: &'static str,
        offset: usize,
        size: usize,
    },

    #[error("{opcode}: Could not fetch {target_type} at offset {offset} - code stream too small({size})")]
    BadInstruction {
        opcode: &'static str,
        offset: usize,
        size: usize,
        target_type: &'static str,
    },

    #[error("{opcode}: Invalid argument count {count} for format {format:?}")]
    InvalidArgCount {
        opcode: &'static str,
        format: &'static Format,
        count: u8,
    },

    #[error("{opcode}: Invalid argument range {start}..{start}+{end} for format {format:?} - the range must at least cover one register")]
    InvalidArgRange {
        opcode: &'static str,
        format: &'static Format,
        start: u16,
        end: u16,
    },

    #[error("Encountered an encoded value with no size which is not allowed")]
    EmptyEncodedValue,

    #[error("Invalid encoded value({0:#x})")]
    BadEncodedValueType(u8),

    #[error("Invalid encoded value({value_type:#x}) requested byte at offset({offset}) which is out of bounds (size: {size})")]
    InvalidEncodedValue {
        value_type: u8,
        offset: usize,
        size: usize,
    },

    #[error("Invalid encoded value({value_type:#x}) requested size({size}) which is too big for data type (size: {max})")]
    BadEncodedValueSize {
        value_type: u8,
        size: usize,
        max: usize,
    },

    #[error("Invalid encoded value({value_type:#x}) requested array length({size}) which does not fit into value buffer (size: {max})")]
    BadEncodedArrayLength {
        value_type: u8,
        size: usize,
        offset: usize,
        max: usize,
    },

    #[error(
        "Got invalid object reference({offset}) which is out of bounds (start: {start}, end: {end})"
    )]
    UnknownObjectRef {
        offset: usize,
        start: usize,
        end: usize,
    },

    #[error(
        "Got invalid mUTF8 encoded string that encodes up to {idx} characters with only {len} bytes"
    )]
    MalformedMUTF8Sequence { idx: usize, len: usize },
}

#[macro_export]
macro_rules! dex_err {
    ($name:ident) => {
        Err(DexError::$name)
    };
    ($name:ident, $arg1:literal, $($arg:tt)*) => {
        Err(DexError::$name(format!($arg1, $($arg)*)))
    };
    (DexLayoutError, $dex:ident, $off:ident, $item_ty:expr, $array_len:expr) => {
        Err(DexError::DexLayoutError {
            location: $dex.get_location().to_string(),
            offset: $off,
            item_ty: $item_ty,
            array_len: $array_len,
            file_size: $dex.file_size(),
        })
    };
    ($name:ident { $($arg:tt)* }) => {
        Err(DexError::$name { $($arg)* })
    };
    ($name:ident, $($arg:tt)*) => {
        Err(DexError::$name($($arg)*))
    };
}

impl Debug for DexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
