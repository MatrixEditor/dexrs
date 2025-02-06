use std::fmt::Debug;

use thiserror::Error;

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
    BadStringData(usize),

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
