use std::fmt::Display;

use memmap2::{Mmap, MmapMut};

pub mod structs;
pub use structs::*;
pub mod header;
pub use header::*;
pub mod class_accessor;
pub mod verifier;
pub use class_accessor::*;
pub mod modifiers;
pub use modifiers::*;
pub mod instruction;
pub use instruction::*;
pub mod code_item_accessors;
pub use code_item_accessors::*;
pub mod container;
pub mod dump;
pub use container::*;
pub mod annotations;
pub use annotations::*;
pub mod debug;
pub use debug::*;
pub mod patch;
pub use patch::{patch_class_access_flags, patch_instruction_word, update_checksum};
pub mod editor;
pub use editor::DexEditor;
pub mod ir;
pub use ir::{
    BranchTarget, ClassDef as IrClassDef, CodeDef, DexIr, DexRef, EncodedValueIr, FieldDef as IrFieldDef,
    InsnNode, MethodDef as IrMethodDef, ProtoKey, TryDef,
};
pub mod writer;
pub use writer::DexWriter;
pub mod builder;
pub use builder::{CodeBuilder, DexIrBuilder};

pub const DEX_MAGIC: &[u8] = b"dex\n";
pub const DEX_MAGIC_VERSIONS: &[&[u8]] = &[
    b"035\0", b"037\0", // Dex version 038: Android "O" and beyond.
    b"038\0", // Dex version 039: Android "P" and beyond.
    b"039\0", // Dex version 040: Android "Q" and beyond (aka Android 10).
    b"040\0", // Dex version 041: Android "V" and beyond (aka Android 15).
    b"041\0",
];

pub const DEX_ENDIAN_CONSTANT: u32 = 0x12345678;
pub const DEX_NO_INDEX: u32 = 0xffffffff;

#[derive(Debug)]
pub enum DexLocation {
    InMemory,
    Path(String),
}

impl From<&'static str> for DexLocation {
    fn from(s: &'static str) -> Self {
        DexLocation::Path(s.to_string())
    }
}

impl From<String> for DexLocation {
    fn from(s: String) -> Self {
        DexLocation::Path(s)
    }
}

impl Display for DexLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DexLocation::InMemory => write!(f, "[in-memory]"),
            DexLocation::Path(path) => write!(f, "{}", path),
        }
    }
}

pub type InMemoryDexFile<'a> = DexFile<'a, &'a [u8]>;
pub type MmapDexFile<'a> = DexFile<'a, Mmap>;
pub type MmapMutDexFile<'a> = DexFile<'a, MmapMut>;

pub mod dex_file;
pub use dex_file::*;

pub mod compact_dex;
pub use compact_dex::{CDEX_MAGIC, CDEX_MAGIC_VERSIONS};

pub mod signature;
pub use signature::Signature;

pub mod type_lookup_table;
pub use type_lookup_table::TypeLookupTable;

/// Whether a DEX file uses the standard (`dex\n`) or compact (`cdex`) format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexFormat {
    Standard,
    Compact,
}
