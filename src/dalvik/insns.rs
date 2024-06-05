//! Dalvik executable instruction set
//!
//! More details can be taken from [Android Docs: Dalvik executable
//! instruction formats](https://source.android.com/docs/core/runtime/instruction-formats)
//!
//! Instruction formats are implemented as functions and will be used to
//! parse a single instruction. As multiple opcodes store the same instruction
//! format, they simply reference their corresponding function to parse the
//! contents.

use binrw::{
    BinRead, // trait for reading
};
use byteorder::{LittleEndian, ReadBytesExt};

use crate::dalvik::error::Result;

use std::fmt::Debug;
use std::io::{Cursor, Seek};
use std::ops::Range;
use std::rc::Rc;

use super::dex::{
    CallSiteIdItem, CodeItem, DexType, FieldIdItem, FillArrayData, MethodHandleItem, MethodIdItem,
    PackedSwitch, SparseSwitch,
};
use crate::dalvik::file::{method::DexPrototype, IDexRef};

// The function below is important:
pub fn disasm(item: &CodeItem, dex: IDexRef<'_>) -> Result<Vec<Insn>> {
    let mut insns = Vec::new();
    let mut cursor = Cursor::new(item.insns.as_ref());
    // 1. Fetch information for the next opcode
    while let Some(raw_opcode) = match cursor.read_u16::<LittleEndian>() {
        Ok(raw_opcode) => Some(raw_opcode),
        Err(_) => None,
    } {
        // 2. Decode the opcode and its representation
        let opcode = &OPCODES[(raw_opcode & 0xFF) as usize];
        let start = (cursor.position() - 2) as usize;

        let mut insn = Insn {
            opcode: &opcode,
            range: start..(start + opcode.length as usize),
            format: InsnFormat::Format00x,
            payload: None,
        };
        // 3. Execute the instruction format and insert the instruction's
        // information into the instruction list
        cursor.set_position(start as u64);
        let format = match (opcode.format_factory)(&mut cursor, &mut insn, dex) {
            Ok(format) => format,
            Err(e) => {
                return Err(super::error::Error::InvalidData(format!(
                    "failed to parse instruction: {:?} at {:?}",
                    e, opcode
                )));
            }
        };

        insn.format = format;
        // update range if necessary
        if cursor.position() > insn.range.end as u64 {
            insn.range.end = cursor.position() as usize;
        }
        insns.push(insn);
    }
    return Ok(insns);
}

// just the implementation for above
pub enum Index {
    Type(Rc<DexType>),
    Field(Rc<FieldIdItem>),
    MethodHandle(Rc<MethodHandleItem>),
    Proto(Rc<DexPrototype>),
    String(Rc<String>),
    CallSite(Rc<CallSiteIdItem>),
    Method(Rc<MethodIdItem>),
    Unknown(u32),
    Literal(i64),
}

#[derive(Debug)]
pub enum InsnFormat {
    Format00x,
    Format10x,
    Format12x {
        a: u8,
        b: u8,
    },
    // REVISIT: change to string reference
    Format11n {
        a: u8,
        b: Index,
    },
    Format11x {
        a: u8,
    },
    Format10t {
        a: i8,
    },
    /// ### Format: `AA|op` (`20t`)
    ///
    /// This format specifically describes the `goto/16`` opcode.
    Format20t {
        a: i16,
    },
    /// suggested format for statically determined verification errors; A is the type
    /// of error and B is an index into a type-appropriate table (e.g. method references
    /// for a no-such-method error).
    Format20bc {
        a: u8,
        b: Index,
    },

    Format22x {
        a: u8,
        b: u16,
    },

    Format21t {
        a: u8,
        b: i16,
    },

    Format21s {
        a: u8,
        b: Index,
    },
    /// B register's format is special
    Format21h {
        a: u8,
        b: Index,
    },
    Format21c {
        a: u8,
        b: Index,
    },

    Format23x {
        a: u8,
        b: u8,
        c: u8,
    },
    Format22b {
        a: u8,
        b: u8,
        c: Index,
    },

    Format22t {
        a: u8,
        b: u8,
        c: i16,
    },

    Format22s {
        a: u8,
        b: u8,
        c: Index,
    },
    Format22c {
        a: u8,
        b: u8,
        c: Index,
    },

    // Format22cs: suggested format for statically linked field
    // access instructions of format 22c
    Format30t {
        a: i32,
    },

    Format32x {
        a: u16,
        b: u16,
    },

    Format31i {
        a: u8,
        b: Index,
    },

    Format31t {
        a: u8,
        b: i32,
    },

    Format31c {
        a: u8,
        b: Index,
    },

    Format35c {
        a: u32,
        b: Index, // reference
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
    },

    Format3rc {
        a: u8,
        b: Index,
        c: u16,
        regs: Range<u16>,
    },

    Format45cc {
        a: u8,
        b: Index,
        c: u8,
        d: u8,
        e: u8,
        f: u8,
        g: u8,
        h: Index,
    },

    Format4rcc {
        a: u8,
        b: Index,
        c: u16,
        h: Index,
        regs: Range<u16>,
    },
    Format51l {
        a: u8,
        b: Index,
    },
}

#[derive(Debug)]
pub enum Payload {
    PackedSwitch(PackedSwitch),
    SparseSwitch(SparseSwitch),
    FillArrayData(FillArrayData),
}

#[derive(Debug)]
pub struct Insn {
    pub opcode: &'static Opcode,
    pub range: Range<usize>,
    pub format: InsnFormat,
    pub payload: Option<Payload>,
}

type IFormatFactory = dyn Fn(&mut Cursor<&[u8]>, &mut Insn, IDexRef<'_>) -> Result<InsnFormat>;

pub struct Opcode {
    pub opcode: u8,
    pub name: &'static str,
    pub registers: u8,
    pub length: u8,
    pub format_factory: &'static IFormatFactory,
}

impl Debug for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Opcode{{val={:02x}, name={}, registers={}, length={}}}",
            self.opcode, self.name, self.registers, self.length
        )
    }
}

// REVISIT: is it possible to make this Sync?
unsafe impl Sync for Opcode {}

macro_rules! opcode {
    ($name:literal:= $_opcode_:literal impl $func:ident[len=$length:literal, reg=$registers:literal]) => {
        Opcode {
            opcode: $_opcode_,
            name: $name,
            registers: $registers,
            length: $length,
            format_factory: &$func,
        }
    };
    ($name:literal:= $_opcode_:literal impl $func:ident []) => {
        Opcode {
            opcode: $_opcode_,
            name: $name,
            registers: 0,
            length: 0,
            format_factory: &$func,
        }
    };

    ($_opcode_:literal) => {
        Opcode {
            opcode: $_opcode_,
            name: stringify!($_opcode_),
            registers: 0,
            length: 1,
            format_factory: &format_10x,
        }
    };
}

/* Notes on opcodes definitions:

The first identifier specifies the name of the opcode (it will be
stringified internally). Next, the opcode number is specified as
a [uByte], followed by a reference to the function implementation
of the opcode format. The last two numbers are essentially the
number of code units this opcode uses and the amount of registers
to allocate.

format := <name> ':=' <opcode> 'impl' <format-func> '[' 'use' len=<n>, 'reg'=<n> ']'

The format is designed to operate on an iterator of [USHort] values,
and will be used to parse the opcode's contents. For example,

pub fn format_00x(cursor: &mut Cursor<&'a [u8]>, insn: &mut Insn) -> Result<InsnFormat> {
    // parsing is done here
}

will parse opcodes using the format "00x" and update the instruction's
contents. The specified length can be used while parsing to validate
whether the format function has been used correctly. Additionally, the
number of registers used by the opcode must be specified to remove
the amount of unnecessary register allocations.
*/
pub const OPCODES: &[Opcode] = &[
    opcode! { "nop" := 0x00 impl format_10x [len=1, reg=0] },
    // move ops
    opcode! { "move"               := 0x01 impl format_12x[len=1, reg=2] },
    opcode! { "move/from16"        := 0x02 impl format_22x[len=2, reg=2] },
    opcode! { "move/16"            := 0x03 impl format_32x[len=3, reg=2] },
    opcode! { "move-wide"          := 0x04 impl format_12x[len=1, reg=2] },
    opcode! { "move-wide/from16"   := 0x05 impl format_22x[len=2, reg=2] },
    opcode! { "move-wide/16"       := 0x06 impl format_32x[len=3, reg=2] },
    opcode! { "move-object"        := 0x07 impl format_12x[len=1, reg=2] },
    opcode! { "move-object/from16" := 0x08 impl format_22x[len=2, reg=2] },
    opcode! { "move-object/16"     := 0x09 impl format_32x[len=3, reg=2] },
    opcode! { "move-result"        := 0x0A impl format_11x[len=1, reg=1] },
    opcode! { "move-result-wide"   := 0x0B impl format_11x[len=1, reg=1] },
    opcode! { "move-result-object" := 0x0C impl format_11x[len=1, reg=1] },
    opcode! { "move-exception"     := 0x0D impl format_11x[len=1, reg=1] },
    // returnops
    opcode! { "return-void"    := 0x0E impl format_10x[len=1, reg=0] },
    opcode! { "return"         := 0x0F impl format_11x[len=1, reg=1] },
    opcode! { "return-wide"    := 0x10 impl format_11x[len=1, reg=1] },
    opcode! { "return-object"  := 0x11 impl format_11x[len=1, reg=1] },
    // constops
    opcode! { "const/4"             := 0x12 impl format_11n[len=1, reg=2] },
    opcode! { "const/16"            := 0x13 impl format_21s[len=2, reg=2] },
    opcode! { "const"               := 0x14 impl format_31i[len=3, reg=2] },
    opcode! { "const/high16"        := 0x15 impl format_21h[len=2, reg=2] },
    opcode! { "const-wide/16"       := 0x16 impl format_21s[len=2, reg=2] },
    opcode! { "const-wide/32"       := 0x17 impl format_31i[len=3, reg=2] },
    opcode! { "const-wide"          := 0x18 impl format_51l[len=5, reg=2] },
    opcode! { "const-wide/high16"   := 0x19 impl format_21h[len=2, reg=2] },
    opcode! { "const-string"        := 0x1A impl format_21c[len=2, reg=2] },
    opcode! { "const-string/jumbo"  := 0x1B impl format_31c[len=3, reg=2] },
    opcode! { "const-class"         := 0x1C impl format_21c[len=2, reg=2] },
    // monitorops
    opcode! { "monitor-enter"   := 0x1D impl format_11x[len=1, reg=1] },
    opcode! { "monitor-exit"    := 0x1E impl format_11x[len=1, reg=1] },
    // (other ops)
    opcode! { "check-cast"   := 0x1F impl format_21c[len=2, reg=2] },
    opcode! { "instance-of"  := 0x20 impl format_22c[len=2, reg=2] },
    opcode! { "array-length" := 0x21 impl format_12x[len=1, reg=1] },
    // new-* ops
    opcode! { "new-instance"   := 0x22 impl format_21c[len=2, reg=2] },
    opcode! { "new-array"      := 0x23 impl format_22c[len=2, reg=2] },
    // filled-* ops
    opcode! { "filled-new-array"        := 0x24 impl format_35c[len=3, reg=7] },
    opcode! { "filled-new-array/range"  := 0x25 impl format_3rc[len=3, reg=2] },
    opcode! { "fill-array-data"         := 0x26 impl format_31t[len=3, reg=2] },
    // throw
    opcode! { "throw" := 0x27 impl format_11x[len=1, reg=1] },
    // goto
    opcode! { "goto"        := 0x28 impl format_10t[len=1, reg=1] },
    opcode! { "goto/16"     := 0x29 impl format_20t[len=2, reg=1] },
    opcode! { "goto/32"     := 0x2A impl format_30t[len=3, reg=1] },
    // branches
    opcode! { "packed-branch" := 0x2B impl format_31t[len=1, reg=1] },
    opcode! { "sparse-branch" := 0x2C impl format_31t[len=2, reg=1] },
    // comparisons
    opcode! { "cmpl-float"    := 0x2D impl format_23x[len=2, reg=3] },
    opcode! { "cmpg-float"    := 0x2E impl format_23x[len=2, reg=3] },
    opcode! { "cmpl-double"   := 0x2F impl format_23x[len=2, reg=3] },
    opcode! { "cmpg-double"   := 0x30 impl format_23x[len=2, reg=3] },
    opcode! { "cmp-long"      := 0x31 impl format_23x[len=2, reg=3] },
    // ifops
    opcode! { "if-eq"  := 0x32 impl format_22t[len=2, reg=3] },
    opcode! { "if-ne"  := 0x33 impl format_22t[len=2, reg=3] },
    opcode! { "if-lt"  := 0x34 impl format_22t[len=2, reg=3] },
    opcode! { "if-ge"  := 0x35 impl format_22t[len=2, reg=3] },
    opcode! { "if-gt"  := 0x36 impl format_22t[len=2, reg=3] },
    opcode! { "if-le"  := 0x37 impl format_22t[len=2, reg=3] },
    opcode! { "if-eqz" := 0x38 impl format_21t[len=2, reg=2] },
    opcode! { "if-nez" := 0x39 impl format_21t[len=2, reg=2] },
    opcode! { "if-ltz" := 0x3A impl format_21t[len=2, reg=2] },
    opcode! { "if-gez" := 0x3B impl format_21t[len=2, reg=2] },
    opcode! { "if-gtz" := 0x3C impl format_21t[len=2, reg=2] },
    opcode! { "if-lez" := 0x3D impl format_21t[len=2, reg=2] },
    // unused
    opcode!(0x3E),
    opcode!(0x3F),
    opcode!(0x40),
    opcode!(0x41),
    opcode!(0x42),
    opcode!(0x43),
    // arrayops
    opcode! { "aget"            := 0x44 impl format_23x[len=2, reg=3] },
    opcode! { "aget-wide"       := 0x45 impl format_23x[len=2, reg=3] },
    opcode! { "aget-object"     := 0x46 impl format_23x[len=2, reg=3] },
    opcode! { "aget-boolean"    := 0x47 impl format_23x[len=2, reg=3] },
    opcode! { "aget-byte"       := 0x48 impl format_23x[len=2, reg=3] },
    opcode! { "aget-char"       := 0x49 impl format_23x[len=2, reg=3] },
    opcode! { "aget-short"      := 0x4A impl format_23x[len=2, reg=3] },
    opcode! { "aput"            := 0x4B impl format_23x[len=2, reg=3] },
    opcode! { "aput-wide"       := 0x4C impl format_23x[len=2, reg=3] },
    opcode! { "aput-object"     := 0x4D impl format_23x[len=2, reg=3] },
    opcode! { "aput-boolean"    := 0x4E impl format_23x[len=2, reg=3] },
    opcode! { "aput-byte"       := 0x4F impl format_23x[len=2, reg=3] },
    opcode! { "aput-char"       := 0x50 impl format_23x[len=2, reg=3] },
    opcode! { "aput-short"      := 0x51 impl format_23x[len=2, reg=3] },
    // instanceops
    opcode! { "iget"            := 0x52 impl format_22c[len=2, reg=2] },
    opcode! { "iget-wide"       := 0x53 impl format_22c[len=2, reg=2] },
    opcode! { "iget-object"     := 0x54 impl format_22c[len=2, reg=2] },
    opcode! { "iget-boolean"    := 0x55 impl format_22c[len=2, reg=2] },
    opcode! { "iget-byte"       := 0x56 impl format_22c[len=2, reg=2] },
    opcode! { "iget-char"       := 0x57 impl format_22c[len=2, reg=2] },
    opcode! { "iget-short"      := 0x58 impl format_22c[len=2, reg=2] },
    opcode! { "iput"            := 0x59 impl format_22c[len=2, reg=2] },
    opcode! { "iput-wide"       := 0x5A impl format_22c[len=2, reg=2] },
    opcode! { "iput-object"     := 0x5B impl format_22c[len=2, reg=2] },
    opcode! { "iput-boolean"    := 0x5C impl format_22c[len=2, reg=2] },
    opcode! { "iput-byte"       := 0x5D impl format_22c[len=2, reg=2] },
    opcode! { "iput-char"       := 0x5E impl format_22c[len=2, reg=2] },
    opcode! { "iput-short"      := 0x5F impl format_22c[len=2, reg=2] },
    // staticops
    opcode! { "sget"            := 0x60 impl format_21c[len=2, reg=2] },
    opcode! { "sget-wide"       := 0x61 impl format_21c[len=2, reg=2] },
    opcode! { "sget-object"     := 0x62 impl format_21c[len=2, reg=2] },
    opcode! { "sget-boolean"    := 0x63 impl format_21c[len=2, reg=2] },
    opcode! { "sget-byte"       := 0x64 impl format_21c[len=2, reg=2] },
    opcode! { "sget-char"       := 0x65 impl format_21c[len=2, reg=2] },
    opcode! { "sget-short"      := 0x66 impl format_21c[len=2, reg=2] },
    opcode! { "sput"            := 0x67 impl format_21c[len=2, reg=2] },
    opcode! { "sput-wide"       := 0x68 impl format_21c[len=2, reg=2] },
    opcode! { "sput-object"     := 0x69 impl format_21c[len=2, reg=2] },
    opcode! { "sput-boolean"    := 0x6A impl format_21c[len=2, reg=2] },
    opcode! { "sput-byte"       := 0x6B impl format_21c[len=2, reg=2] },
    opcode! { "sput-char"       := 0x6C impl format_21c[len=2, reg=2] },
    opcode! { "sput-short"      := 0x6D impl format_21c[len=2, reg=2] },
    // invokeops
    opcode! { "invoke-virtual"   := 0x6E impl format_35c[len=3, reg=7] },
    opcode! { "invoke-super"     := 0x6F impl format_35c[len=3, reg=7] },
    opcode! { "invoke-direct"    := 0x70 impl format_35c[len=3, reg=7] },
    opcode! { "invoke-static"    := 0x71 impl format_35c[len=3, reg=7] },
    opcode! { "invoke-interface" := 0x72 impl format_35c[len=3, reg=7] },
    // unused
    opcode!(0x73),
    // invoke/range
    opcode! { "invoke-virtual/range"   := 0x74 impl format_3rc[len=3, reg=7] },
    opcode! { "invoke-super/range"     := 0x75 impl format_3rc[len=3, reg=7] },
    opcode! { "invoke-direct/range"    := 0x76 impl format_3rc[len=3, reg=7] },
    opcode! { "invoke-static/range"    := 0x77 impl format_3rc[len=3, reg=7] },
    opcode! { "invoke-interface/range" := 0x78 impl format_3rc[len=3, reg=7] },
    // unused
    opcode!(0x79),
    opcode!(0x7A),
    // unops
    opcode! { "neg-int"         := 0x7B impl format_12x[len=1, reg=2] },
    opcode! { "not-int"         := 0x7C impl format_12x[len=1, reg=2] },
    opcode! { "neg-long"        := 0x7D impl format_12x[len=1, reg=2] },
    opcode! { "not-long"        := 0x7E impl format_12x[len=1, reg=2] },
    opcode! { "neg-float"       := 0x7F impl format_12x[len=1, reg=2] },
    opcode! { "neg-double"      := 0x80 impl format_12x[len=1, reg=2] },
    opcode! { "int-to-long"     := 0x81 impl format_12x[len=1, reg=2] },
    opcode! { "int-to-float"    := 0x82 impl format_12x[len=1, reg=2] },
    opcode! { "int-to-double"   := 0x83 impl format_12x[len=1, reg=2] },
    opcode! { "long-to-int"     := 0x84 impl format_12x[len=1, reg=2] },
    opcode! { "long-to-float"   := 0x85 impl format_12x[len=1, reg=2] },
    opcode! { "long-to-double"  := 0x86 impl format_12x[len=1, reg=2] },
    opcode! { "float-to-int"    := 0x87 impl format_12x[len=1, reg=2] },
    opcode! { "float-to-long"   := 0x88 impl format_12x[len=1, reg=2] },
    opcode! { "float-to-double" := 0x89 impl format_12x[len=1, reg=2] },
    opcode! { "double-to-int"   := 0x8A impl format_12x[len=1, reg=2] },
    opcode! { "double-to-long"  := 0x8B impl format_12x[len=1, reg=2] },
    opcode! { "double-to-float" := 0x8C impl format_12x[len=1, reg=2] },
    opcode! { "int-to-byte"     := 0x8D impl format_12x[len=1, reg=2] },
    opcode! { "int-to-char"     := 0x8E impl format_12x[len=1, reg=2] },
    opcode! { "int-to-short"    := 0x8F impl format_12x[len=1, reg=2] },
    // binops
    opcode! { "add-int"     := 0x90 impl format_23x[len=2, reg=3] },
    opcode! { "sub-int"     := 0x91 impl format_23x[len=2, reg=3] },
    opcode! { "mul-int"     := 0x92 impl format_23x[len=2, reg=3] },
    opcode! { "div-int"     := 0x93 impl format_23x[len=2, reg=3] },
    opcode! { "rem-int"     := 0x94 impl format_23x[len=2, reg=3] },
    opcode! { "and-int"     := 0x95 impl format_23x[len=2, reg=3] },
    opcode! { "or-int"      := 0x96 impl format_23x[len=2, reg=3] },
    opcode! { "xor-int"     := 0x97 impl format_23x[len=2, reg=3] },
    opcode! { "shl-int"     := 0x98 impl format_23x[len=2, reg=3] },
    opcode! { "shr-int"     := 0x99 impl format_23x[len=2, reg=3] },
    opcode! { "ushr-int"    := 0x9A impl format_23x[len=2, reg=3] },
    opcode! { "add-long"    := 0x9B impl format_23x[len=2, reg=3] },
    opcode! { "sub-long"    := 0x9C impl format_23x[len=2, reg=3] },
    opcode! { "mul-long"    := 0x9D impl format_23x[len=2, reg=3] },
    opcode! { "div-long"    := 0x9E impl format_23x[len=2, reg=3] },
    opcode! { "rem-long"    := 0x9F impl format_23x[len=2, reg=3] },
    opcode! { "and-long"    := 0xA0 impl format_23x[len=2, reg=3] },
    opcode! { "or-long"     := 0xA1 impl format_23x[len=2, reg=3] },
    opcode! { "xor-long"    := 0xA2 impl format_23x[len=2, reg=3] },
    opcode! { "shl-long"    := 0xA3 impl format_23x[len=2, reg=3] },
    opcode! { "shr-long"    := 0xA4 impl format_23x[len=2, reg=3] },
    opcode! { "ushr-long"   := 0xA5 impl format_23x[len=2, reg=3] },
    opcode! { "add-float"   := 0xA6 impl format_23x[len=2, reg=3] },
    opcode! { "sub-float"   := 0xA7 impl format_23x[len=2, reg=3] },
    opcode! { "mul-float"   := 0xA8 impl format_23x[len=2, reg=3] },
    opcode! { "div-float"   := 0xA9 impl format_23x[len=2, reg=3] },
    opcode! { "rem-float"   := 0xAA impl format_23x[len=2, reg=3] },
    opcode! { "add-double"  := 0xAB impl format_23x[len=2, reg=3] },
    opcode! { "sub-double"  := 0xAC impl format_23x[len=2, reg=3] },
    opcode! { "mul-double"  := 0xAD impl format_23x[len=2, reg=3] },
    opcode! { "div-double"  := 0xAE impl format_23x[len=2, reg=3] },
    opcode! { "rem-double"  := 0xAF impl format_23x[len=2, reg=3] },
    // binops/2addr
    opcode! { "add-int/2addr"   := 0xB0 impl format_12x[len=1, reg=2] },
    opcode! { "sub-int/2addr"   := 0xB1 impl format_12x[len=1, reg=2] },
    opcode! { "mul-int/2addr"   := 0xB2 impl format_12x[len=1, reg=2] },
    opcode! { "div-int/2addr"   := 0xB3 impl format_12x[len=1, reg=2] },
    opcode! { "rem-int/2addr"   := 0xB4 impl format_12x[len=1, reg=2] },
    opcode! { "and-int/2addr"   := 0xB5 impl format_12x[len=1, reg=2] },
    opcode! { "or-int/2addr"    := 0xB6 impl format_12x[len=1, reg=2] },
    opcode! { "xor-int/2addr"   := 0xB7 impl format_12x[len=1, reg=2] },
    opcode! { "shl-int/2addr"   := 0xB8 impl format_12x[len=1, reg=2] },
    opcode! { "shr-int/2addr"   := 0xB9 impl format_12x[len=1, reg=2] },
    opcode! { "ushr-int/2addr"  := 0xBA impl format_12x[len=1, reg=2] },
    opcode! { "add-long/2addr"  := 0xBB impl format_12x[len=1, reg=2] },
    opcode! { "sub-long/2addr"  := 0xBC impl format_12x[len=1, reg=2] },
    opcode! { "mul-long/2addr"  := 0xBD impl format_12x[len=1, reg=2] },
    opcode! { "div-long/2addr"  := 0xBE impl format_12x[len=1, reg=2] },
    opcode! { "rem-long/2addr"  := 0xBF impl format_12x[len=1, reg=2] },
    opcode! { "and-long/2addr"  := 0xC0 impl format_12x[len=1, reg=2] },
    opcode! { "or-long/2addr"   := 0xC1 impl format_12x[len=1, reg=2] },
    opcode! { "xor-long/2addr"  := 0xC2 impl format_12x[len=1, reg=2] },
    opcode! { "shl-long/2addr"  := 0xC3 impl format_12x[len=1, reg=2] },
    opcode! { "shr-long/2addr"  := 0xC4 impl format_12x[len=1, reg=2] },
    opcode! { "ushr-long/2addr" := 0xC5 impl format_12x[len=1, reg=2] },
    opcode! { "add-float/2addr" := 0xC6 impl format_12x[len=1, reg=2] },
    opcode! { "sub-float/2addr" := 0xC7 impl format_12x[len=1, reg=2] },
    opcode! { "mul-float/2addr" := 0xC8 impl format_12x[len=1, reg=2] },
    opcode! { "div-float/2addr" := 0xC9 impl format_12x[len=1, reg=2] },
    opcode! { "rem-float/2addr" := 0xCA impl format_12x[len=1, reg=2] },
    opcode! { "add-double/2addr" := 0xCB impl format_12x[len=1, reg=2] },
    opcode! { "sub-double/2addr" := 0xCC impl format_12x[len=1, reg=2] },
    opcode! { "mul-double/2addr" := 0xCD impl format_12x[len=1, reg=2] },
    opcode! { "div-double/2addr" := 0xCE impl format_12x[len=1, reg=2] },
    opcode! { "rem-double/2addr" := 0xCF impl format_12x[len=1, reg=2] },
    // binops/lit16
    opcode! { "add-int/lit16"   := 0xD0 impl format_22s[len=2, reg=3] },
    opcode! { "rsub-int/lit16"  := 0xD1 impl format_22s[len=2, reg=3] },
    opcode! { "mul-int/lit16"   := 0xD2 impl format_22s[len=2, reg=3] },
    opcode! { "div-int/lit16"   := 0xD3 impl format_22s[len=2, reg=3] },
    opcode! { "rem-int/lit16"   := 0xD4 impl format_22s[len=2, reg=3] },
    opcode! { "and-int/lit16"   := 0xD5 impl format_22s[len=2, reg=3] },
    opcode! { "or-int/lit16"    := 0xD6 impl format_22s[len=2, reg=3] },
    opcode! { "xor-int/lit16"   := 0xD7 impl format_22s[len=2, reg=3] },
    // binops/lit8
    opcode! { "add-int/lit8"    := 0xD8 impl format_22b[len=2, reg=3] },
    opcode! { "rsub-int/lit8"   := 0xD9 impl format_22b[len=2, reg=3] },
    opcode! { "mul-int/lit8"    := 0xDA impl format_22b[len=2, reg=3] },
    opcode! { "div-int/lit8"    := 0xDB impl format_22b[len=2, reg=3] },
    opcode! { "rem-int/lit8"    := 0xDC impl format_22b[len=2, reg=3] },
    opcode! { "and-int/lit8"    := 0xDD impl format_22b[len=2, reg=3] },
    opcode! { "or-int/lit8"     := 0xDE impl format_22b[len=2, reg=3] },
    opcode! { "xor-int/lit8"    := 0xDF impl format_22b[len=2, reg=3] },
    opcode! { "shl-int/lit8"    := 0xE0 impl format_22b[len=2, reg=3] },
    opcode! { "shr-int/lit8"    := 0xE1 impl format_22b[len=2, reg=3] },
    opcode! { "ushr-int/lit8"   := 0xE2 impl format_22b[len=2, reg=3] },
    // (unused)
    opcode!(0xE3),
    opcode!(0xE4),
    opcode!(0xE5),
    opcode!(0xE6),
    opcode!(0xE7),
    opcode!(0xE8),
    opcode!(0xE9),
    opcode!(0xEA),
    opcode!(0xEB),
    opcode!(0xEC),
    opcode!(0xED),
    opcode!(0xEE),
    opcode!(0xEF),
    opcode!(0xF0),
    opcode!(0xF1),
    opcode!(0xF2),
    opcode!(0xF3),
    opcode!(0xF4),
    opcode!(0xF5),
    opcode!(0xF6),
    opcode!(0xF7),
    opcode!(0xF8),
    opcode!(0xF9),
    opcode! { "invoke-polymorphic"       := 0xFA impl format_45cc[len=4, reg=7] },
    opcode! { "invoke-polymorphic/range" := 0xFB impl format_4rcc[len=4, reg=7] },
    opcode! { "invoke-custom"            := 0xFC impl format_35c[len=4, reg=7] },
    opcode! { "invoke-custom/range"      := 0xFD impl format_3rc[len=4, reg=7] },
    opcode! { "const-method-handle"      := 0xFE impl format_21c[len=2, reg=2] },
    opcode! { "const-method-type"        := 0xFF impl format_21c[len=2, reg=2] },
];

/// pseudo-format used for unused opcodes; suggested for use as the nominal
/// format for a breakpoint opcode
pub fn format_00x<'a>(
    _: &mut Cursor<&'a [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    return Ok(InsnFormat::Format00x);
}

pub fn format_10x(
    code: &mut Cursor<&'_ [u8]>,
    insn: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let val = code.read_u16::<LittleEndian>()?;
    if val & 0xFF == 0 {
        match val {
            0x0100 => {
                packed_switch(code, insn)?;
            }
            0x0200 => {
                sparse_switch(code, insn)?;
            }
            0x0300 => {
                fill_array_data(code, insn)?;
            }
            _ => {}
        }
    }
    return Ok(InsnFormat::Format10x);
}

/// ID: 12x
/// Syntax: `op vA, vB`
/// Format: `B|A|op`
pub fn format_12x(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format12x {
        a: ((value & 0x0F00) >> 8) as u8,
        b: ((value & 0xF000) >> 12) as u8,
    });
}

/// ID: 11n
/// Syntax: `op vA, #+B`
/// Format: `B|A|op`
pub fn format_11n(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format11n {
        a: ((value & 0x0F00) >> 8) as u8,
        b: Index::Literal(((value & 0xF000) >> 12) as i64),
    });
}

/// ID: 11x
/// Syntax: `op vAA`
/// Format: `AA|op`
pub fn format_11x(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format11x {
        a: ((value & 0xFF00) >> 8) as u8,
    });
}

/// ID: 10t
/// Syntax: `op +AA`
/// Format: `AA|op`
pub fn format_10t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format10t {
        a: ((value & 0xFF00) >> 8) as i8,
    });
}

/// ID: 20t
/// Syntax: `op +AAAA`
/// Format: `||op AAAA`
pub fn format_20t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    code.seek(std::io::SeekFrom::Current(2))?;
    let format = InsnFormat::Format20t {
        a: code.read_i16::<LittleEndian>()?,
    };
    Ok(format)
}

/// ID: 20bc (unused)
/// Syntax: `op AA, kind@BBBB`
/// Format: `AA|op BBBB`
pub fn format_20bc(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let index_value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format20bc {
        a: ((value & 0xFF00) >> 8) as u8,
        b: Index::Unknown(index_value as u32),
    });
}

/// ID: 22x
/// Syntax: `op vAA, vBBBB`
/// Format: `AA|op BBBB`
pub fn format_22x(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format22x {
        a: ((value & 0xFF00) >> 8) as u8,
        b: code.read_u16::<LittleEndian>()? as u16,
    });
}

/// ID: 21t
/// Syntax: `op vAA, +BBBB`
/// Format: `AA|op BBBB`
pub fn format_21t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format21t {
        a: ((value & 0xFF00) >> 8) as u8,
        b: code.read_u16::<LittleEndian>()? as i16,
    });
}

/// ID: 21s
/// Syntax: `op vAA, #+BBBB`
/// Format: `AA|op BBBB`
pub fn format_21s(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    return Ok(InsnFormat::Format21s {
        a: ((value & 0xFF00) >> 8) as u8,
        b: Index::Literal(code.read_u16::<LittleEndian>()? as i64),
    });
}

/// ID: 21h
/// Syntax: `op vAA, #+BBBB0000`
/// Format: `AA|op BBBB`
pub fn format_21h(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let index_value = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format21h {
        a: ((value & 0xFF00) >> 8) as u8,
        b: match value & 0xFF {
            0x15 =>
            /* const/high16 */
            {
                Index::Literal((index_value as i64) << 16)
            }
            0x19 =>
            /* const-wide/high16 */
            {
                Index::Literal((index_value as i64) << 48)
            }
            _ => Index::Unknown(index_value as u32),
        },
    })
}

/// ID: 21c
/// Syntax: `op vAA, thing@BBBB`
/// Format: `AA|op BBBB`
pub fn format_21c(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let index_value = code.read_u16::<LittleEndian>()? as u32;
    let res = Ok(InsnFormat::Format21c {
        a: ((value & 0xFF00) >> 8) as u8,
        b: match value & 0xFF {
            0x1A =>
            /* const-string */
            {
                Index::String(dex.get_string(index_value)?)
            }
            0x1C | 0x60..=0x6d =>
            /* const-class */
            {
                Index::Field(dex.get_field(index_value)?)
            }
            0x1F | 0x22 =>
            /* check-cast | new-instance */
            {
                Index::Type(dex.get_type(index_value)?)
            }
            0xFE =>
            /* const-method-handle */
            {
                Index::MethodHandle(dex.get_method_handle(index_value)?)
            }
            0xFF =>
            /* const-method-type */
            {
                Index::Proto(dex.get_proto(index_value)?)
            }
            _ => Index::Unknown(index_value),
        },
    });
    res
}

/// ID: 23x
/// Syntax: `op vAA, vBB, vCC`
/// Format: `AA|op CC|BB`
pub fn format_23x(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let next = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format23x {
        a: ((value & 0xFF00) >> 8) as u8,
        b: (next & 0x00FF) as u8,
        c: ((next & 0xFF00) >> 8) as u8,
    })
}

/// ID: 22b
/// Syntax: `op vAA, vBB, +#CC`
/// Format: `AA|op CC|BB`
pub fn format_22b(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let next = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format22b {
        a: ((value & 0xFF00) >> 8) as u8,
        b: (next & 0x00FF) as u8,
        c: Index::Literal(((next & 0xFF00) >> 8) as i64),
    })
}

/// ID: 22t
/// Syntax: `op vA, vB, +CCCC`
/// Format: `B|A|op CCCCC`
pub fn format_22t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let next = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format22t {
        a: ((value & 0x0F00) >> 8) as u8,
        b: ((value & 0xF000) >> 12) as u8,
        c: next as i16,
    })
}

/// ID: 22s
/// Syntax: `op vA, vB, #+CCCC`
/// Format: `B|A|op CCCCC`
pub fn format_22s(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let next = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format22s {
        a: ((value & 0x0F00) >> 8) as u8,
        b: ((value & 0xF000) >> 12) as u8,
        c: Index::Literal(next as i64),
    })
}

/// ID: 22c
/// Syntax: `op vA, vB, thing@CCCC`
/// Format: `B|A|op CCCCC`
pub fn format_22c(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let next = code.read_u16::<LittleEndian>()?;
    Ok(InsnFormat::Format22c {
        a: ((value & 0x0F00) >> 8) as u8,
        b: ((value & 0xF000) >> 12) as u8,
        c: match value & 0xFF {
            0x20 /* instance-of */ => {
                Index::Type(dex.get_type(next as u32)?)
            }
            _=> {
                Index::Field(dex.get_field(next as u32)?)
            }
        },
    })
}

/// ID: 30t
/// Syntax: `op +AAAAAAAA`
/// Format: `||op AAAA_lo AAAA_hi`
pub fn format_30t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    code.seek(std::io::SeekFrom::Current(2))?;
    let format = InsnFormat::Format30t {
        // index 0 is where the opcode is stored
        a: code.read_i32::<LittleEndian>()?,
    };
    Ok(format)
}

/// ID: 32x
/// Syntax: `op vAAAA, vBBBB`
/// Format: `||op AAAA BBBB`
pub fn format_32x(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    code.seek(std::io::SeekFrom::Current(2))?;
    let format = InsnFormat::Format32x {
        a: code.read_u16::<LittleEndian>()?,
        b: code.read_u16::<LittleEndian>()?,
    };
    Ok(format)
}

/// ID: 31i
/// Syntax: `op vAA, #+BBBBBBBB`
/// Format: `AA|op BBBB_lo BBBB_hi`
pub fn format_31i(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let index = code.read_i32::<LittleEndian>()?;
    let format = InsnFormat::Format31i {
        a: ((value & 0xFF) >> 8) as u8,
        b: Index::Literal(index as i64),
    };
    Ok(format)
}

/// ID: 31t
/// Syntax: `op: vAA, +BBBBBBBB`
/// Format: `AA|op BBBB_lo BBBB_hi`
pub fn format_31t(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let b = code.read_i32::<LittleEndian>()?;
    let format = InsnFormat::Format31t {
        a: ((value & 0xFF) >> 8) as u8,
        b,
    };
    Ok(format)
}

/// ID: 31c
/// Syntax: `op vAA, string@BBBBBBBB`
/// Format: `AA|op BBBB_lo BBBB_hi`
pub fn format_31c(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    // note: same as 31i
    let a = code.read_u16::<LittleEndian>()?;
    let index = code.read_u32::<LittleEndian>()?;
    let format = InsnFormat::Format31c {
        a: ((a & 0xFF) >> 8) as u8,
        b: Index::String(dex.get_string(index)?),
    };
    Ok(format)
}

/// ID: 35c
/// Syntax: `op {vC, vD, vE, vF, vG}, ref@BBBB` (based on A)
/// Format: `A|G|op BBBB F|E|D|C`
pub fn format_35c(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let first = code.read_u16::<LittleEndian>()?;
    let second = code.read_u16::<LittleEndian>()?;
    let third = code.read_u16::<LittleEndian>()?;
    let fmt = InsnFormat::Format35c {
        a: ((first & 0xF000) >> 12) as u32,
        g: ((first & 0x0F00) >> 8) as u32,
        b: match first & 0x00FF {
            0x24 /* filled-new-array */ => {
                Index::Type(dex.get_type(second as u32)?)
            },
            0x6E..=0x72 /* invoke-kind */ => {
                Index::Method(dex.get_method(second as u32)?)
            },
            0xFC /* invoke-custom */ => {
                Index::CallSite(dex.get_call_site(second as u32)?)
            },
            _ => {
                Index::Unknown(second as u32)
            }
        },
        f: ((third & 0xF000) >> 12) as u32,
        e: ((third & 0x0F00) >> 8) as u32,
        d: ((third & 0x00F0) >> 4) as u32,
        c: (third & 0x000F) as u32,
    };
    Ok(fmt)
}

/// ID: 3rc
/// Syntax: `op {vCCCC .. vNNNN}, {vCCCC .. vNNNN}`
/// Format: `AA|op BBBB CCCC .. NNNN`
pub fn format_3rc(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value: u16 = code.read_u16::<LittleEndian>()?;
    let count = (value & 0xFF00) >> 8;
    let b: u16 = code.read_u16::<LittleEndian>()?;
    let c = code.read_u16::<LittleEndian>()?;

    let n = (c + count) - 1;
    let format = InsnFormat::Format3rc {
        a: count as u8,
        b: match value & 0xFF {
            0x25 /* filled-new-array/range */ => {
                Index::Type(dex.get_type(b as u32)?)
            },
            0x74..=0x78 /* invoke-kind/range */=> {
                Index::Method(dex.get_method(b as u32)?)
            },
            0xFD /* invoke-custom/range */ => {
                Index::CallSite(dex.get_call_site(b as u32)?)
            }
            _ => Index::Unknown(b as u32),
        },
        c,
        /* from AOSP:
        where NNNN = CCCC+AA-1, that is A determines the count 0..255, and C determines
        the first register.
         */
        regs: c..n,
    };
    Ok(format)
}

/// ID: 45cc
/// Syntax: `op {vC, vD, vE, vF, vG}, method@BBBB, prototype@HHHH`
/// Format: `A|G|op BBBB F|E|D|C HHHH`
pub fn format_45cc(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let value = code.read_u16::<LittleEndian>()?;
    let b: u16 = code.read_u16::<LittleEndian>()?;
    let v2 = code.read_u16::<LittleEndian>()?;
    let h: u16 = code.read_u16::<LittleEndian>()?;
    let format = InsnFormat::Format45cc {
        a: ((value & 0xF000) >> 12) as u8,
        g: ((value & 0x0F00) >> 8) as u8,
        b: Index::Method(dex.get_method(b as u32)?),
        f: ((v2 & 0xF000) >> 8) as u8,
        e: ((v2 & 0x0F00) >> 8) as u8,
        d: ((v2 & 0x00F0) >> 4) as u8,
        c: (v2 & 0x000F) as u8,
        h: Index::Proto(dex.get_proto(h as u32)?),
    };
    Ok(format)
}

/// ID: 4rcc
/// Syntax: `op {vCCCC .. vNNNN}, method@BBBB, prototype@HHHH`
/// AA|op BBBB CCCC HHHH
pub fn format_4rcc(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let count = (code.read_u16::<LittleEndian>()? & 0xFF00) >> 8;
    let b = code.read_u16::<LittleEndian>()?;
    let c = code.read_u16::<LittleEndian>()?;
    let h = code.read_u16::<LittleEndian>()?;
    let n = (c + count) - 1;
    let format = InsnFormat::Format4rcc {
        a: count as u8,
        b: Index::Method(dex.get_method(b as u32)?),
        c,
        regs: c..n,
        h: Index::Proto(dex.get_proto(h as u32)?),
    };
    Ok(format)
}

/// ID: 51l
/// Syntax: `op vAA, #+BBBBBBBBBBBBBBBB`
/// Format: `AA|op AAAA BBBB_lo BBBB BBBB BBBB_hi`
pub fn format_51l(
    code: &mut Cursor<&'_ [u8]>,
    _: &mut Insn,
    _dex: IDexRef<'_>,
) -> Result<InsnFormat> {
    let a = ((code.read_u16::<LittleEndian>()? & 0xF000) >> 12) as u8;
    let b = code.read_i64::<LittleEndian>()?;
    let format = InsnFormat::Format51l {
        a,
        b: Index::Literal(b),
    };
    Ok(format)
}

// payload implementation
pub fn packed_switch(code: &mut Cursor<&'_ [u8]>, insn: &mut Insn) -> Result<()> {
    let data = PackedSwitch::read(code)?;
    insn.payload = Some(Payload::PackedSwitch(data));
    Ok(())
}

pub fn sparse_switch(code: &mut Cursor<&'_ [u8]>, insn: &mut Insn) -> Result<()> {
    let data = SparseSwitch::read(code)?;
    insn.payload = Some(Payload::SparseSwitch(data));
    Ok(())
}

pub fn fill_array_data(code: &mut Cursor<&'_ [u8]>, insn: &mut Insn) -> Result<()> {
    // ident is already processed
    let data = FillArrayData::read(code)?;
    insn.payload = Some(Payload::FillArrayData(data));
    Ok(())
}

impl Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Index::Unknown(x) => write!(f, "<unresolved>{:#x}", x),
            Index::String(x) => write!(f, "{}", x),
            Index::Type(x) => write!(f, "{:?}", x),
            Index::Field(x) => write!(f, "{:?}", x),
            Index::Method(x) => write!(f, "{:?}", x),
            Index::MethodHandle(x) => write!(f, "{:?}", x),
            Index::Proto(x) => write!(f, "{:?}", x),
            Index::CallSite(x) => write!(f, "{:?}", x),
            Index::Literal(x) => write!(f, "{:#x}", x),
        }
    }
}
