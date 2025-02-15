use crate::{dex_err, error::DexError, Result};

pub struct Instruction<'a>(&'a [u16]);

impl<'a> Instruction<'a> {
    #[inline(always)]
    pub fn at(code: &[u16]) -> Instruction<'_> {
        Instruction(code)
    }

    pub fn raw(&self) -> &'a [u16] {
        self.0
    }

    #[inline]
    pub fn relative_at(&self, offset: usize) -> Result<Instruction<'a>> {
        if offset + 1 >= self.0.len() {
            return dex_err!(BadInstructionOffset {
                opcode: self.name(),
                offset: offset,
                size: self.0.len()
            });
        } else {
            Ok(Instruction::at(&self.0[offset..]))
        }
    }

    #[inline(always)]
    pub fn fetch16(&self, offset: usize) -> Result<u16> {
        if offset >= self.0.len() {
            return dex_err!(BadInstruction {
                opcode: self.name(),
                offset: offset,
                size: self.0.len(),
                target_type: "u16"
            });
        }
        Ok(self.0[offset])
    }

    #[inline(always)]
    pub fn fetch32(&self, offset: usize) -> Result<u32> {
        if offset >= self.0.len() {
            return dex_err!(BadInstruction {
                opcode: self.name(),
                offset: offset,
                size: self.0.len(),
                target_type: "u32"
            });
        }
        Ok(self.fetch16(offset)? as u32 | ((self.fetch16(offset + 1)? as u32) << 16))
    }

    const fn format_desc_of(opcode: Code) -> &'static InstructionDescriptor {
        &Instruction::INSN_DESCRIPTORS[opcode as usize]
    }

    pub const fn format_of(opcode: Code) -> &'static Format {
        &Instruction::format_desc_of(opcode).format
    }

    pub const fn index_type_of(opcode: Code) -> &'static IndexType {
        &Instruction::format_desc_of(opcode).index_type
    }

    pub const fn flags_of(opcode: Code) -> u8 {
        Instruction::format_desc_of(opcode).flags
    }

    pub const fn verify_flags_of(opcode: Code) -> u32 {
        Instruction::format_desc_of(opcode).verify_flags
    }

    pub const fn name_of(opcode: Code) -> &'static str {
        Instruction::format_desc_of(opcode).name
    }

    #[inline(always)]
    pub const fn opcode_of(inst_data: u16) -> Code {
        // this will always return a valid result as we are limiting the
        // input to 0xFF
        Instruction::INSN_DESCRIPTORS[(inst_data & 0xFF) as usize].opcode
    }

    #[inline]
    const fn code_size_in_code_units_by_opcode(opcode: Code, format: Format) -> u8 {
        let format_idx = format as u8;
        if opcode as u8 == Code::NOP as u8 {
            code_flags::Complex // will point to complex type
        } else if format_idx >= Format::k10x as u8 && format_idx <= Format::k10t as u8 {
            1
        } else if format_idx >= Format::k20t as u8 && format_idx <= Format::k22c as u8 {
            2
        } else if format_idx >= Format::k30t as u8 && format_idx <= Format::k3rc as u8 {
            3
        } else if format_idx >= Format::k45cc as u8 && format_idx <= Format::k4rcc as u8 {
            4
        } else if format_idx == Format::k51l as u8 {
            5
        } else {
            code_flags::Custom
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Format {
    k10x, // op
    k12x, // op vA, vB
    k11n, // op vA, #+B
    k11x, // op vAA
    k10t, // op +AA
    k20t, // op +AAAA
    k22x, // op vAA, vBBBB
    k21t, // op vAA, +BBBB
    k21s, // op vAA, #+BBBB
    k21h, // op vAA, #+BBBB00000[00000000]
    k21c, // op vAA, thing@BBBB
    k23x, // op vAA, vBB, vCC
    k22b, // op vAA, vBB, #+CC
    k22t, // op vA, vB, +CCCC
    k22s, // op vA, vB, #+CCCC
    k22c, // op vA, vB, thing@CCCC
    k32x, // op vAAAA, vBBBB
    k30t, // op +AAAAAAAA
    k31t, // op vAA, +BBBBBBBB
    k31i, // op vAA, #+BBBBBBBB
    k31c, // op vAA, thing@BBBBBBBB
    k35c, // op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
    k3rc, // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB

    // op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH (A: count)
    // format: AG op BBBB FEDC HHHH
    k45cc,

    // op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)
    // format: AA op BBBB CCCC HHHH
    k4rcc, // op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)

    k51l, // op vAA, #+BBBBBBBBBBBBBBBB
    kInvalidFormat,
}

pub enum IndexType {
    Unknown = 0,
    None,              // has no index
    TypeRef,           // type reference index
    StringRef,         // string reference index
    MethodRef,         // method reference index
    FieldRef,          // field reference index
    MethodAndProtoRef, // method and a proto reference index (for invoke-polymorphic)
    CallSiteRef,       // call site reference index
    MethodHandleRef,   // constant method handle reference index
    ProtoRef,          // prototype reference index
}

#[rustfmt::skip]
#[allow(non_upper_case_globals)]
pub mod code_flags {
    pub const Complex: u8 = 0xFF;
    pub const Custom: u8  = 0xFE;
}

#[rustfmt::skip]
#[allow(non_upper_case_globals)]
pub mod signatures {
    pub const PackedSwitchSignature: u16     = 0x0100;
    pub const SparseSwitchSignature: u16     = 0x0200;
    pub const ArrayDataSignature: u16        = 0x0300;
}
#[rustfmt::skip]
#[allow(non_upper_case_globals)]
pub mod flags {
    pub const Branch: u8              = 0x01;  // conditional or unconditional branch
    pub const Continue: u8            = 0x02;  // flow can continue to next statement
    pub const Switch: u8              = 0x04;  // switch statement
    pub const Throw: u8               = 0x08;  // could cause an exception to be thrown
    pub const Return: u8              = 0x10;  // returns, no additional statements
    pub const Invoke: u8              = 0x20;  // a flavor of invoke
    pub const Unconditional: u8       = 0x40;  // unconditional branch
    pub const Experimental: u8        = 0x80;  // is an experimental opcode
}

// These flags may be used later to verify instructions
#[rustfmt::skip]
#[allow(non_upper_case_globals)]
pub mod verify_flags {
    pub const VerifyNothing: u32            = 0x0000000;
    pub const VerifyRegA: u32               = 0x0000001;
    pub const VerifyRegAWide: u32           = 0x0000002;
    pub const VerifyRegB: u32               = 0x0000004;
    pub const VerifyRegBField: u32          = 0x0000008;
    pub const VerifyRegBMethod: u32         = 0x0000010;
    pub const VerifyRegBNewInstance: u32    = 0x0000020;
    pub const VerifyRegBString: u32         = 0x0000040;
    pub const VerifyRegBType: u32           = 0x0000080;
    pub const VerifyRegBWide: u32           = 0x0000100;
    pub const VerifyRegC: u32               = 0x0000200;
    pub const VerifyRegCField: u32          = 0x0000400;
    pub const VerifyRegCNewArray: u32       = 0x0000800;
    pub const VerifyRegCType: u32           = 0x0001000;
    pub const VerifyRegCWide: u32           = 0x0002000;
    pub const VerifyArrayData: u32          = 0x0004000;
    pub const VerifyBranchTarget: u32       = 0x0008000;
    pub const VerifySwitchTargets: u32      = 0x0010000;
    pub const VerifyVarArg: u32             = 0x0020000;
    pub const VerifyVarArgNonZero: u32      = 0x0040000;
    pub const VerifyVarArgRange: u32        = 0x0080000;
    pub const VerifyVarArgRangeNonZero: u32 = 0x0100000;
    pub const VerifyError: u32              = 0x0200000;
    pub const VerifyRegHPrototype: u32      = 0x0400000;
    pub const VerifyRegBCallSite: u32       = 0x0800000;
    pub const VerifyRegBMethodHandle: u32   = 0x1000000;
    pub const VerifyRegBPrototype: u32      = 0x2000000;
}

impl<'a> Instruction<'a> {
    #[inline(always)]
    const fn format_desc(&self) -> &'static InstructionDescriptor {
        &Instruction::INSN_DESCRIPTORS[(self.0[0] & 0xFF) as usize]
    }

    #[inline(always)]
    pub const fn opcode(&self) -> Code {
        self.format_desc().opcode
    }

    #[inline(always)]
    pub const fn format(&self) -> &'static Format {
        &self.format_desc().format
    }

    #[inline(always)]
    pub const fn name(&self) -> &'static str {
        &self.format_desc().name
    }

    pub fn next(&self) -> Result<Instruction<'a>> {
        self.relative_at(self.size_in_code_units())
    }

    #[inline(always)]
    pub fn size_in_code_units(&self) -> usize {
        let size = Instruction::format_desc_of(self.opcode()).size_in_code_units;
        match size {
            code_flags::Complex => self.size_in_code_units_complex().unwrap_or(1),
            code_flags::Custom => 1, /* TODO? */
            _ => size as usize,
        }
    }

    pub fn size_in_code_units_complex(&self) -> Result<usize> {
        let inst_data = self.fetch16(0)?;
        debug_assert!(inst_data & 0xFF == 0);
        Ok(match inst_data {
            signatures::PackedSwitchSignature => 4 + self.fetch16(1)? as usize * 2,
            signatures::SparseSwitchSignature => 2 + self.fetch16(1)? as usize * 4,
            signatures::ArrayDataSignature => {
                let element_size = self.fetch16(1)? as usize;
                let length = self.fetch32(2)? as usize;
                // The plus 1 is to round up for odd size and width.
                4 + (element_size * length + 1) / 2
            }
            _ => 1,
        })
    }

    pub fn verify_flags(&self) -> u32 {
        Instruction::verify_flags_of(self.opcode())
    }
}

pub struct VarArgs {
    pub count: u8,
    pub arg: Vec<u8>,
}

impl VarArgs {
    pub fn new(count: u8) -> VarArgs {
        VarArgs {
            count,
            arg: vec![0; count as usize],
        }
    }
}
// access to registers of all formats
#[allow(non_snake_case)]
pub mod vreg {

    use std::ops::RangeInclusive;

    use super::*;
    use crate::{dex_err, error::DexError, Result};

    // AA|op ...
    fn inst_aa(inst: &Instruction<'_>) -> Result<u8> {
        Ok((inst.fetch16(0)? >> 8) as u8)
    }

    // B|A|op ...
    fn inst_a(inst: &Instruction<'_>) -> Result<u8> {
        Ok((inst.fetch16(0)? >> 8) as u8 & 0x0F)
    }

    // B|A|op ...
    fn inst_b(inst: &Instruction<'_>) -> Result<u8> {
        Ok((inst.fetch16(0)? >> 12) as u8)
    }

    //------------------------------------------------------------------------------
    // VRegA
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_a(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k10t
            | Format::k10x
            | Format::k11n
            | Format::k11x
            | Format::k12x
            | Format::k20t
            | Format::k21c
            | Format::k21h
            | Format::k21s
            | Format::k21t
            | Format::k22b
            | Format::k22c
            | Format::k22s
            | Format::k22t
            | Format::k22x
            | Format::k23x
            | Format::k30t
            | Format::k31c
            | Format::k31i
            | Format::k31t
            | Format::k32x
            | Format::k35c
            | Format::k3rc
            | Format::k45cc
            | Format::k4rcc
            | Format::k51l => true,
            _ => false,
        }
    }

    #[inline]
    pub fn A(inst: &Instruction<'_>) -> Result<i32> {
        Ok(match inst.format() {
            // AA|op
            Format::k10t
            | Format::k10x
            | Format::k11x
            | Format::k21c
            | Format::k21h
            | Format::k21s
            | Format::k21t
            | Format::k22b
            | Format::k22x
            | Format::k23x
            | Format::k31c
            | Format::k31i
            | Format::k31t
            | Format::k3rc
            | Format::k51l
            | Format::k4rcc => inst_aa(inst)? as i32,
            // B|A|op
            Format::k11n | Format::k12x | Format::k22c | Format::k22s | Format::k22t => {
                inst_a(inst)? as i32
            }
            // op AAAA
            Format::k32x | Format::k20t => inst.fetch16(1)? as i32,
            // op AAAAAAAA
            Format::k30t => inst.fetch32(1)? as i32,
            // A|G|op
            Format::k35c | Format::k45cc => inst_b(inst)? as i32,
            _ => {
                return dex_err!(OperandAccessError {
                    insn_name: inst.name(),
                    operand: "A"
                })
            }
        })
    }

    //------------------------------------------------------------------------------
    // VRegB
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_b(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k11n
            | Format::k12x
            | Format::k21c
            | Format::k21h
            | Format::k21s
            | Format::k21t
            | Format::k22b
            | Format::k22c
            | Format::k22s
            | Format::k22t
            | Format::k22x
            | Format::k23x
            | Format::k31c
            | Format::k31i
            | Format::k31t
            | Format::k32x
            | Format::k35c
            | Format::k3rc
            | Format::k45cc
            | Format::k4rcc
            | Format::k51l => true,
            _ => false,
        }
    }

    pub fn has_wide_b(inst: &Instruction<'_>) -> bool {
        *inst.format() == Format::k51l
    }

    #[inline]
    pub fn wide_b(inst: &Instruction<'_>) -> Result<u64> {
        debug_assert!(*inst.format() == Format::k51l);
        Ok(inst.fetch32(1)? as u64 | ((inst.fetch32(3)? as u64) << 32))
    }

    #[inline]
    pub fn B(inst: &Instruction<'_>) -> Result<i32> {
        Ok(match inst.format() {
            // B|A|op with #+B
            Format::k11n => ((inst_b(inst)? as i32) << 28) >> 28,
            // op BBBB
            Format::k21c
            | Format::k21t
            | Format::k21s
            | Format::k21h
            | Format::k22x
            | Format::k35c
            | Format::k3rc
            | Format::k45cc
            | Format::k4rcc => inst.fetch16(1)? as i32,
            // B|A|op
            Format::k12x | Format::k22c | Format::k22s | Format::k22t => inst_b(inst)? as i32,
            // op CC|BB
            Format::k22b | Format::k23x => (inst.fetch16(1)? & 0xFF) as i32,
            // op BBBBBBBB
            Format::k31c | Format::k31i | Format::k31t => inst.fetch32(1)? as i32,
            // op AAAA BBBB
            Format::k32x => inst.fetch16(2)? as i32,
            // op BBBBBBBBBBBBBBBBB
            Format::k51l => wide_b(inst)? as i32,
            _ => {
                return dex_err!(OperandAccessError {
                    insn_name: inst.name(),
                    operand: "B"
                })
            }
        })
    }

    //------------------------------------------------------------------------------
    // VRegC
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_c(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k22b
            | Format::k22c
            | Format::k22s
            | Format::k22t
            | Format::k23x
            | Format::k35c
            | Format::k3rc
            | Format::k45cc
            | Format::k4rcc => true,
            _ => false,
        }
    }

    #[inline]
    pub fn C(inst: &Instruction<'_>) -> Result<i32> {
        Ok(match inst.format() {
            // op CCCC
            Format::k22c | Format::k22s | Format::k22t => inst.fetch16(1)? as i32,
            // op CC|BB
            Format::k22b | Format::k23x => ((inst.fetch16(1)? >> 8) & 0xFF) as i32,
            // op BBBB CCCC
            Format::k3rc | Format::k4rcc => inst.fetch16(2)? as i32,
            // op BBBB HH|CC
            Format::k35c | Format::k45cc => (inst.fetch16(2)? & 0x0F) as i32,
            _ => {
                return dex_err!(OperandAccessError {
                    insn_name: inst.name(),
                    operand: "C"
                })
            }
        })
    }

    //------------------------------------------------------------------------------
    // VRegH
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_h(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k45cc | Format::k4rcc => true,
            _ => false,
        }
    }

    #[inline]
    pub fn H(inst: &Instruction<'_>) -> Result<i32> {
        Ok(match &inst.format_desc().format {
            Format::k45cc | Format::k4rcc => inst.fetch16(3)? as i32,
            _ => {
                return dex_err!(OperandAccessError {
                    insn_name: inst.name(),
                    operand: "H"
                })
            }
        })
    }

    //------------------------------------------------------------------------------
    // VarArgs
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_var_args(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k35c | Format::k45cc => true,
            _ => false,
        }
    }

    #[inline]
    pub fn var_args(inst: &Instruction<'_>) -> Result<VarArgs> {
        let reg_list = inst.fetch16(2)?;
        let count = inst_b(inst)?;
        let mut var_args = VarArgs::new(count);

        // NOTE only five as maximum
        if count > 5 {
            return dex_err!(InvalidArgCount {
                opcode: inst.name(),
                format: inst.format(),
                count
            });
        }

        if count > 4 {
            var_args.arg[4] = inst_a(inst)?;
        }
        if count > 3 {
            var_args.arg[3] = ((reg_list >> 12) & 0x0F) as u8;
        }
        if count > 2 {
            var_args.arg[2] = ((reg_list >> 8) & 0x0F) as u8;
        }
        if count > 1 {
            var_args.arg[1] = ((reg_list >> 4) & 0x0F) as u8;
        }
        if count > 0 {
            var_args.arg[0] = (reg_list & 0x0F) as u8;
        }
        Ok(var_args)
    }

    //------------------------------------------------------------------------------
    // ArgsRange
    //------------------------------------------------------------------------------
    #[inline]
    pub fn has_args_range(inst: &Instruction<'_>) -> bool {
        match &inst.format_desc().format {
            Format::k3rc | Format::k4rcc => true,
            _ => false,
        }
    }

    pub fn args_range(inst: &Instruction<'_>) -> Result<RangeInclusive<u16>> {
        let first_reg = vreg::C(inst)? as u16;
        let last_reg = vreg::A(inst)? as u16;
        if last_reg == 0 || first_reg as usize + last_reg as usize > u16::MAX as usize {
            return dex_err!(InvalidArgRange {
                opcode: inst.name(),
                format: inst.format(),
                start: first_reg,
                end: last_reg
            });
        }
        Ok(first_reg..=(first_reg + last_reg - 1))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
// instruction descriptors
////////////////////////////////////////////////////////////////////////////////////////////////////////////
pub struct InstructionDescriptor {
    pub name: &'static str,
    pub format: Format,
    pub index_type: IndexType,
    pub flags: u8,
    pub size_in_code_units: u8,
    pub opcode: Code,
    pub verify_flags: u32,
}

macro_rules! insn_desc_table {
    ($({$code:ident, $name:literal, $format:ident, $idx_ty:ident, $flags:expr, $verify_flags:expr},)*) => {
        impl Instruction<'_> {
            const INSN_DESCRIPTORS: &'static [InstructionDescriptor] = &[
                $(InstructionDescriptor {
                    name: $name,
                    format: Format::$format,
                    index_type: IndexType::$idx_ty,
                    flags: $flags,
                    size_in_code_units: Instruction::code_size_in_code_units_by_opcode(Code::$code, Format::$format),
                    opcode: Code::$code,
                    verify_flags: $verify_flags
                },)*
            ];
        }

        #[repr(u8)]
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum Code {
            $($code,)*
        }
    };
}
insn_desc_table!(
 /* 0x00 */ {NOP,  "nop", k10x, None,  flags::Continue,  verify_flags::VerifyNothing},
 /* 0x01 */ {MOVE,  "move", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x02 */ {MOVE_FROM16,  "move/from16", k22x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x03 */ {MOVE_16,  "move/16", k32x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x04 */ {MOVE_WIDE,  "move-wide", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x05 */ {MOVE_WIDE_FROM16,  "move-wide/from16", k22x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x06 */ {MOVE_WIDE_16,  "move-wide/16", k32x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x07 */ {MOVE_OBJECT,  "move-object", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x08 */ {MOVE_OBJECT_FROM16,  "move-object/from16", k22x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x09 */ {MOVE_OBJECT_16,  "move-object/16", k32x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x0a */ {MOVE_RESULT,  "move-result", k11x, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x0b */ {MOVE_RESULT_WIDE,  "move-result-wide", k11x, None,  flags::Continue,  verify_flags::VerifyRegAWide},
 /* 0x0c */ {MOVE_RESULT_OBJECT,  "move-result-object", k11x, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x0d */ {MOVE_EXCEPTION,  "move-exception", k11x, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x0e */ {RETURN_VOID,  "return-void", k10x, None,  flags::Return,  verify_flags::VerifyNothing},
 /* 0x0f */ {RETURN,  "return", k11x, None,  flags::Return,  verify_flags::VerifyRegA},
 /* 0x10 */ {RETURN_WIDE,  "return-wide", k11x, None,  flags::Return,  verify_flags::VerifyRegAWide},
 /* 0x11 */ {RETURN_OBJECT,  "return-object", k11x, None,  flags::Return,  verify_flags::VerifyRegA},
 /* 0x12 */ {CONST_4,  "const/4", k11n, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x13 */ {CONST_16,  "const/16", k21s, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x14 */ {CONST,  "const", k31i, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x15 */ {CONST_HIGH16,  "const/high16", k21h, None,  flags::Continue,  verify_flags::VerifyRegA},
 /* 0x16 */ {CONST_WIDE_16,  "const-wide/16", k21s, None,  flags::Continue,  verify_flags::VerifyRegAWide},
 /* 0x17 */ {CONST_WIDE_32,  "const-wide/32", k31i, None,  flags::Continue,  verify_flags::VerifyRegAWide},
 /* 0x18 */ {CONST_WIDE,  "const-wide", k51l, None,  flags::Continue,  verify_flags::VerifyRegAWide},
 /* 0x19 */ {CONST_WIDE_HIGH16,  "const-wide/high16", k21h, None,  flags::Continue,  verify_flags::VerifyRegAWide},
 /* 0x1a */ {CONST_STRING,  "const-string", k21c, StringRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBString},
 /* 0x1b */ {CONST_STRING_JUMBO,  "const-string/jumbo", k31c, StringRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBString},
 /* 0x1c */ {CONST_CLASS,  "const-class", k21c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBType},
 /* 0x1d */ {MONITOR_ENTER,  "monitor-enter", k11x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA},
 /* 0x1e */ {MONITOR_EXIT,  "monitor-exit", k11x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA},
 /* 0x1f */ {CHECK_CAST,  "check-cast", k21c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBType},
 /* 0x20 */ {INSTANCE_OF,  "instance-of", k22c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCType},
 /* 0x21 */ {ARRAY_LENGTH,  "array-length", k12x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x22 */ {NEW_INSTANCE,  "new-instance", k21c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBNewInstance},
 /* 0x23 */ {NEW_ARRAY,  "new-array", k22c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCNewArray},
 /* 0x24 */ {FILLED_NEW_ARRAY,  "filled-new-array", k35c, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegBType | verify_flags::VerifyVarArg},
 /* 0x25 */ {FILLED_NEW_ARRAY_RANGE,  "filled-new-array/range", k3rc, TypeRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegBType | verify_flags::VerifyVarArgRange},
 /* 0x26 */ {FILL_ARRAY_DATA,  "fill-array-data", k31t, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyArrayData},
 /* 0x27 */ {THROW,  "throw", k11x, None,  flags::Throw,  verify_flags::VerifyRegA},
 /* 0x28 */ {GOTO,  "goto", k10t, None,  flags::Branch | flags::Unconditional,  verify_flags::VerifyBranchTarget},
 /* 0x29 */ {GOTO_16,  "goto/16", k20t, None,  flags::Branch | flags::Unconditional,  verify_flags::VerifyBranchTarget},
 /* 0x2a */ {GOTO_32,  "goto/32", k30t, None,  flags::Branch | flags::Unconditional,  verify_flags::VerifyBranchTarget},
 /* 0x2b */ {PACKED_SWITCH,  "packed-switch", k31t, None,  flags::Continue | flags::Switch,  verify_flags::VerifyRegA | verify_flags::VerifySwitchTargets},
 /* 0x2c */ {SPARSE_SWITCH,  "sparse-switch", k31t, None,  flags::Continue | flags::Switch,  verify_flags::VerifyRegA | verify_flags::VerifySwitchTargets},
 /* 0x2d */ {CMPL_FLOAT,  "cmpl-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x2e */ {CMPG_FLOAT,  "cmpg-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x2f */ {CMPL_DOUBLE,  "cmpl-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x30 */ {CMPG_DOUBLE,  "cmpg-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x31 */ {CMP_LONG,  "cmp-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x32 */ {IF_EQ,  "if-eq", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x33 */ {IF_NE,  "if-ne", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x34 */ {IF_LT,  "if-lt", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x35 */ {IF_GE,  "if-ge", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x36 */ {IF_GT,  "if-gt", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x37 */ {IF_LE,  "if-le", k22t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyBranchTarget},
 /* 0x38 */ {IF_EQZ,  "if-eqz", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x39 */ {IF_NEZ,  "if-nez", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x3a */ {IF_LTZ,  "if-ltz", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x3b */ {IF_GEZ,  "if-gez", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x3c */ {IF_GTZ,  "if-gtz", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x3d */ {IF_LEZ,  "if-lez", k21t, None,  flags::Continue | flags::Branch,  verify_flags::VerifyRegA | verify_flags::VerifyBranchTarget},
 /* 0x3e */ {UNUSED_3E,  "unused-3e", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x3f */ {UNUSED_3F,  "unused-3f", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x40 */ {UNUSED_40,  "unused-40", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x41 */ {UNUSED_41,  "unused-41", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x42 */ {UNUSED_42,  "unused-42", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x43 */ {UNUSED_43,  "unused-43", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x44 */ {AGET,  "aget", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x45 */ {AGET_WIDE,  "aget-wide", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x46 */ {AGET_OBJECT,  "aget-object", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x47 */ {AGET_BOOLEAN,  "aget-boolean", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x48 */ {AGET_BYTE,  "aget-byte", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x49 */ {AGET_CHAR,  "aget-char", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4a */ {AGET_SHORT,  "aget-short", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4b */ {APUT,  "aput", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4c */ {APUT_WIDE,  "aput-wide", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4d */ {APUT_OBJECT,  "aput-object", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4e */ {APUT_BOOLEAN,  "aput-boolean", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x4f */ {APUT_BYTE,  "aput-byte", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x50 */ {APUT_CHAR,  "aput-char", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x51 */ {APUT_SHORT,  "aput-short", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x52 */ {IGET,  "iget", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x53 */ {IGET_WIDE,  "iget-wide", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x54 */ {IGET_OBJECT,  "iget-object", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x55 */ {IGET_BOOLEAN,  "iget-boolean", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x56 */ {IGET_BYTE,  "iget-byte", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x57 */ {IGET_CHAR,  "iget-char", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x58 */ {IGET_SHORT,  "iget-short", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x59 */ {IPUT,  "iput", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5a */ {IPUT_WIDE,  "iput-wide", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5b */ {IPUT_OBJECT,  "iput-object", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5c */ {IPUT_BOOLEAN,  "iput-boolean", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5d */ {IPUT_BYTE,  "iput-byte", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5e */ {IPUT_CHAR,  "iput-char", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x5f */ {IPUT_SHORT,  "iput-short", k22c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegCField},
 /* 0x60 */ {SGET,  "sget", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x61 */ {SGET_WIDE,  "sget-wide", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBField},
 /* 0x62 */ {SGET_OBJECT,  "sget-object", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x63 */ {SGET_BOOLEAN,  "sget-boolean", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x64 */ {SGET_BYTE,  "sget-byte", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x65 */ {SGET_CHAR,  "sget-char", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x66 */ {SGET_SHORT,  "sget-short", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x67 */ {SPUT,  "sput", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x68 */ {SPUT_WIDE,  "sput-wide", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBField},
 /* 0x69 */ {SPUT_OBJECT,  "sput-object", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x6a */ {SPUT_BOOLEAN,  "sput-boolean", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x6b */ {SPUT_BYTE,  "sput-byte", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x6c */ {SPUT_CHAR,  "sput-char", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x6d */ {SPUT_SHORT,  "sput-short", k21c, FieldRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBField},
 /* 0x6e */ {INVOKE_VIRTUAL,  "invoke-virtual", k35c, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgNonZero},
 /* 0x6f */ {INVOKE_SUPER,  "invoke-super", k35c, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgNonZero},
 /* 0x70 */ {INVOKE_DIRECT,  "invoke-direct", k35c, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgNonZero},
 /* 0x71 */ {INVOKE_STATIC,  "invoke-static", k35c, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArg},
 /* 0x72 */ {INVOKE_INTERFACE,  "invoke-interface", k35c, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgNonZero},
 /* 0x73 */ {UNUSED_73,  "unused-73", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x74 */ {INVOKE_VIRTUAL_RANGE,  "invoke-virtual/range", k3rc, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRangeNonZero},
 /* 0x75 */ {INVOKE_SUPER_RANGE,  "invoke-super/range", k3rc, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRangeNonZero},
 /* 0x76 */ {INVOKE_DIRECT_RANGE,  "invoke-direct/range", k3rc, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRangeNonZero},
 /* 0x77 */ {INVOKE_STATIC_RANGE,  "invoke-static/range", k3rc, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRange},
 /* 0x78 */ {INVOKE_INTERFACE_RANGE,  "invoke-interface/range", k3rc, MethodRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRangeNonZero},
 /* 0x79 */ {UNUSED_79,  "unused-79", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x7a */ {UNUSED_7A,  "unused-7a", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0x7b */ {NEG_INT,  "neg-int", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x7c */ {NOT_INT,  "not-int", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x7d */ {NEG_LONG,  "neg-long", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x7e */ {NOT_LONG,  "not-long", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x7f */ {NEG_FLOAT,  "neg-float", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x80 */ {NEG_DOUBLE,  "neg-double", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x81 */ {INT_TO_LONG,  "int-to-long", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0x82 */ {INT_TO_FLOAT,  "int-to-float", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x83 */ {INT_TO_DOUBLE,  "int-to-double", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0x84 */ {LONG_TO_INT,  "long-to-int", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide},
 /* 0x85 */ {LONG_TO_FLOAT,  "long-to-float", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide},
 /* 0x86 */ {LONG_TO_DOUBLE,  "long-to-double", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x87 */ {FLOAT_TO_INT,  "float-to-int", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x88 */ {FLOAT_TO_LONG,  "float-to-long", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0x89 */ {FLOAT_TO_DOUBLE,  "float-to-double", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0x8a */ {DOUBLE_TO_INT,  "double-to-int", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide},
 /* 0x8b */ {DOUBLE_TO_LONG,  "double-to-long", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0x8c */ {DOUBLE_TO_FLOAT,  "double-to-float", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegBWide},
 /* 0x8d */ {INT_TO_BYTE,  "int-to-byte", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x8e */ {INT_TO_CHAR,  "int-to-char", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x8f */ {INT_TO_SHORT,  "int-to-short", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0x90 */ {ADD_INT,  "add-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x91 */ {SUB_INT,  "sub-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x92 */ {MUL_INT,  "mul-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x93 */ {DIV_INT,  "div-int", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x94 */ {REM_INT,  "rem-int", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x95 */ {AND_INT,  "and-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x96 */ {OR_INT,  "or-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x97 */ {XOR_INT,  "xor-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x98 */ {SHL_INT,  "shl-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x99 */ {SHR_INT,  "shr-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x9a */ {USHR_INT,  "ushr-int", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0x9b */ {ADD_LONG,  "add-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x9c */ {SUB_LONG,  "sub-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x9d */ {MUL_LONG,  "mul-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x9e */ {DIV_LONG,  "div-long", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0x9f */ {REM_LONG,  "rem-long", k23x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xa0 */ {AND_LONG,  "and-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xa1 */ {OR_LONG,  "or-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xa2 */ {XOR_LONG,  "xor-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xa3 */ {SHL_LONG,  "shl-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegC},
 /* 0xa4 */ {SHR_LONG,  "shr-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegC},
 /* 0xa5 */ {USHR_LONG,  "ushr-long", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegC},
 /* 0xa6 */ {ADD_FLOAT,  "add-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0xa7 */ {SUB_FLOAT,  "sub-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0xa8 */ {MUL_FLOAT,  "mul-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0xa9 */ {DIV_FLOAT,  "div-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0xaa */ {REM_FLOAT,  "rem-float", k23x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB | verify_flags::VerifyRegC},
 /* 0xab */ {ADD_DOUBLE,  "add-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xac */ {SUB_DOUBLE,  "sub-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xad */ {MUL_DOUBLE,  "mul-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xae */ {DIV_DOUBLE,  "div-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xaf */ {REM_DOUBLE,  "rem-double", k23x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide | verify_flags::VerifyRegCWide},
 /* 0xb0 */ {ADD_INT_2ADDR,  "add-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb1 */ {SUB_INT_2ADDR,  "sub-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb2 */ {MUL_INT_2ADDR,  "mul-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb3 */ {DIV_INT_2ADDR,  "div-int/2addr", k12x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb4 */ {REM_INT_2ADDR,  "rem-int/2addr", k12x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb5 */ {AND_INT_2ADDR,  "and-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb6 */ {OR_INT_2ADDR,  "or-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb7 */ {XOR_INT_2ADDR,  "xor-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb8 */ {SHL_INT_2ADDR,  "shl-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xb9 */ {SHR_INT_2ADDR,  "shr-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xba */ {USHR_INT_2ADDR,  "ushr-int/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xbb */ {ADD_LONG_2ADDR,  "add-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xbc */ {SUB_LONG_2ADDR,  "sub-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xbd */ {MUL_LONG_2ADDR,  "mul-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xbe */ {DIV_LONG_2ADDR,  "div-long/2addr", k12x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xbf */ {REM_LONG_2ADDR,  "rem-long/2addr", k12x, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xc0 */ {AND_LONG_2ADDR,  "and-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xc1 */ {OR_LONG_2ADDR,  "or-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xc2 */ {XOR_LONG_2ADDR,  "xor-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xc3 */ {SHL_LONG_2ADDR,  "shl-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0xc4 */ {SHR_LONG_2ADDR,  "shr-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0xc5 */ {USHR_LONG_2ADDR,  "ushr-long/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegB},
 /* 0xc6 */ {ADD_FLOAT_2ADDR,  "add-float/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xc7 */ {SUB_FLOAT_2ADDR,  "sub-float/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xc8 */ {MUL_FLOAT_2ADDR,  "mul-float/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xc9 */ {DIV_FLOAT_2ADDR,  "div-float/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xca */ {REM_FLOAT_2ADDR,  "rem-float/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xcb */ {ADD_DOUBLE_2ADDR,  "add-double/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xcc */ {SUB_DOUBLE_2ADDR,  "sub-double/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xcd */ {MUL_DOUBLE_2ADDR,  "mul-double/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xce */ {DIV_DOUBLE_2ADDR,  "div-double/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xcf */ {REM_DOUBLE_2ADDR,  "rem-double/2addr", k12x, None,  flags::Continue,  verify_flags::VerifyRegAWide | verify_flags::VerifyRegBWide},
 /* 0xd0 */ {ADD_INT_LIT16,  "add-int/lit16", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd1 */ {RSUB_INT,  "rsub-int", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd2 */ {MUL_INT_LIT16,  "mul-int/lit16", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd3 */ {DIV_INT_LIT16,  "div-int/lit16", k22s, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd4 */ {REM_INT_LIT16,  "rem-int/lit16", k22s, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd5 */ {AND_INT_LIT16,  "and-int/lit16", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd6 */ {OR_INT_LIT16,  "or-int/lit16", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd7 */ {XOR_INT_LIT16,  "xor-int/lit16", k22s, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd8 */ {ADD_INT_LIT8,  "add-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xd9 */ {RSUB_INT_LIT8,  "rsub-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xda */ {MUL_INT_LIT8,  "mul-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xdb */ {DIV_INT_LIT8,  "div-int/lit8", k22b, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xdc */ {REM_INT_LIT8,  "rem-int/lit8", k22b, None,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xdd */ {AND_INT_LIT8,  "and-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xde */ {OR_INT_LIT8,  "or-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xdf */ {XOR_INT_LIT8,  "xor-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xe0 */ {SHL_INT_LIT8,  "shl-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xe1 */ {SHR_INT_LIT8,  "shr-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xe2 */ {USHR_INT_LIT8,  "ushr-int/lit8", k22b, None,  flags::Continue,  verify_flags::VerifyRegA | verify_flags::VerifyRegB},
 /* 0xe3 */ {UNUSED_E3,  "unused-e3", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe4 */ {UNUSED_E4,  "unused-e4", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe5 */ {UNUSED_E5,  "unused-e5", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe6 */ {UNUSED_E6,  "unused-e6", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe7 */ {UNUSED_E7,  "unused-e7", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe8 */ {UNUSED_E8,  "unused-e8", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xe9 */ {UNUSED_E9,  "unused-e9", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xea */ {UNUSED_EA,  "unused-ea", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xeb */ {UNUSED_EB,  "unused-eb", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xec */ {UNUSED_EC,  "unused-ec", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xed */ {UNUSED_ED,  "unused-ed", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xee */ {UNUSED_EE,  "unused-ee", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xef */ {UNUSED_EF,  "unused-ef", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf0 */ {UNUSED_F0,  "unused-f0", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf1 */ {UNUSED_F1,  "unused-f1", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf2 */ {UNUSED_F2,  "unused-f2", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf3 */ {UNUSED_F3,  "unused-f3", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf4 */ {UNUSED_F4,  "unused-f4", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf5 */ {UNUSED_F5,  "unused-f5", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf6 */ {UNUSED_F6,  "unused-f6", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf7 */ {UNUSED_F7,  "unused-f7", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf8 */ {UNUSED_F8,  "unused-f8", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xf9 */ {UNUSED_F9,  "unused-f9", k10x, Unknown,  0,  verify_flags::VerifyError},
 /* 0xfa */ {INVOKE_POLYMORPHIC,  "invoke-polymorphic", k45cc, MethodAndProtoRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgNonZero | verify_flags::VerifyRegHPrototype},
 /* 0xfb */ {INVOKE_POLYMORPHIC_RANGE,  "invoke-polymorphic/range", k4rcc, MethodAndProtoRef,  flags::Continue | flags::Throw | flags::Invoke,  verify_flags::VerifyRegBMethod | verify_flags::VerifyVarArgRangeNonZero | verify_flags::VerifyRegHPrototype},
 /* 0xfc */ {INVOKE_CUSTOM,  "invoke-custom", k35c, CallSiteRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegBCallSite | verify_flags::VerifyVarArg},
 /* 0xfd */ {INVOKE_CUSTOM_RANGE,  "invoke-custom/range", k3rc, CallSiteRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegBCallSite | verify_flags::VerifyVarArgRange},
 /* 0xfe */ {CONST_METHOD_HANDLE,  "const-method-handle", k21c, MethodHandleRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBMethodHandle},
 /* 0xff */ {CONST_METHOD_TYPE,  "const-method-type", k21c, ProtoRef,  flags::Continue | flags::Throw,  verify_flags::VerifyRegA | verify_flags::VerifyRegBPrototype},
);
