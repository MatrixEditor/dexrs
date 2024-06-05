use super::types::*;
use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct DebugInfoItem {
    /// the initial value for the state machine's line register. Does not represent
    /// an actual positions entry.
    pub line_start: ULeb128,

    /// the number of parameter names that are encoded. There should be one per
    /// method parameter, excluding an instance method's this, if any.
    #[bw(calc = ULeb128(parameter_names.len() as u32))]
    pub parameters_size: ULeb128,

    /// string index of the method parameter name. An encoded value of `NO_INDEX`
    /// indicates that no name is available for the associated parameter. The type
    /// descriptor and signature are implied from the method descriptor and signature.
    #[br(count = parameters_size.0)]
    pub parameter_names: Vec<ULeb128p1>,
}

impl DebugInfoItem {
    /// terminates a debug info sequence for a code_item
    pub const DBG_END_SEQUENCE: UByte = 0x00;

    /// advances the address register without emitting a positions entry
    ///
    /// @format: [ULeb128] addr_diff
    ///
    /// @args:
    ///     - `addr_diff`: amount to add to address register
    pub const DBG_ADVANCE_PC: UByte = 0x01;

    /// advances the line register without emitting a positions entry
    ///
    /// @format: [SLeb128] line_diff
    ///
    /// @args:
    ///     - `line_diff`: amount to add to line register
    pub const DBG_ADVANCE_LINE: UByte = 0x02;

    /// introduces a local variable at the current address. Either name_idx or
    /// type_idx may be NO_INDEX to indicate that that value is unknown.
    ///
    /// @format:
    ///     - [ULeb128] register_num
    ///     - [ULeb128p1] name_idx
    ///     - [ULeb128p1] type_idx
    ///
    /// @args:
    ///     - `register_num`: register number that will contain local
    ///     - `name_idx`: index into the string_ids list
    ///     - `type_idx`: index into the type_ids list
    pub const DBG_START_LOCAL: UByte = 0x03;

    /// introduces a local with a type signature at the current address. Any of
    /// name_idx, type_idx, or sig_idx may be NO_INDEX to indicate that that value
    /// is unknown. (If sig_idx is -1, though, the same data could be represented
    /// more efficiently using the opcode DBG_START_LOCAL.)
    ///
    /// @format:
    ///     - [ULeb128] register_num
    ///     - [ULeb128p1] name_idx
    ///     - [ULeb128p1] type_idx
    ///     - [ULeb128p1] sig_idx
    ///
    /// @args:
    ///     - `register_num`: register number that will contain local
    ///     - `name_idx`: index into the string_ids list
    ///     - `type_idx`: index into the type_ids list
    ///     - `sig_idx`: string index of the type signature
    pub const DBG_START_LOCAL_EXTENDED: UByte = 0x04;

    /// marks a currently-live local variable as out of scope at the current address
    ///
    /// @format:
    ///     - [ULeb128] register_num
    ///
    /// @args:
    ///     - `register_num`: register that contained local
    pub const DBG_END_LOCAL: UByte = 0x05;

    /// re-introduces a local variable at the current address. The name and type are
    /// the same as the last local that was live in the specified register.
    ///
    /// @format:
    ///     - [ULeb128] register_num
    ///
    /// @args:
    ///     - `register_num`:  register to restart
    pub const DBG_RESTART_LOCAL: UByte = 0x06;

    /// sets the prologue_end state machine register, indicating that the next position
    /// entry that is added should be considered the end of a method prologue (an
    /// appropriate place for a method breakpoint). The prologue_end register is
    /// cleared by any special (>= 0x0a) opcode.
    pub const DBG_SET_PROLOGUE_END: UByte = 0x07;

    /// sets the epilogue_begin state machine register, indicating that the next position
    /// entry that is added should be considered the beginning of a method epilogue (an
    /// appropriate place to suspend execution before method exit). The epilogue_begin
    /// register is cleared by any special (>= 0x0a) opcode.
    pub const DBG_SET_EPILOGUE_BEGIN: UByte = 0x08;

    /// indicates that all subsequent line number entries make reference to this source
    /// file name, instead of the default name specified in code_item
    ///
    /// @format:
    ///     - [ULeb128p1] file_idx
    ///
    /// @args:
    ///     - `file_idx`: string index of source file name; [NO_INDEX] if unknown
    pub const DBG_SET_FILE: UByte = 0x09;

    /// Behaviour for special opcodes: advances the line and address registers, emits a
    /// position entry, and clears prologue_end and epilogue_begin. See below for description.
    ///
    /// Opcodes with values between 0x0a and 0xff (inclusive) move both the line and address
    /// registers by a small amount and then emit a new position table entry.
    pub const DBG_FIRST_SPECIAL: UByte = 0x0a;

    /// the smallest line number increment
    pub const DBG_LINE_BASE: i8 = -4;

    /// the number of line increments represented
    pub const DBG_LINE_RANGE: UByte = 15;
}


