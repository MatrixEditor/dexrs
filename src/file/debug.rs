use crate::{
    leb128::{decode_leb128_off, decode_leb128p1_off, decode_sleb128},
    Result,
};

use super::StringIndex;

#[derive(Debug, Clone)]
pub enum SourceFile {
    This,
    Other(StringIndex), // index to file
}

/// Local variable information decoded from a debug info stream.
#[derive(Debug, Clone, Default)]
pub struct LocalInfo {
    /// Index into string_ids for the variable name, or `None`.
    pub name_idx: Option<StringIndex>,
    /// Index into type_ids for the variable type descriptor, or `None`.
    pub descriptor_idx: Option<StringIndex>,
    /// Index into string_ids for the Dalvik/generic signature, or `None`.
    pub signature_idx: Option<StringIndex>,
    /// DEX program counter where the local comes into scope.
    pub start_address: u32,
    /// DEX program counter where the local goes out of scope.
    pub end_address: u32,
    /// Register number holding this local.
    pub reg: u16,
    /// Whether this local is currently live (used during decoding).
    pub is_live: bool,
}

#[rustfmt::skip]
pub mod code {
    pub const DBG_END_SEQUENCE: u8         = 0x00;
    pub const DBG_ADVANCE_PC: u8           = 0x01;
    pub const DBG_ADVANCE_LINE: u8         = 0x02;
    pub const DBG_START_LOCAL: u8          = 0x03;
    pub const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
    pub const DBG_END_LOCAL: u8            = 0x05;
    pub const DBG_RESTART_LOCAL: u8        = 0x06;
    pub const DBG_SET_PROLOGUE_END: u8     = 0x07;
    pub const DBG_SET_EPILOGUE_BEGIN: u8   = 0x08;
    pub const DBG_SET_FILE: u8             = 0x09;

    pub const DBG_FIRST_SPECIAL: u8        = 0x0a;
    pub const DBG_LINE_BASE: u8            = -4_i8 as u8;
    pub const DBG_LINE_RANGE: u8           = 15;
}

pub struct PositionInfo {
    pub address: u32,
    pub line: u32,
    pub file: SourceFile,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
}

impl PositionInfo {
    pub fn new() -> Self {
        Self {
            address: 0,
            line: 0,
            file: SourceFile::This,
            prologue_end: false,
            epilogue_begin: false,
        }
    }
}

impl Default for PositionInfo {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CodeItemDebugInfoAccessor<'a> {
    ptr: &'a [u8],
}

impl<'a> CodeItemDebugInfoAccessor<'a> {
    pub fn new(ptr: &'a [u8]) -> Self {
        Self { ptr }
    }

    pub fn parameter_names(&self) -> Result<DebugInfoParameterNamesIterator<'a>> {
        DebugInfoParameterNamesIterator::new(self.ptr, 0)
    }

    pub fn visit_parameter_names<F>(&self, visitor: F) -> Result<()>
    where
        F: FnMut(u32),
    {
        let mut offset = 0;
        self.decode_parameter_names(visitor, &mut offset)?;
        Ok(())
    }

    fn decode_parameter_names<F>(&self, mut visitor: F, offset: &mut usize) -> Result<u32>
    where
        F: FnMut(u32),
    {
        let line = decode_leb128_off(self.ptr, offset)?;
        let size = decode_leb128_off::<u32>(self.ptr, offset)?;

        for _ in 0..size {
            let index = decode_leb128p1_off(self.ptr, offset)?;
            visitor(index as u32);
        }
        Ok(line)
    }

    pub fn decode_position_info<F>(&self, mut pos_visitor: F) -> Result<()>
    where
        F: FnMut(&PositionInfo),
    {
        let mut entry = PositionInfo::new();
        let mut offset = 0;
        entry.line = self.decode_parameter_names(|_| {}, &mut offset)?;

        loop {
            let opcode = self.ptr[offset];
            offset += 1;

            match opcode {
                code::DBG_END_SEQUENCE => break,
                code::DBG_ADVANCE_PC => {
                    entry.address = entry.address
                        .wrapping_add(decode_leb128_off::<u32>(self.ptr, &mut offset)?)
                }
                code::DBG_ADVANCE_LINE => {
                    let delta = decode_sleb128(self.ptr, &mut offset)?;
                    entry.line = (entry.line as i32).wrapping_add(delta) as u32;
                }
                code::DBG_START_LOCAL => {
                    decode_leb128_off::<u32>(self.ptr, &mut offset)?; // reg
                    decode_leb128p1_off(self.ptr, &mut offset)?; // name
                    decode_leb128p1_off(self.ptr, &mut offset)?; // descriptor
                }
                code::DBG_START_LOCAL_EXTENDED => {
                    decode_leb128_off::<u32>(self.ptr, &mut offset)?; // reg
                    decode_leb128p1_off(self.ptr, &mut offset)?; // name
                    decode_leb128p1_off(self.ptr, &mut offset)?; // descriptor
                    decode_leb128p1_off(self.ptr, &mut offset)?; // signature
                }
                code::DBG_END_LOCAL | code::DBG_RESTART_LOCAL => {
                    decode_leb128_off::<u32>(self.ptr, &mut offset)?; // reg
                }
                code::DBG_SET_PROLOGUE_END => entry.prologue_end = true,
                code::DBG_SET_EPILOGUE_BEGIN => entry.epilogue_begin = true,
                code::DBG_SET_FILE => {
                    let file = decode_leb128p1_off(self.ptr, &mut offset)?; // file
                    entry.file = SourceFile::Other(file as u32);
                }
                _ => {
                    let adjusted_opcode = opcode - code::DBG_FIRST_SPECIAL;
                    entry.address = entry.address
                        .wrapping_add((adjusted_opcode / code::DBG_LINE_RANGE) as u32);
                    let line_delta = (code::DBG_LINE_BASE as i8 as i32)
                        + (adjusted_opcode % code::DBG_LINE_RANGE) as i32;
                    entry.line = (entry.line as i32).wrapping_add(line_delta) as u32;
                    pos_visitor(&entry);
                    entry.epilogue_begin = false;
                    entry.prologue_end = false;
                }
            }
        }
        Ok(())
    }

    /// Returns the source line number for the given DEX program counter, or `None`
    /// if no position entry covers that PC.  Matches ART's `GetLineNumForPc`.
    pub fn get_line_for_pc(&self, dex_pc: u32) -> Result<Option<u32>> {
        let mut result: Option<u32> = None;
        self.decode_position_info(|pos| {
            if pos.address <= dex_pc {
                result = Some(pos.line);
            }
        })?;
        Ok(result)
    }

    /// Decodes the local variable table and calls `visitor` for each completed
    /// (or still-live-at-end) local variable.
    ///
    /// `num_regs` should come from [`CodeItem::registers_size`].
    /// Matches ART's `CodeItemDebugInfoAccessor::DecodeDebugLocalInfo`.
    pub fn decode_local_info<F>(&self, num_regs: u16, mut visitor: F) -> Result<()>
    where
        F: FnMut(&LocalInfo),
    {
        let mut locals: Vec<LocalInfo> = (0..num_regs as usize)
            .map(|i| LocalInfo { reg: i as u16, ..Default::default() })
            .collect();

        let mut offset = 0usize;
        // skip line start and parameter names
        decode_leb128_off::<u32>(self.ptr, &mut offset)?;
        let param_count = decode_leb128_off::<u32>(self.ptr, &mut offset)?;
        for _ in 0..param_count {
            decode_leb128p1_off(self.ptr, &mut offset)?;
        }

        let mut address: u32 = 0;

        loop {
            if offset >= self.ptr.len() {
                break;
            }
            let opcode = self.ptr[offset];
            offset += 1;

            match opcode {
                code::DBG_END_SEQUENCE => break,
                code::DBG_ADVANCE_PC => {
                    address = address
                        .wrapping_add(decode_leb128_off::<u32>(self.ptr, &mut offset)?);
                }
                code::DBG_ADVANCE_LINE => {
                    decode_sleb128(self.ptr, &mut offset)?;
                }
                code::DBG_START_LOCAL => {
                    let reg = decode_leb128_off::<u32>(self.ptr, &mut offset)? as usize;
                    let name = decode_leb128p1_off(self.ptr, &mut offset)?;
                    let descriptor = decode_leb128p1_off(self.ptr, &mut offset)?;
                    if reg < locals.len() {
                        if locals[reg].is_live {
                            let mut ended = locals[reg].clone();
                            ended.end_address = address;
                            visitor(&ended);
                        }
                        locals[reg] = LocalInfo {
                            reg: reg as u16,
                            name_idx: if name >= 0 { Some(name as u32) } else { None },
                            descriptor_idx: if descriptor >= 0 { Some(descriptor as u32) } else { None },
                            signature_idx: None,
                            start_address: address,
                            end_address: 0,
                            is_live: true,
                        };
                    }
                }
                code::DBG_START_LOCAL_EXTENDED => {
                    let reg = decode_leb128_off::<u32>(self.ptr, &mut offset)? as usize;
                    let name = decode_leb128p1_off(self.ptr, &mut offset)?;
                    let descriptor = decode_leb128p1_off(self.ptr, &mut offset)?;
                    let signature = decode_leb128p1_off(self.ptr, &mut offset)?;
                    if reg < locals.len() {
                        if locals[reg].is_live {
                            let mut ended = locals[reg].clone();
                            ended.end_address = address;
                            visitor(&ended);
                        }
                        locals[reg] = LocalInfo {
                            reg: reg as u16,
                            name_idx: if name >= 0 { Some(name as u32) } else { None },
                            descriptor_idx: if descriptor >= 0 { Some(descriptor as u32) } else { None },
                            signature_idx: if signature >= 0 { Some(signature as u32) } else { None },
                            start_address: address,
                            end_address: 0,
                            is_live: true,
                        };
                    }
                }
                code::DBG_END_LOCAL => {
                    let reg = decode_leb128_off::<u32>(self.ptr, &mut offset)? as usize;
                    if reg < locals.len() && locals[reg].is_live {
                        let mut ended = locals[reg].clone();
                        ended.end_address = address;
                        ended.is_live = false;
                        visitor(&ended);
                        locals[reg].is_live = false;
                    }
                }
                code::DBG_RESTART_LOCAL => {
                    let reg = decode_leb128_off::<u32>(self.ptr, &mut offset)? as usize;
                    if reg < locals.len() && !locals[reg].is_live {
                        locals[reg].start_address = address;
                        locals[reg].is_live = true;
                    }
                }
                code::DBG_SET_PROLOGUE_END | code::DBG_SET_EPILOGUE_BEGIN => {}
                code::DBG_SET_FILE => {
                    decode_leb128p1_off(self.ptr, &mut offset)?;
                }
                _ => {
                    let adjusted_opcode = opcode - code::DBG_FIRST_SPECIAL;
                    address = address
                        .wrapping_add((adjusted_opcode / code::DBG_LINE_RANGE) as u32);
                }
            }
        }

        // flush locals still live at end of method
        for local in &locals {
            if local.is_live {
                let mut ended = local.clone();
                ended.end_address = address;
                visitor(&ended);
            }
        }
        Ok(())
    }

}

pub struct DebugInfoParameterNamesIterator<'dex> {
    ptr: &'dex [u8],
    offset: usize,
    idx: usize,
    size: usize,
}

impl<'dex> DebugInfoParameterNamesIterator<'dex> {
    pub fn new(ptr: &'dex [u8], offset: usize) -> Result<Self> {
        let mut pos = offset;
        // skipping line number
        decode_leb128_off::<u32>(ptr, &mut pos)?;
        let size = decode_leb128_off::<u32>(ptr, &mut pos)? as usize;
        Ok(Self {
            ptr,
            offset: pos,
            size,
            idx: 0,
        })
    }
}

impl Iterator for DebugInfoParameterNamesIterator<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.idx >= self.size {
            return None;
        }
        self.idx += 1;
        match decode_leb128p1_off(self.ptr, &mut self.offset) {
            Ok(v) => Some(v as u32),
            Err(_) => None,
        }
    }
}
