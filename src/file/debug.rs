use crate::{
    leb128::{decode_leb128_off, decode_leb128p1_off},
    Result,
};

pub enum SourceFile {
    This,
    Other(u32), // index to file
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
    pub const DBG_LINE_BASE: u8            = (-4 as i8) as u8;
    pub const DBG_LINE_RANGE: u8           = 15;
}

pub struct PositionInfo {
    pub address: u32,
    pub line: u32,
    pub file: SourceFile,
    prologue_end: bool,
    epilogue_begin: bool,
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
        F: Fn(u32),
    {
        let mut offset = 0;
        self.decode_parameter_names(visitor, &mut offset)?;
        Ok(())
    }

    fn decode_parameter_names<F>(&self, visitor: F, offset: &mut usize) -> Result<u32>
    where
        F: Fn(u32),
    {
        let line = decode_leb128_off(&self.ptr, offset)?;
        let size = decode_leb128_off::<u32>(&self.ptr, offset)?;

        for _ in 0..size {
            let index = decode_leb128p1_off(&self.ptr, offset)?;
            visitor(index as u32);
        }
        Ok(line)
    }

    pub fn decode_position_info<F>(&self, pos_visitor: F) -> Result<()>
    where
        F: Fn(&PositionInfo),
    {
        let mut entry = PositionInfo::new();
        let mut offset = 0;
        entry.line = self.decode_parameter_names(|_| {}, &mut offset)?;

        loop {
            let opcode = self.ptr[offset];
            offset += 1;

            match opcode {
                code::DBG_END_SEQUENCE => break,
                // This will cause overflow
                code::DBG_ADVANCE_PC => {
                    entry.address += decode_leb128_off::<u32>(&self.ptr, &mut offset)?
                }
                code::DBG_ADVANCE_LINE => {
                    entry.line += decode_leb128_off::<u32>(&self.ptr, &mut offset)?
                }
                code::DBG_START_LOCAL => {
                    decode_leb128_off::<u32>(&self.ptr, &mut offset)?; // reg
                    decode_leb128p1_off(&self.ptr, &mut offset)?; // name
                    decode_leb128p1_off(&self.ptr, &mut offset)?; // descriptor
                }
                code::DBG_START_LOCAL_EXTENDED => {
                    decode_leb128_off::<u32>(&self.ptr, &mut offset)?; // reg
                    decode_leb128p1_off(&self.ptr, &mut offset)?; // name
                    decode_leb128p1_off(&self.ptr, &mut offset)?; // descriptor
                    decode_leb128p1_off(&self.ptr, &mut offset)?; // signature
                }
                code::DBG_END_LOCAL | code::DBG_RESTART_LOCAL => {
                    decode_leb128_off::<u32>(&self.ptr, &mut offset)?; // reg
                }
                code::DBG_SET_PROLOGUE_END => entry.prologue_end = true,
                code::DBG_SET_EPILOGUE_BEGIN => entry.epilogue_begin = true,
                code::DBG_SET_FILE => {
                    let file = decode_leb128p1_off(&self.ptr, &mut offset)?; // file
                    entry.file = SourceFile::Other(file as u32);
                }
                _ => {
                    let adjusted_opcode = opcode - code::DBG_FIRST_SPECIAL;
                    entry.address += (adjusted_opcode / code::DBG_LINE_RANGE) as u32;
                    entry.line +=
                        (code::DBG_LINE_BASE + (adjusted_opcode % code::DBG_LINE_RANGE)) as u32;
                    pos_visitor(&entry);
                    entry.epilogue_begin = false;
                    entry.prologue_end = false;
                }
            }
        }
        Ok(())
    }

    // TODO
    // pub fn decode_local_info<F>(&self, visitor: F)
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
        let line = decode_leb128_off::<u32>(&ptr, &mut pos)?;
        let size = decode_leb128_off::<u32>(&ptr, &mut pos)? as usize;
        Ok(Self {
            ptr,
            offset,
            size,
            idx: 0,
        })
    }
}

impl<'a> Iterator for DebugInfoParameterNamesIterator<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.idx >= self.size {
            return None;
        }
        self.idx += 1;
        match decode_leb128p1_off(&self.ptr, &mut self.offset) {
            Ok(v) => {
                Some(v as u32)
            }
            Err(_) => None,
        }
    }
}
