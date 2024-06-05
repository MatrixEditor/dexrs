use std::{
    array,
    collections::{HashMap, LinkedList, VecDeque},
    env::var,
    future,
    io::{Read, Seek},
    rc::Rc,
};

use binrw::BinRead;

use crate::dalvik::{
    dex::*,
    error::{Error, Result},
    file::{method::DexPrototype, Dex, IDex},
};

#[derive(Debug)]
pub struct LocalVariable {
    pub register_num: UInt,
    pub name: Option<Rc<String>>,
    pub type_: Option<Rc<DexType>>,
    pub signature: Option<Rc<String>>,
    pub start_pc: UInt,
    pub end_pc: UInt,
    pub parameter: bool,
}

#[derive(Debug)]
pub struct DebugInfo {
    // A table that maps each instruction offset to its line number.
    pub lines: HashMap<UInt, ULong>,

    // A list of all defined local variables mapped to their instruction offsets.
    pub local_variables: HashMap<UInt, LocalVariable>,

    // The name of the source file containing the code.
    pub source_file: Option<Rc<String>>,
}

impl DebugInfoItem {
    pub fn parse_debug_info<R>(
        &self,
        code: &CodeItem,
        dex: &mut Dex<'_, R>,
        prototype: &DexPrototype,
    ) -> Result<DebugInfo>
    where
        R: Read + Seek,
    {
        let mut file: Option<Rc<String>> = None;
        let mut lines: HashMap<UInt, ULong> = HashMap::new();
        let mut local_variables: HashMap<UInt, LocalVariable> = HashMap::new();
        let mut buf = [0u8; 1];

        let mut pc = 0;
        let mut line: i64 = self.line_start.0 as i64;
        let mut regs: Vec<Option<LocalVariable>> = Vec::with_capacity(code.registers_size as usize);
        for _ in 0..code.registers_size {
            regs.push(None);
        }

        macro_rules! ulebp1_unwrap {
            ($idx:ident, $func:ident, $ty:ident) => {
                if let ULeb128p1::Pos(pos) = $idx {
                    Some(dex.$func(pos as $ty)?)
                } else {
                    None
                }
            };
        }

        let mut i = code.registers_size as isize;
        for (p_type, idx) in prototype
            .parameters
            .iter()
            .zip(self.parameter_names.iter())
            .rev()
        {
            i -= match &(p_type.descriptor)[..] {
                "D" | "J" => 2,
                _ => 1,
            };
            if i < 0 {
                break;
            }
            regs[i as usize] = Some(LocalVariable {
                register_num: i as u32,
                name: if let ULeb128p1::Pos(pos) = idx {
                    Some(dex.get_string(*pos)?)
                } else {
                    None
                },
                type_: Some(p_type.clone()),
                signature: None,
                start_pc: 0,
                end_pc: 0,
                parameter: true,
            });
        }

        macro_rules! start_var {
            // starts a new local variable by removing any previously defined local variable
            // from the target register.
            ($reg:ident, $var:ident) => {
                if let Some(mut prev_var) = regs[$reg.0 as usize].take() {
                    prev_var.end_pc = pc;
                    local_variables.insert(prev_var.start_pc, prev_var);
                }
                regs[$reg.0 as usize] = Some($var);
            };
        }

        macro_rules! end_var {
            ($reg:ident) => {
                if let Some(mut var) = regs[$reg.0 as usize].take() {
                    var.end_pc = pc;
                    local_variables.insert(var.start_pc, var);
                }
                regs[$reg.0 as usize] = None;
            };
        }

        loop {
            if dex.fd.read(&mut buf)? != 1 {
                return Err(Error::Custom("Unexpected EOF"));
            };
            let c = buf[0];

            match c {
                // terminates a debug info sequence for a code_item
                DebugInfoItem::DBG_END_SEQUENCE => break,

                // advances the address register without emitting a positions entry
                DebugInfoItem::DBG_ADVANCE_PC => {
                    let addr_diff = ULeb128::read(dex.fd)?;
                    pc += addr_diff.0;
                }

                // advances the line register without emitting a positions entry
                DebugInfoItem::DBG_ADVANCE_LINE => {
                    let line_diff = SLeb128::read(dex.fd)?;
                    line += line_diff.0 as i64;
                }

                // introduces a local variable at the current address. Either name_idx
                // or type_idx may be NO_INDEX to indicate that that value is unknown.
                DebugInfoItem::DBG_START_LOCAL => {
                    let register_num = ULeb128::read(dex.fd)?;
                    let name_idx = ULeb128p1::read(dex.fd)?;
                    let type_idx = ULeb128p1::read(dex.fd)?;
                    let var = LocalVariable {
                        register_num: register_num.0,
                        name: ulebp1_unwrap!(name_idx, get_string, u32),
                        type_: ulebp1_unwrap!(type_idx, get_type, u32),
                        signature: None,
                        start_pc: pc,
                        end_pc: 0,
                        parameter: false,
                    };
                    start_var!(register_num, var);
                }

                // introduces a local with a type signature at the current address. Any of
                // name_idx, type_idx, or sig_idx may be NO_INDEX to indicate that that
                // value is unknown. (If sig_idx is -1, though, the same data could be
                // represented more efficiently using the opcode DBG_START_LOCAL.)
                DebugInfoItem::DBG_START_LOCAL_EXTENDED => {
                    let register_num = ULeb128::read(dex.fd)?;
                    let name_idx = ULeb128p1::read(dex.fd)?;
                    let type_idx = ULeb128p1::read(dex.fd)?;
                    let sig_idx = ULeb128p1::read(dex.fd)?;
                    let var = LocalVariable {
                        register_num: register_num.0,
                        name: ulebp1_unwrap!(name_idx, get_string, u32),
                        type_: ulebp1_unwrap!(type_idx, get_type, u32),
                        signature: ulebp1_unwrap!(sig_idx, get_string, u32),
                        start_pc: pc,
                        end_pc: 0,
                        parameter: false,
                    };
                    start_var!(register_num, var);
                }

                // marks a currently-live local variable as out of scope at the current address
                DebugInfoItem::DBG_END_LOCAL => {
                    let register_num = ULeb128::read(dex.fd)?;
                    end_var!(register_num);
                }

                // re-introduces a local variable at the current address. The name and type are
                // the same as the last local that was live in the specified register.
                DebugInfoItem::DBG_RESTART_LOCAL => {
                    let register_num = ULeb128::read(dex.fd)?;
                    if let Some(var) = regs[register_num.0 as usize].take() {
                        let new_var = LocalVariable {
                            register_num: var.register_num,
                            name: var.name.clone(),
                            type_: var.type_,
                            signature: var.signature.clone(),
                            start_pc: pc,
                            end_pc: 0,
                            parameter: false,
                        };
                        start_var!(register_num, new_var);
                    }
                }

                // ignore those states as they don't contribute to the debug info
                DebugInfoItem::DBG_SET_PROLOGUE_END | DebugInfoItem::DBG_SET_EPILOGUE_BEGIN => {
                    // ignore
                }

                // indicates that all subsequent line number entries make reference to this source
                // file name, instead of the default name specified in code_item
                DebugInfoItem::DBG_SET_FILE => {
                    if let ULeb128p1::Pos(file_idx) = ULeb128p1::read(dex.fd)? {
                        file = Some(dex.get_string(file_idx)?);
                    }
                }

                0x0A..=0xFF => {
                    // special opcodes
                    let adjusted_opcode = c - DebugInfoItem::DBG_FIRST_SPECIAL;

                    line += DebugInfoItem::DBG_LINE_BASE as i64
                        + ((adjusted_opcode % DebugInfoItem::DBG_LINE_RANGE) as i64);

                    pc += (adjusted_opcode / DebugInfoItem::DBG_LINE_RANGE) as u32;
                    lines.insert(pc, line as ULong);
                }
            }
        }

        for mut var in regs.into_iter().flatten() {
            var.end_pc = pc;
            local_variables.insert(var.start_pc, var);
        }

        Ok(DebugInfo {
            lines,
            local_variables,
            source_file: file,
        })
    }
}
