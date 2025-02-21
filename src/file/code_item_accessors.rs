#[cfg(feature = "python")]
use pyo3::PyResult;
#[cfg(feature = "python")]
use std::sync::Arc;

#[cfg(feature = "python")]
use crate::py::rs_type_wrapper;

use crate::{leb128, Result};

use super::{CatchHandlerData, CodeItem, DexContainer, DexFile, Instruction, TryItem, TypeIndex};

#[cfg(feature = "python")]
use super::{PyDexCodeItem, PyDexInstruction};

// ----------------------------------------------------------------------------
// CodeItemAccessor
// ----------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct CodeItemAccessor<'a> {
    code_off: u32,
    code_item: &'a CodeItem,
    insns: &'a [u16],
}

impl<'a> CodeItemAccessor<'a> {
    #[inline]
    pub fn insns_size_in_code_units(&self) -> u32 {
        self.insns.len() as u32
    }

    #[inline]
    pub fn insns_size_in_bytes(&self) -> u32 {
        self.insns.len() as u32 * 2
    }

    #[inline(always)]
    pub fn insns(&self) -> &'a [u16] {
        self.insns
    }

    #[inline]
    pub fn get_tries_off(&self) -> Option<usize> {
        if self.tries_size() == 0 {
            return None; //
        }

        let offset = (self.code_off() as usize)
            + std::mem::size_of::<CodeItem>()
            + self.insns_size_in_code_units() as usize;
        // must be 4-byte aligned
        let offset = (offset + 3) & !3;
        Some(offset)
    }

    #[inline]
    pub fn get_catch_handler_data_off(&self) -> usize {
        let tries_off = self.code_off() as usize
            + std::mem::size_of::<CodeItem>()
            + self.insns_size_in_code_units() as usize;

        tries_off + (self.tries_size() as usize * std::mem::size_of::<TryItem>())
    }

    #[inline]
    pub fn has_code(&self) -> bool {
        !self.insns.is_empty()
    }

    #[inline(always)]
    pub fn from_code_item<C>(
        dex: &DexFile<'a, C>,
        code_item: &'a CodeItem,
        code_off: u32,
    ) -> Result<CodeItemAccessor<'a>>
    where
        C: DexContainer<'a>,
    {
        let insns = match code_off {
            0 => &[],
            _ => dex.get_insns_raw(code_off, code_item.insns_size)?,
        };
        Ok(CodeItemAccessor {
            code_off,
            code_item,
            insns,
        })
    }

    pub fn code_off(&self) -> u32 {
        self.code_off
    }

    pub fn code_item(&self) -> &'a CodeItem {
        self.code_item
    }

    pub fn registers_size(&self) -> u16 {
        self.code_item.registers_size
    }

    pub fn ins_size(&self) -> u16 {
        self.code_item.ins_size
    }

    pub fn outs_size(&self) -> u16 {
        self.code_item.outs_size
    }

    pub fn tries_size(&self) -> u16 {
        self.code_item.tries_size
    }

    pub fn inst_at(&self, pc: u32) -> Instruction<'a> {
        debug_assert!(pc < self.insns_size_in_code_units());
        Instruction::at(&self.insns[pc as usize..])
    }

    pub fn get_inst_offset_in_code_units(&self, inst: &Instruction<'_>) -> usize {
        let code_ptr = self.insns.as_ptr() as usize;
        let inst_ptr = inst.raw().as_ptr() as usize;
        inst_ptr - code_ptr
    }
}

impl<'a> IntoIterator for CodeItemAccessor<'a> {
    type Item = Instruction<'a>;
    type IntoIter = DexInstructionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // iterator will be valid on empty input
        DexInstructionIterator::new(self.insns)
    }
}

impl<'a> IntoIterator for &'a CodeItemAccessor<'a> {
    type Item = Instruction<'a>;
    type IntoIter = DexInstructionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // iterator will be valid on empty input
        DexInstructionIterator::new(self.insns)
    }
}

// >>> begin python export
#[cfg(feature = "python")]
rs_type_wrapper!(
    CodeItemAccessor<'static>,
    PyCodeItemAccessor,
    RsCodeItemAccessor,
    name: "CodeItemAccessor",
    module: "dexrs._internal.code"
);

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PyCodeItemAccessor {
    #[getter]
    pub fn insns_size_in_code_units(&self) -> u32 {
        self.inner.0.insns_size_in_code_units()
    }

    #[getter]
    pub fn insns_size_in_bytes(&self) -> u32 {
        self.inner.0.insns_size_in_bytes()
    }

    pub fn has_code(&self) -> bool {
        self.inner.0.has_code()
    }

    #[getter]
    pub fn code_off(&self) -> u32 {
        self.inner.0.code_off()
    }

    #[getter]
    pub fn code_item(&self) -> PyDexCodeItem {
        self.inner.0.code_item().into()
    }

    #[getter]
    pub fn registers_size(&self) -> u16 {
        self.inner.0.registers_size()
    }

    #[getter]
    pub fn ins_size(&self) -> u16 {
        self.inner.0.ins_size()
    }

    #[getter]
    pub fn outs_size(&self) -> u16 {
        self.inner.0.outs_size()
    }

    #[getter]
    pub fn tries_size(&self) -> u16 {
        self.inner.0.tries_size()
    }

    pub fn insns_raw(&self) -> &[u16] {
        self.inner.0.insns()
    }

    pub fn inst_at(&self, pc: u32) -> PyDexInstruction {
        self.inner.0.inst_at(pc).into()
    }

    // REVISIT: dex_pc is unused here
    pub fn insns(&self) -> PyResult<Vec<PyDexInstruction>> {
        Ok(DexInstructionIterator::new(self.inner.0.insns)
            .map(Into::into)
            .collect())
    }
}
// <<< end python export

// ----------------------------------------------------------------------------
// Instruction Iterator
// ----------------------------------------------------------------------------
pub struct DexInstructionIterator<'a> {
    instructions: &'a [u16],
    pc: usize,
}

impl<'a> DexInstructionIterator<'a> {
    pub fn new(instructions: &'a [u16]) -> Self {
        Self {
            instructions,
            pc: 0,
        }
    }

    pub fn inst(&self) -> Instruction<'a> {
        debug_assert!(self.pc < self.instructions.len());
        Instruction::at(&self.instructions[self.pc..])
    }

    // REVISIT: make mutable?
    pub fn dex_pc(&self) -> usize {
        self.pc
    }

    pub fn advance(&mut self) {
        if self.pc >= self.instructions.len() {
            return;
        }

        let size = self.inst().size_in_code_units();
        self.pc += size;
        debug_assert!(self.pc <= self.instructions.len());
    }
}

impl<'a> Iterator for DexInstructionIterator<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pc < self.instructions.len() {
            let inst = self.inst();
            self.pc += inst.size_in_code_units();
            Some(inst)
        } else {
            None
        }
    }
}

// ----------------------------------------------------------------------------
// EncodedCatchHandler Iterator
// ----------------------------------------------------------------------------

pub struct EncodedCatchHandlerIterator<'a> {
    data: &'a [u8],
    offset: usize,
    catch_all: bool,
    remaining: i32,
}

impl<'a> EncodedCatchHandlerIterator<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let mut pos = 0;
        let remaining = leb128::decode_sleb128(&data, &mut pos)?;
        Ok(Self {
            data,
            offset: pos,
            catch_all: remaining <= 0,
            remaining: if remaining <= 0 {
                remaining
            } else {
                -remaining
            },
        })
    }
}

impl<'a> Iterator for EncodedCatchHandlerIterator<'a> {
    type Item = CatchHandlerData;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == -1 {
            return None;
        }

        let mut handler = CatchHandlerData::default();
        if self.remaining > 0 {
            match leb128::decode_leb128_off::<u32>(&self.data, &mut self.offset) {
                Ok(v) => handler.type_idx = v as TypeIndex,
                Err(_) => return None,
            };
            match leb128::decode_leb128_off::<u32>(&self.data, &mut self.offset) {
                Ok(v) => handler.address = v,
                Err(_) => return None,
            }
            self.remaining -= 1;
            return Some(handler);
        }

        if self.catch_all {
            handler.is_catch_all = true;
            handler.type_idx = TypeIndex::MAX;
            match leb128::decode_leb128_off::<u32>(&self.data, &mut self.offset) {
                Ok(v) => handler.address = v,
                Err(_) => return None,
            }
            self.catch_all = false;
            return Some(handler);
        }

        self.remaining = -1;
        None
    }
}
