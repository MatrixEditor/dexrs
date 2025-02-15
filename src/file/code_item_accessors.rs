#[cfg(feature = "python")]
use pyo3::PyResult;
#[cfg(feature = "python")]
use std::sync::Arc;

#[cfg(feature = "python")]
use crate::py::rs_type_wrapper;

use crate::Result;

use super::{CodeItem, DexContainer, DexFile, Instruction};

#[cfg(feature = "python")]
use super::{PyDexCodeItem, PyInstruction};

// ----------------------------------------------------------------------------
// CodeItemAccessor
// ----------------------------------------------------------------------------
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
    pub fn has_code(&self) -> bool {
        !self.insns.is_empty()
    }

    #[inline(always)]
    pub fn from_code_item<C>(
        dex: &'a DexFile<'a, C>,
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

    pub fn inst_at(&self, pc: u32) -> PyInstruction {
        self.inner.0.inst_at(pc).into()
    }

    // REVISIT: dex_pc is unused here
    pub fn insns(&self) -> PyResult<Vec<PyInstruction>> {
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
