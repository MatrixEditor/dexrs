use std::sync::Arc;

use pyo3::PyResult;

use crate::file::{Code, CodeItemAccessor, Instruction, PyDexCode};

use super::rs_type_wrapper;

rs_type_wrapper!(
    CodeItemAccessor<'static>,
    PyCodeItemAccessor,
    RsCodeItemAccessor,
    name: "CodeItemAccessor",
    module: "dexrs._internal.code"
);

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
}

rs_type_wrapper!(
    Instruction<'static>,
    PyInstruction,
    RsInstruction,
    name: "Instruction",
    module: "dexrs._internal.code"
);

#[pyo3::pymethods]
impl PyInstruction {
    pub fn fetch16(&self, offset: u32) -> PyResult<u16> {
        Ok(self.inner.0.fetch16(offset as usize)?)
    }

    pub fn fetch32(&self, offset: u32) -> PyResult<u32> {
        Ok(self.inner.0.fetch32(offset as usize)?)
    }

    #[staticmethod]
    pub fn opcode_of(inst_data: u16) -> PyDexCode {
        let opcode = Instruction::opcode_of(inst_data);
        Instruction::format_desc_of(opcode).py_opcode
    }

    #[staticmethod]
    pub fn name_of(opcode: PyDexCode) -> &'static str {
        Instruction::format_desc_of(opcode.into()).name
    }
}

// opcodes
impl Into<Code> for PyDexCode {
    #[inline]
    fn into(self) -> Code {
        Instruction::opcode_of(self as u8 as u16)
    }
}

#[pyo3::pymodule(name = "code")]
pub mod py_code {
    #[pymodule_export]
    use super::{PyCodeItemAccessor, PyDexCode, PyInstruction};
}
