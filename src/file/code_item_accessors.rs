use crate::{leb128, Result};

use super::{CatchHandlerData, CodeItem, DexContainer, DexFile, Instruction, TryItem, TypeIndex};

#[cfg(feature = "python")]
use pyo3::PyResult;
#[cfg(feature = "python")]
use std::sync::Arc;

#[cfg(feature = "python")]
use crate::py::rs_type_wrapper;

#[cfg(feature = "python")]
use super::{PyDexCodeItem, PyDexInstruction};

// ----------------------------------------------------------------------------
// CodeItemAccessor
// ----------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct CodeItemAccessor<'a> {
    code_off: u32,
    /// Decoded CodeItem fields stored by value so both standard and compact
    /// DEX code items normalise to the same structure.
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    tries_size: u16,
    /// `debug_info_off` from the standard DEX code item (0 for compact DEX).
    pub debug_info_off: u32,
    insns: &'a [u16],
    // these values are cached to reduce the number of calculations
    tries_off: Option<u32>,
    catch_handlers_off: Option<u32>,
}

impl<'a> CodeItemAccessor<'a> {
    /// Builds an accessor from a standard DEX [`CodeItem`].
    #[inline(always)]
    pub fn from_code_item<C>(
        dex: &DexFile<'a, C>,
        code_item: &'a CodeItem,
        code_off: u32,
    ) -> Result<CodeItemAccessor<'a>>
    where
        C: DexContainer<'a>,
    {
        Self::from_fields(
            dex,
            code_item.registers_size,
            code_item.ins_size,
            code_item.outs_size,
            code_item.tries_size,
            code_item.debug_info_off,
            code_item.insns_size,
            code_off,
        )
    }

    /// Builds an accessor from already-decoded field values.
    ///
    /// `code_off` is the absolute byte offset of the first instruction word.
    #[allow(clippy::too_many_arguments)]
    pub fn from_fields<C>(
        dex: &DexFile<'a, C>,
        registers_size: u16,
        ins_size: u16,
        outs_size: u16,
        tries_size: u16,
        debug_info_off: u32,
        insns_size: u32,
        code_off: u32,
    ) -> Result<CodeItemAccessor<'a>>
    where
        C: DexContainer<'a>,
    {
        let insns = match code_off {
            0 => &[],
            _ => dex.get_insns_raw(code_off, insns_size)?,
        };

        // end of insns must be 4-byte aligned
        let tries_off_rel = insns.len() * 2 + if insns.len() % 2 == 1 { 2 } else { 0 };
        let try_item_total = tries_size as usize * std::mem::size_of::<TryItem>();
        Ok(CodeItemAccessor {
            code_off,
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns,
            tries_off: if tries_size > 0 {
                Some(tries_off_rel as u32)
            } else {
                None
            },
            catch_handlers_off: if tries_size > 0 {
                Some((tries_off_rel + try_item_total) as u32)
            } else {
                None
            },
        })
    }

    /// Returns an empty accessor (no instructions, used for null code offsets).
    pub fn empty() -> Result<CodeItemAccessor<'a>> {
        Ok(CodeItemAccessor {
            code_off: 0,
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            tries_size: 0,
            debug_info_off: 0,
            insns: &[],
            tries_off: None,
            catch_handlers_off: None,
        })
    }

    /// Returns a synthetic [`CodeItem`] built from the decoded fields.
    ///
    /// For standard DEX files this matches the on-disk struct exactly.
    /// For compact DEX files it is a synthesised value (insns_size comes from
    /// the instruction slice length).
    pub fn code_item(&self) -> CodeItem {
        CodeItem {
            registers_size: self.registers_size,
            ins_size: self.ins_size,
            outs_size: self.outs_size,
            tries_size: self.tries_size,
            debug_info_off: self.debug_info_off,
            insns_size: self.insns.len() as u32,
        }
    }

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
    pub fn get_tries_off(&self) -> Option<u32> {
        self.tries_off
    }

    #[inline]
    pub fn get_tries_abs_off(&self) -> Option<u32> {
        self.get_tries_off()
            .map(|tries_off| tries_off + self.insns_off())
    }

    #[inline]
    pub fn get_catch_handler_data_off(&self) -> Option<u32> {
        self.catch_handlers_off
    }

    #[inline]
    pub fn get_catch_handler_data_abs_off(&self) -> Option<u32> {
        self.get_catch_handler_data_off()
            .map(|data_off| data_off + self.insns_off())
    }

    #[inline]
    pub fn has_code(&self) -> bool {
        !self.insns.is_empty()
    }

    pub fn insns_off(&self) -> u32 {
        self.code_off
    }

    pub fn registers_size(&self) -> u16 {
        self.registers_size
    }

    pub fn ins_size(&self) -> u16 {
        self.ins_size
    }

    pub fn outs_size(&self) -> u16 {
        self.outs_size
    }

    pub fn tries_size(&self) -> u16 {
        self.tries_size
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

/// Performs a binary search for the try item covering `dex_pc`, matching ART's
/// `DexFile::FindTryItem`.  Returns the index of the matching `TryItem`, or
/// `None` if `dex_pc` is not covered by any try block.
///
/// `try_items` must be sorted by `start_addr` (guaranteed by the DEX spec).
pub fn find_try_item(try_items: &[TryItem], dex_pc: u32) -> Option<usize> {
    let mut min = 0usize;
    let mut max = try_items.len();
    while min < max {
        let mid = (min + max) / 2;
        let start = try_items[mid].start_addr;
        let end = start + try_items[mid].insn_count as u32;
        if dex_pc < start {
            max = mid;
        } else if dex_pc >= end {
            min = mid + 1;
        } else {
            return Some(mid);
        }
    }
    None
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
        // TODO: add docs
        self.inner.0.insns_off()
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
    has_catch_all: bool,
    remaining: i32,
}

impl<'a> EncodedCatchHandlerIterator<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let mut pos = 0;
        let remaining = leb128::decode_sleb128(data, &mut pos)?;
        println!("remaining: {}", remaining);
        Ok(Self {
            data,
            offset: pos,
            has_catch_all: remaining <= 0,
            // If remaining is non-positive, then it is the negative of
            // the number of catch types, and the catches are followed by a
            // catch-all handler.
            remaining: if remaining <= 0 {
                -remaining
            } else {
                remaining
            },
        })
    }

    #[inline(always)]
    fn leb128(&mut self) -> Result<u32> {
        leb128::decode_leb128_off::<u32>(self.data, &mut self.offset)
    }
}

impl Iterator for EncodedCatchHandlerIterator<'_> {
    type Item = CatchHandlerData;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == -1 {
            return None;
        }

        let mut handler = CatchHandlerData::default();
        if self.remaining > 0 {
            match self.leb128() {
                Ok(v) => handler.type_idx = v as TypeIndex,
                Err(_) => return None,
            }
            match self.leb128() {
                Ok(v) => handler.address = v,
                Err(_) => return None,
            }
            self.remaining -= 1;
            return Some(handler);
        }

        if self.has_catch_all {
            handler.is_catch_all = true;
            handler.type_idx = TypeIndex::MAX;
            match self.leb128() {
                Ok(v) => handler.address = v,
                Err(_) => return None,
            }
            self.has_catch_all = false;
            return Some(handler);
        }

        self.remaining = -1;
        None
    }
}
