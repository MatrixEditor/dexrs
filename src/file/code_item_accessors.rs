use crate::Result;

use super::{CodeItem, DexFile, Instruction};

pub struct CodeItemAccessor<'a> {
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
    pub fn from_code_item(
        dex: &'a DexFile<'a>,
        code_item: &'a CodeItem,
        code_off: u32,
    ) -> Result<CodeItemAccessor<'a>> {
        let insns = match code_off {
            0 => &[],
            _ => dex.get_insns_raw(code_off, code_item.insns_size)?,
        };
        Ok(CodeItemAccessor { code_item, insns })
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

    pub fn insn_at(&self, pc: u32) -> Instruction<'a> {
        debug_assert!(pc < self.insns_size_in_code_units());
        Instruction::at(&self.insns[pc as usize..])

    }
}
