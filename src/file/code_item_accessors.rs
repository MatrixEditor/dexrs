use crate::Result;

use super::{CodeItem, DexContainer, DexFile, Instruction};

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
}

impl<'a> IntoIterator for CodeItemAccessor<'a> {
    type Item = Instruction<'a>;
    type IntoIter = DexInstructionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // iterator will be valid on empty input
        DexInstructionIterator::new(self.insns)
    }
}

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
