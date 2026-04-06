use std::collections::HashMap;

use super::{DexContainer, DexFile};

/// Fast O(1) lookup of `class_def_idx` by type descriptor.
///
/// Equivalent to ART's `TypeLookupTable`. Built on demand from a [`DexFile`]
/// using a `HashMap` internally.  The table is owned and does not borrow from
/// the DEX file, so it can outlive it.
pub struct TypeLookupTable {
    table: HashMap<String, u32>,
}

impl TypeLookupTable {
    /// Builds a lookup table from all class definitions in `dex`.
    pub fn new<'a, C: DexContainer<'a>>(dex: &'a DexFile<'a, C>) -> Self {
        let mut table = HashMap::with_capacity(dex.num_class_defs() as usize);
        for (idx, class_def) in dex.get_class_defs().iter().enumerate() {
            if let Ok(desc) = dex.get_type_desc_utf16_at(class_def.class_idx) {
                table.insert(desc, idx as u32);
            }
        }
        TypeLookupTable { table }
    }

    /// Returns the `class_def_idx` for the given type descriptor, or `None` if not found.
    ///
    /// `descriptor` must be in DEX format, e.g. `"Ljava/lang/String;"`.
    pub fn lookup(&self, descriptor: &str) -> Option<u32> {
        self.table.get(descriptor).copied()
    }

    /// Returns the number of entries in the table.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns `true` if the table contains no entries.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}
