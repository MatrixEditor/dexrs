use crate::file::TypeLookupTable;

/// Fast O(1) class lookup table.  Build via `DexFile.build_type_lookup_table()`.
#[pyo3::pyclass(name = "TypeLookupTable", module = "dexrs._internal.type_lookup_table")]
pub struct PyTypeLookupTable(pub(crate) TypeLookupTable);

#[pyo3::pymethods]
impl PyTypeLookupTable {
    /// Returns the `class_def_idx` for `descriptor`, or `None` if not found.
    ///
    /// `descriptor` must be in DEX format, e.g. `"Ljava/lang/String;"`.
    pub fn lookup(&self, descriptor: &str) -> Option<u32> {
        self.0.lookup(descriptor)
    }

    /// Returns the number of classes in the table.
    pub fn __len__(&self) -> usize {
        self.0.len()
    }

    /// Returns `True` if `descriptor` is in the table.
    pub fn __contains__(&self, descriptor: &str) -> bool {
        self.0.lookup(descriptor).is_some()
    }

    pub fn __repr__(&self) -> String {
        format!("TypeLookupTable({} classes)", self.0.len())
    }
}

#[pyo3::pymodule(name = "type_lookup_table")]
pub(crate) mod py_type_lookup_table {
    #[pymodule_export]
    use super::PyTypeLookupTable;
}
