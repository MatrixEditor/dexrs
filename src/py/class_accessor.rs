#[pyo3::pymodule]
pub mod py_class_accessor {
    #[pymodule_export]
    use crate::file::class_accessor::{PyClassAccessor, PyDexField, PyDexMethod};
}
