use std::result;

pub mod error;
pub mod file;
pub mod leb128;
pub mod utf;

pub mod desc_names;

pub type Result<T> = result::Result<T, error::DexError>;

#[cfg(feature = "python")]
pub(crate) mod py;

#[cfg(feature = "python")]
#[pyo3::pymodule]
mod _internal {

    #[pymodule_export]
    use crate::py::container::py_container;

    #[pymodule_export]
    use crate::py::file::py_file;

    #[pymodule_export]
    use crate::py::error::py_error;

    #[pymodule_export]
    use crate::py::structs::py_structs;

    #[pymodule_export]
    use crate::py::mutf8::py_mutf8;

    #[pymodule_export]
    use crate::py::class_accessor::py_class_accessor;
}