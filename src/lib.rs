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
    use crate::file::container::py_container;

    #[pymodule_export]
    use crate::py::file::py_file;

    #[pymodule_export]
    use crate::error::py_error;

    #[pymodule_export]
    use crate::file::structs::py_structs;

    #[pymodule_export]
    use crate::utf::py_utf;

    #[pymodule_export]
    use crate::leb128::py_leb128;

    #[pymodule_export]
    use crate::file::class_accessor::py_class_accessor;

    #[pymodule_export]
    use crate::file::instruction::py_code;
}
