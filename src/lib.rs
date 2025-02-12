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
    use crate::py::container::container_mod;

    #[pymodule_export]
    use crate::py::file::file_mod;

    #[pymodule_export]
    use crate::py::error::error;

    #[pymodule_export]
    use crate::py::structs::structs;
}