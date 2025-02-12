use pyo3::{create_exception, exceptions::{PyIOError, PyRuntimeError}, PyErr};

use crate::error::DexError;

create_exception!(dexrs._internal.error, PyDexError, PyRuntimeError);

impl From<DexError> for PyErr {
    fn from(err: DexError) -> PyErr {
        PyDexError::new_err(err.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenericError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

impl From<GenericError> for PyErr {
    fn from(err: GenericError) -> PyErr {
        PyIOError::new_err(err.to_string())
    }
}

#[pyo3::pymodule]
pub(crate) mod error {

    #[pymodule_export]
    use super::PyDexError;

}