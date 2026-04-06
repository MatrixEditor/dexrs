use pyo3::exceptions::PyException;

pyo3::create_exception!(dexrs._internal.error, PyDexError, PyException);

impl From<crate::error::DexError> for pyo3::PyErr {
    fn from(err: crate::error::DexError) -> pyo3::PyErr {
        PyDexError::new_err(err.to_string())
    }
}

/// Generic errors not wrapped by dexrs (e.g. IO errors from container opening).
#[derive(Debug, thiserror::Error)]
pub enum GenericError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

impl From<GenericError> for pyo3::PyErr {
    fn from(err: GenericError) -> pyo3::PyErr {
        pyo3::exceptions::PyIOError::new_err(err.to_string())
    }
}

#[pyo3::pymodule(name = "error")]
pub(crate) mod py_error {
    #[pymodule_export]
    use super::PyDexError as PyDexErrorExport;
}
