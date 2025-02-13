use pyo3::PyResult;

use crate::{error::DexError, utf};

#[pyo3::pyfunction]
pub fn mutf8_to_str(utf8_data_in: &[u8]) -> PyResult<String> {
    if let Some(end) = utf8_data_in.iter().position(|&x| x == 0) {
        Ok(utf::mutf8_to_str(&utf8_data_in[0..=end])?)
    } else {
        Err(DexError::BadStringDataMissingNullByte(utf8_data_in.as_ptr() as usize).into())
    }
}

#[pyo3::pyfunction]
pub fn mutf8_to_str_lossy(utf8_data_in: &[u8]) -> PyResult<String> {
    if let Some(end) = utf8_data_in.iter().position(|&x| x == 0) {
        Ok(utf::mutf8_to_str_lossy(&utf8_data_in[0..=end])?)
    } else {
        Err(DexError::BadStringDataMissingNullByte(utf8_data_in.as_ptr() as usize).into())
    }
}

#[pyo3::pyfunction]
pub fn str_to_mutf8(str_data_in: &str) -> Vec<u8> {
    utf::str_to_mutf8(str_data_in)
}

#[pyo3::pyfunction]
pub fn str_to_mutf8_lossy(str_data_in: &str) -> Vec<u8> {
    utf::str_to_mutf8_lossy(str_data_in)
}

#[pyo3::pymodule(name = "mutf8")]
pub(crate) mod py_mutf8 {
    #[pymodule_export]
    use super::{mutf8_to_str, mutf8_to_str_lossy, str_to_mutf8, str_to_mutf8_lossy};
}
