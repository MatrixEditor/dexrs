#[pyo3::pymodule(name = "mutf8")]
pub(crate) mod py_utf {
    use crate::error::DexError;
    use pyo3::PyResult;

    #[pyo3::pyfunction]
    pub fn mutf8_to_str(utf8_data_in: &[u8]) -> PyResult<String> {
        if let Some(end) = utf8_data_in.iter().position(|&x| x == 0) {
            Ok(crate::utf::mutf8_to_str(&utf8_data_in[0..=end])?)
        } else {
            Err(DexError::BadStringDataMissingNullByte(utf8_data_in.as_ptr() as usize).into())
        }
    }

    #[pyo3::pyfunction]
    pub fn mutf8_to_str_lossy(utf8_data_in: &[u8]) -> PyResult<String> {
        if let Some(end) = utf8_data_in.iter().position(|&x| x == 0) {
            Ok(crate::utf::mutf8_to_str_lossy(&utf8_data_in[0..=end])?)
        } else {
            Err(DexError::BadStringDataMissingNullByte(utf8_data_in.as_ptr() as usize).into())
        }
    }

    #[pyo3::pyfunction]
    pub fn str_to_mutf8(str_data_in: &str) -> Vec<u8> {
        crate::utf::str_to_mutf8(str_data_in)
    }

    #[pyo3::pyfunction]
    pub fn str_to_mutf8_lossy(str_data_in: &str) -> Vec<u8> {
        crate::utf::str_to_mutf8_lossy(str_data_in)
    }
}
