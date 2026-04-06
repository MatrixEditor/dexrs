#[pyo3::pymodule(name = "leb128")]
pub(crate) mod py_leb128 {
    use pyo3::PyResult;

    #[pyo3::pyfunction]
    pub fn decode_uleb128(data_in: &[u8]) -> PyResult<(u32, usize)> {
        Ok(crate::leb128::decode_leb128::<u32>(data_in)?)
    }

    #[pyo3::pyfunction]
    pub fn decode_sleb128(data_in: &[u8]) -> PyResult<i32> {
        Ok(crate::leb128::decode_sleb128(data_in, &mut 0)?)
    }

    #[pyo3::pyfunction]
    pub fn decode_leb128p1(data_in: &[u8]) -> PyResult<(i32, usize)> {
        Ok(crate::leb128::decode_leb128p1(data_in)?)
    }
}
