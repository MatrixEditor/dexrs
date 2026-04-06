#[pyo3::pymodule(name = "container")]
pub(crate) mod py_container {
    #[pymodule_export]
    use crate::file::container::{PyFileDexContainer, PyInMemoryDexContainer};
}
