use std::{ops::Deref, sync::Arc};

use pyo3::{exceptions::PyNotImplementedError, types::PyBytes, Py, PyRef, PyResult, Python};

use crate::file::DexContainer;

use super::error::GenericError;

#[pyo3::pyclass(name = "DexContainer", module = "dexrs._internal.container", subclass)]
pub struct PyDexContainer {}

#[pyo3::pymethods]
impl PyDexContainer {
    #[new]
    pub fn new() -> Self {
        PyDexContainer {}
    }

    pub fn data(&self) -> PyResult<&[u8]> {
        Err(PyNotImplementedError::new_err("foobar"))
    }

    pub fn file_size(&self) -> PyResult<usize> {
        Err(PyNotImplementedError::new_err("foobar"))
    }
}

// custom implementation of DexFileContainer to support python values

#[pyo3::pyclass(
    name = "InMemoryDexContainer",
    module = "dexrs._internal.container",
    extends = PyDexContainer,
    subclass
)]
pub struct PyInMemoryDexContainer {
    data: Py<PyBytes>,
    length: usize,
}

impl AsRef<[u8]> for PyInMemoryDexContainer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        Python::with_gil(|py| self.data.as_bytes(py))
    }
}

impl Deref for PyInMemoryDexContainer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DexContainer<'_> for PyInMemoryDexContainer {}

impl PyInMemoryDexContainer {
    pub fn open<'py>(py: Python, data: Py<PyBytes>) -> Self {
        Self {
            data: data.clone_ref(py),
            length: data.as_bytes(py).len(),
        }
    }
}

#[pyo3::pymethods]
impl PyInMemoryDexContainer {
    #[new]
    pub fn new<'py>(
        py: Python<'py>,
        data: Py<PyBytes>,
    ) -> PyResult<(PyInMemoryDexContainer, PyDexContainer)> {
        Ok((
            PyInMemoryDexContainer::open(py, data),
            PyDexContainer::new(),
        ))
    }

    // TODO: measure performance overhead if data is huge
    pub fn data<'py>(&self, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        Ok(self.data.clone_ref(py))
    }

    #[getter]
    pub fn file_size(&self) -> PyResult<usize> {
        Ok(self.length)
    }

    pub fn __len__(py_self: PyRef<'_, Self>) -> usize {
        py_self.length
    }
}

#[pyo3::pyclass(
    name = "FileDexContainer",
    module = "dexrs._internal.container",
    extends = PyDexContainer,
    subclass
)]
pub struct PyFileDexContainer {
    path: String,
    _fp: std::fs::File,
    data: Arc<memmap2::Mmap>,
}

impl AsRef<[u8]> for PyFileDexContainer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl Deref for PyFileDexContainer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DexContainer<'_> for PyFileDexContainer {}

impl PyFileDexContainer {
    pub fn open(path: String) -> Result<Self, GenericError> {
        let fp = std::fs::File::open(path.clone())?;
        let mmap = unsafe { memmap2::Mmap::map(&fp)? };
        Ok(PyFileDexContainer {
            path,
            _fp: fp,
            data: Arc::new(mmap),
        })
    }
}

#[pyo3::pymethods]
impl PyFileDexContainer {
    #[new]
    pub fn new(path: String) -> PyResult<(Self, PyDexContainer)> {
        Ok((
            PyFileDexContainer::open(path)?,
            PyDexContainer::new(),
        ))
    }

    pub fn data<'py>(&self, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new(py, self.data.as_ref()).into())
    }

    #[getter]
    pub fn file_size(&self) -> PyResult<usize> {
        Ok(self.data.len())
    }

    #[getter]
    pub fn location(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    pub fn __len__(&self) -> usize {
        self.data.len()
    }
}

#[pyo3::pymodule(name = "container")]
pub(crate) mod container_mod {

    #[pymodule_export]
    use super::{PyDexContainer, PyFileDexContainer, PyInMemoryDexContainer};
}
