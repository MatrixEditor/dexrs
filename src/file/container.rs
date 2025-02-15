use memmap2::{MmapAsRawDesc, MmapMut};
use std::ops::{Deref, DerefMut};

#[cfg(feature = "python")]
use std::sync::Arc;

#[cfg(feature = "python")]
use pyo3::{types::PyBytes, Py, PyRef, PyResult, Python};

use super::MmapDexFile;
use crate::Result;

#[cfg(feature = "python")]
use crate::error::py_error::GenericError;

// ----------------------------------------------------------------------------
// DexContainer
// ----------------------------------------------------------------------------
pub trait DexContainer<'a>: AsRef<[u8]> + Deref<Target = [u8]> + 'a {
    fn data(&'a self) -> &'a [u8] {
        self.as_ref()
    }

    fn file_size(&'a self) -> usize {
        self.data().len()
    }
}

// ----------------------------------------------------------------------------
// DexContainerMut
// ----------------------------------------------------------------------------

pub trait DexContainerMut<'a>: DexContainer<'a> + DerefMut {
    fn data_mut(&'a mut self) -> &'a mut [u8] {
        self.deref_mut()
    }
}

// ----------------------------------------------------------------------------
// default implementations
// ----------------------------------------------------------------------------
impl DexContainer<'_> for memmap2::Mmap {}
impl DexContainer<'_> for MmapMut {}
impl DexContainerMut<'_> for MmapMut {}

impl<'a> DexContainer<'a> for &'a [u8] {}
impl<'a> DexContainer<'a> for &'a mut [u8] {}
impl<'a> DexContainerMut<'a> for &'a mut [u8] {}

impl DexContainer<'_> for Vec<u8> {}
impl DexContainerMut<'_> for Vec<u8> {}

// ----------------------------------------------------------------------------
// InMemoryDexContainer
// ----------------------------------------------------------------------------
pub struct InMemoryDexContainer<'a>(&'a [u8]);

impl<'a> InMemoryDexContainer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> Deref for InMemoryDexContainer<'a> {
    type Target = [u8];
    fn deref(&self) -> &'a Self::Target {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for InMemoryDexContainer<'a> {
    fn as_ref(&self) -> &'a [u8] {
        &self.0
    }
}

impl<'a> DexContainer<'a> for InMemoryDexContainer<'a> {}

// >>> begin python export

#[cfg(feature = "python")]
// custom implementation of DexFileContainer to support python values
#[pyo3::pyclass(
    name = "InMemoryDexContainer",
    module = "dexrs._internal.container",
    frozen
)]
pub struct PyInMemoryDexContainer {
    pub(crate) data: Py<PyBytes>,
    length: usize,
}

#[cfg(feature = "python")]
impl AsRef<[u8]> for PyInMemoryDexContainer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

#[cfg(feature = "python")]
impl Deref for PyInMemoryDexContainer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        Python::with_gil(|py| self.data.as_bytes(py))
    }
}

#[cfg(feature = "python")]
impl DexContainer<'_> for PyInMemoryDexContainer {}

#[cfg(feature = "python")]
impl PyInMemoryDexContainer {
    pub fn open<'py>(py: Python, data: Py<PyBytes>) -> Self {
        Self {
            data: data.clone_ref(py),
            length: data.as_bytes(py).len(),
        }
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PyInMemoryDexContainer {
    #[new]
    pub fn new<'py>(py: Python<'py>, data: Py<PyBytes>) -> PyResult<PyInMemoryDexContainer> {
        Ok(PyInMemoryDexContainer::open(py, data))
    }

    pub fn data<'py>(py_self: PyRef<'_, Self>, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        Ok(py_self.data.clone_ref(py))
    }

    #[getter]
    pub fn file_size(py_self: PyRef<'_, Self>) -> PyResult<usize> {
        Ok(py_self.length)
    }

    pub fn __len__(py_self: PyRef<'_, Self>) -> usize {
        py_self.length
    }
}

// ----------------------------------------------------------------------------
// DexFileContainer
// ----------------------------------------------------------------------------
pub struct DexFileContainer {
    mmap: memmap2::Mmap,
    location: String,
    pub verify: bool,
    pub verify_checksum: bool,
}

impl DexFileContainer {
    pub fn new<T>(file: T) -> Self
    where
        T: MmapAsRawDesc,
    {
        Self {
            mmap: unsafe { memmap2::Mmap::map(file).unwrap() },
            verify: false,
            verify_checksum: false,
            location: "[anonymous]".to_string(),
        }
    }

    pub fn location(&mut self, location: String) -> &mut Self {
        self.location = location;
        self
    }

    pub fn verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    pub fn verify_checksum(mut self, verify_checksum: bool) -> Self {
        self.verify_checksum = verify_checksum;
        self
    }

    pub fn open<'a>(&'a self) -> Result<MmapDexFile<'a>> {
        MmapDexFile::open_file(self)
    }

    pub fn get_location(&self) -> &str {
        &self.location
    }

    pub fn data(&self) -> &memmap2::Mmap {
        &self.mmap
    }
}

// >>> begin python export
#[cfg(feature = "python")]
#[pyo3::pyclass(
    name = "FileDexContainer",
    module = "dexrs._internal.container",
    frozen
)]
pub struct PyFileDexContainer {
    pub(crate) path: String,
    _fp: Arc<std::fs::File>,
    data: Arc<memmap2::Mmap>,
}

#[cfg(feature = "python")]
impl AsRef<[u8]> for PyFileDexContainer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data.as_ref()
    }
}

#[cfg(feature = "python")]
impl Deref for PyFileDexContainer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data.deref()
    }
}

#[cfg(feature = "python")]
impl DexContainer<'_> for PyFileDexContainer {}

// Rust API
#[cfg(feature = "python")]
impl PyFileDexContainer {
    pub fn open(path: String) -> std::result::Result<Self, GenericError> {
        let fp = std::fs::File::open(path.clone())?;
        let mmap = unsafe { memmap2::Mmap::map(&fp)? };
        Ok(PyFileDexContainer {
            path,
            _fp: Arc::new(fp),
            data: Arc::new(mmap),
        })
    }
}

// Python API
#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PyFileDexContainer {
    #[new]
    pub fn new(path: String) -> PyResult<PyFileDexContainer> {
        Ok(PyFileDexContainer::open(path)?)
    }

    #[getter]
    pub fn location(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    pub fn data<'py>(&self, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        Ok(PyBytes::new(py, self.data.as_ref()).into())
    }

    #[getter]
    pub fn file_size(&self) -> PyResult<usize> {
        Ok(self.data.len())
    }

    pub fn __len__(&self) -> usize {
        self.data.len()
    }
}
// <<< end python export

#[cfg(feature = "python")]
#[pyo3::pymodule(name = "container")]
pub(crate) mod py_container {

    #[pymodule_export]
    use super::{PyFileDexContainer, PyInMemoryDexContainer};
}
