use std::{
    borrow::Borrow,
    sync::{Arc, Mutex},
};

use pyo3::{types::PyBytes, Py, PyResult, Python};

use crate::file::{verifier::VerifyPreset, DexFile, DexLocation, Header};

use super::{
    arc_mutex_get,
    container::{PyFileDexContainer, PyInMemoryDexContainer},
    structs::PyHeader,
};

#[pyo3::pyclass(name = "VerifyPreset", module = "dexrs._internal.file", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyVerifyPreset {
    ALL = 1,
    CHECKSUM_ONLY = 2,
    NONE = 3,
}

impl Into<VerifyPreset> for PyVerifyPreset {
    fn into(self) -> VerifyPreset {
        match self {
            PyVerifyPreset::ALL => VerifyPreset::All,
            PyVerifyPreset::CHECKSUM_ONLY => VerifyPreset::ChecksumOnly,
            PyVerifyPreset::NONE => VerifyPreset::None,
        }
    }
}

// lifetime annotation can't be removed for now
pub type PyInMemoryDexFile<'a> = DexFile<'a, PyInMemoryDexContainer>;
pub type PyDexFile<'a> = DexFile<'a, PyFileDexContainer>;

// REVISIT: there's currently no other way to store the dex file
pub enum RsDexFile {
    InMemory {
        dex: PyInMemoryDexFile<'static>,
        container: PyInMemoryDexContainer,
    },
    File {
        dex: PyDexFile<'static>,
        container: PyFileDexContainer,
    },
}

// Python wrapper class that enables mutli-threading operations
#[pyo3::pyclass(name = "DexFile", module = "dexrs._internal.file")]
pub struct PyDexFileImpl {
    inner: Arc<RsDexFile>,
}

macro_rules! bind_dex {
    ($dex_file:ident, $dex_type:ident, $c:ident) => {{
        let static_dex = unsafe { std::mem::transmute($dex_file) };
        let inner = RsDexFile::$dex_type {
            container: $c,
            dex: static_dex,
        };
        PyDexFileImpl {
            inner: Arc::new(inner),
        }
    }};
}

impl PyDexFileImpl {}

macro_rules! dex_action_impl {
    ($this:ident, $method:ident) => {{
        match $this.inner.as_ref() {
            RsDexFile::InMemory { dex, .. } => dex.$method(),
            RsDexFile::File { dex, .. } => dex.$method(),
        }
    }};
}

#[pyo3::pymethods]
impl PyDexFileImpl {
    #[staticmethod]
    #[pyo3(signature = (
        data,
        preset=PyVerifyPreset::ALL
    ))]
    pub fn from_bytes<'py>(
        py: Python<'py>,
        data: Py<PyBytes>,
        preset: PyVerifyPreset,
    ) -> PyResult<PyDexFileImpl> {
        let preset = preset.into();
        let container = PyInMemoryDexContainer::open(py, data);
        let dex = PyInMemoryDexFile::open(&container, DexLocation::InMemory, preset)?;
        Ok(bind_dex!(dex, InMemory, container))
    }

    #[staticmethod]
    #[pyo3(signature = (
        path,
        preset=PyVerifyPreset::ALL
    ))]
    pub fn from_file(path: String, preset: PyVerifyPreset) -> PyResult<PyDexFileImpl> {
        let preset = preset.into();
        let container = PyFileDexContainer::open(path.clone())?;
        let dex = PyDexFile::open(&container, DexLocation::Path(path), preset)?;
        Ok(bind_dex!(dex, File, container))
    }

    pub fn get_header(&self) -> PyResult<PyHeader> {
        Ok(dex_action_impl!(self, get_header).into())
    }
}

// final module
#[pyo3::pymodule(name = "file")]
pub(crate) mod file_mod {

    #[pymodule_export]
    use super::{PyDexFileImpl, PyVerifyPreset};
}
