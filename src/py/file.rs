use std::sync::Arc;

use pyo3::{exceptions::PyValueError, Py, PyResult, Python};

use crate::file::{verifier::VerifyPreset, DexFile, DexLocation, StringIndex};

use super::{
    container::{PyFileDexContainer, PyInMemoryDexContainer},
    structs::{PyDexHeader, PyDexStringId},
};


#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[pyo3::pyclass(name = "VerifyPreset", module = "dexrs._internal.file", eq, eq_int)]
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
        container: Py<PyInMemoryDexContainer>,
    },
    File {
        dex: PyDexFile<'static>,
        container: Py<PyFileDexContainer>,
    },
}

// Python wrapper class that enables mutli-threading operations
#[pyo3::pyclass(name = "DexFile", module = "dexrs._internal.file")]
pub struct PyDexFileImpl {
    inner: Arc<RsDexFile>,
}

macro_rules! bind_dex {
    ($dex_file:ident, $dex_type:ident, $c:ident, $py:ident) => {{
        let static_dex = unsafe { std::mem::transmute($dex_file) };
        let inner = RsDexFile::$dex_type {
            container: $c.clone_ref($py),
            dex: static_dex,
        };
        PyDexFileImpl {
            inner: Arc::new(inner),
        }
    }};
}

impl PyDexFileImpl {}

macro_rules! dex_container_check {
    ($container:ident, $py:ident, $method:expr) => {
        if $container.get_refcnt($py) == 0 {
            return Err(PyValueError::new_err(concat!(
                "Tried to execute DexFile::",
                stringify!($method),
                " on a dex container that was deleted by Python!"
            )));
        }
    };
}

macro_rules! dex_action_impl {
    ($this:ident, $method:ident, $py:ident) => {{
        match &$this.inner.as_ref() {
            RsDexFile::InMemory { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method()
            }
            RsDexFile::File { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method()
            }
        }
    }};
    ($this:ident, $method:ident, $arg:expr, $py:ident) => {{
        match &$this.inner.as_ref() {
            RsDexFile::InMemory { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($arg)?
            }
            RsDexFile::File { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($arg)?
            }
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
        data: Py<PyInMemoryDexContainer>,
        preset: PyVerifyPreset,
    ) -> PyResult<PyDexFileImpl> {
        let preset = preset.into();
        let dex = PyInMemoryDexFile::open(data.get(), DexLocation::InMemory, preset)?;
        Ok(bind_dex!(dex, InMemory, data, py))
    }

    #[staticmethod]
    #[pyo3(signature = (
        data,
        preset=PyVerifyPreset::ALL
    ))]
    pub fn from_file<'py>(
        py: Python<'py>,
        data: Py<PyFileDexContainer>,
        preset: PyVerifyPreset,
    ) -> PyResult<PyDexFileImpl> {
        let preset = preset.into();
        let container = data.get();
        let dex = PyDexFile::open(
            data.get(),
            DexLocation::Path(container.path.clone()),
            preset,
        )?;
        Ok(bind_dex!(dex, File, data, py))
    }

    pub fn get_header<'py>(&self, py: Python<'py>) -> PyResult<PyDexHeader> {
        Ok(dex_action_impl!(self, get_header, py).into())
    }

    // ----------------------------------------------------------------------------
    // String Ids
    // ----------------------------------------------------------------------------
    pub fn get_string_id<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<PyDexStringId> {
        Ok(dex_action_impl!(self, get_string_id, index, py).into())
    }

    pub fn get_string_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<Option<PyDexStringId>> {
        Ok(dex_action_impl!(self, get_string_id_opt, index, py).map(Into::into))
    }

    pub fn num_string_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_string_ids, py))
    }

    // ----------------------------------------------------------------------------
    // string data
    // ----------------------------------------------------------------------------

    pub fn get_utf16_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_utf16_str_at, index, py))
    }

    pub fn get_utf16<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_utf16_str, &string_id, py))
    }
}

// final module
#[pyo3::pymodule(name = "file")]
pub(crate) mod file_mod {

    #[pymodule_export]
    use super::{PyDexFileImpl, PyVerifyPreset};
}
