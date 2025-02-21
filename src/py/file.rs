use std::sync::Arc;

use pyo3::{exceptions::PyValueError, Py, PyResult, Python};

use crate::file::{
    verifier::VerifyPreset, DexFile, DexLocation, FieldIndex, ProtoIndex, PyDexClassDef,
    PyDexFieldId, PyDexHeader, PyDexMethodId, PyDexProtoId, PyDexStringId, PyDexTypeId,
    PyDexTypeItem, PyFileDexContainer, PyInMemoryDexContainer, StringIndex, TypeIndex,
};
use crate::file::{PyCodeItemAccessor, PyDexCatchHandlerData, PyDexTryItem};

use crate::file::class_accessor::PyClassAccessor;

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
    pub(crate) inner: Arc<RsDexFile>,
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

// REVISIT: this can be reduced
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
    ($this:ident, $method:ident($($args:tt)*)?, $py:ident) => {{
        match &$this.inner.as_ref() {
            RsDexFile::InMemory { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($($args)*)?
            }
            RsDexFile::File { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($($args)*)?
            }
        }
    }};
    ($this:ident, $method:ident, $arg:expr, $py:ident) => {{
        match &$this.inner.as_ref() {
            RsDexFile::InMemory { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($arg)
            }
            RsDexFile::File { dex, container } => {
                dex_container_check!(container, $py, $method);
                dex.$method($arg)
            }
        }
    }};
    ($this:ident, unsafe { $method:ident }, $arg:expr, $py:ident) => {{
        match &$this.inner.as_ref() {
            RsDexFile::InMemory { dex, container } => {
                dex_container_check!(container, $py, $method);
                unsafe { dex.$method($arg)? }
            }
            RsDexFile::File { dex, container } => {
                dex_container_check!(container, $py, $method);
                unsafe { dex.$method($arg)? }
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
        Ok(dex_action_impl!(self, get_string_id(index)?, py).into())
    }

    pub fn get_string_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<Option<PyDexStringId>> {
        Ok(dex_action_impl!(self, get_string_id_opt(index)?, py).map(Into::into))
    }

    pub fn num_string_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_string_ids, py))
    }

    // ----------------------------------------------------------------------------
    // Type Ids
    // ----------------------------------------------------------------------------
    pub fn get_type_id<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<PyDexTypeId> {
        Ok(dex_action_impl!(self, get_type_id(index)?, py).into())
    }

    pub fn get_type_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: TypeIndex,
    ) -> PyResult<Option<PyDexTypeId>> {
        Ok(dex_action_impl!(self, get_type_id_opt(index)?, py).map(Into::into))
    }

    pub fn num_type_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_type_ids, py))
    }

    pub fn get_type_desc<'py>(
        &self,
        py: Python<'py>,
        type_id: Py<PyDexTypeId>,
    ) -> PyResult<String> {
        let rs_type_id = &type_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_type_desc_utf16(rs_type_id)?, py))
    }

    pub fn get_type_desc_at<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_type_desc_utf16_at(index)?, py))
    }

    pub fn pretty_type_at<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, pretty_type_at, index, py))
    }

    pub fn pretty_type<'py>(&self, py: Python<'py>, type_id: Py<PyDexTypeId>) -> PyResult<String> {
        let rs_type_id = &type_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, pretty_type, rs_type_id, py))
    }

    // ----------------------------------------------------------------------------
    // Field Ids
    // ----------------------------------------------------------------------------
    pub fn get_field_id<'py>(&self, py: Python<'py>, index: FieldIndex) -> PyResult<PyDexFieldId> {
        Ok(dex_action_impl!(self, get_field_id(index)?, py).into())
    }

    pub fn get_field_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: FieldIndex,
    ) -> PyResult<Option<PyDexFieldId>> {
        Ok(dex_action_impl!(self, get_field_id_opt(index)?, py).map(Into::into))
    }

    pub fn num_field_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_field_ids, py))
    }

    pub fn get_field_name<'py>(
        &self,
        py: Python<'py>,
        field_id: Py<PyDexFieldId>,
    ) -> PyResult<String> {
        let rs_field_id = &field_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_field_name(rs_field_id)?, py))
    }

    pub fn get_field_name_at<'py>(&self, py: Python<'py>, index: FieldIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_field_name_at(index)?, py))
    }

    // ----------------------------------------------------------------------------
    // Proto Ids
    // ----------------------------------------------------------------------------
    pub fn get_proto_id<'py>(&self, py: Python<'py>, index: ProtoIndex) -> PyResult<PyDexProtoId> {
        Ok(dex_action_impl!(self, get_proto_id(index)?, py).into())
    }

    pub fn get_proto_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: ProtoIndex,
    ) -> PyResult<Option<PyDexProtoId>> {
        Ok(dex_action_impl!(self, get_proto_id_opt(index)?, py).map(Into::into))
    }

    pub fn num_proto_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_proto_ids, py))
    }

    pub fn get_shorty<'py>(&self, py: Python<'py>, proto_id: Py<PyDexProtoId>) -> PyResult<String> {
        let rs_proto_id = &proto_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_shorty(rs_proto_id)?, py))
    }

    pub fn get_shorty_at<'py>(&self, py: Python<'py>, index: ProtoIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_shorty_at(index)?, py))
    }

    // ----------------------------------------------------------------------------
    // method ids
    // ----------------------------------------------------------------------------
    pub fn get_method_id<'py>(&self, py: Python<'py>, index: u32) -> PyResult<PyDexMethodId> {
        Ok(dex_action_impl!(self, get_method_id(index)?, py).into())
    }

    pub fn get_method_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: u32,
    ) -> PyResult<Option<PyDexMethodId>> {
        Ok(dex_action_impl!(self, get_method_id_opt(index)?, py).map(Into::into))
    }

    pub fn num_method_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_method_ids, py))
    }

    //------------------------------------------------------------------------------
    // ClassDefs
    //------------------------------------------------------------------------------
    pub fn get_class_def<'py>(&self, py: Python<'py>, index: u32) -> PyResult<PyDexClassDef> {
        Ok(dex_action_impl!(self, get_class_def(index)?, py).into())
    }

    pub fn get_class_def_opt<'py>(
        &self,
        py: Python<'py>,
        index: u32,
    ) -> PyResult<Option<PyDexClassDef>> {
        Ok(dex_action_impl!(self, get_class_def_opt(index)?, py).map(Into::into))
    }

    pub fn num_class_defs<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(dex_action_impl!(self, num_class_defs, py))
    }

    pub fn get_class_desc<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<String> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(dex_action_impl!(
            self,
            get_class_desc_utf16(rs_class_def)?,
            py
        ))
    }

    pub fn get_interfaces_list<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<Option<Vec<PyDexTypeItem>>> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(
            dex_action_impl!(self, get_interfaces_list(rs_class_def)?, py)
                .map(|x| x.iter().map(Into::into).collect()),
        )
    }

    // ----------------------------------------------------------------------------
    // class accessor
    // ----------------------------------------------------------------------------
    pub fn get_class_accessor<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<Option<PyClassAccessor>> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_class_accessor(rs_class_def)?, py).map(Into::into))
    }

    // ----------------------------------------------------------------------------
    // code item accessor
    // ----------------------------------------------------------------------------
    pub fn get_code_item_accessor<'py>(
        &self,
        py: Python<'py>,
        code_offset: u32,
    ) -> PyResult<PyCodeItemAccessor> {
        Ok(dex_action_impl!(self, get_code_item_accessor(code_offset)?, py).into())
    }

    //------------------------------------------------------------------------------
    // TryItem
    //------------------------------------------------------------------------------
    pub fn get_try_items<'py>(
        &self,
        py: Python<'py>,
        ca: Py<PyCodeItemAccessor>,
    ) -> PyResult<Vec<PyDexTryItem>> {
        let code_item_accessor = &ca.try_borrow(py)?.inner.0;
        Ok(
            dex_action_impl!(self, get_try_items(code_item_accessor)?, py)
                .into_iter()
                .map(Into::into)
                .collect::<Vec<PyDexTryItem>>(),
        )
    }

    //------------------------------------------------------------------------------
    // Encoded Catch Handlers
    //------------------------------------------------------------------------------
    pub fn get_catch_handlers<'py>(
        &self,
        py: Python<'py>,
        ca: Py<PyCodeItemAccessor>,
        try_item: Py<PyDexTryItem>,
    ) -> PyResult<Vec<PyDexCatchHandlerData>> {
        let code_item_accessor = &ca.try_borrow(py)?.inner.0;
        let rs_try_item = &try_item.try_borrow(py)?.0;
        Ok(dex_action_impl!(
            self,
            iter_catch_handlers(code_item_accessor, rs_try_item)?,
            py
        )
        .into_iter()
        .map(Into::into)
        .collect::<Vec<PyDexCatchHandlerData>>())
    }

    pub fn get_catch_handlers_at<'py>(
        &self,
        py: Python<'py>,
        ca: Py<PyCodeItemAccessor>,
        offset: u32,
    ) -> PyResult<Vec<PyDexCatchHandlerData>> {
        let code_item_accessor = &ca.try_borrow(py)?.inner.0;
        Ok(dex_action_impl!(
            self,
            iter_catch_handlers_at(code_item_accessor, offset as usize)?,
            py
        )
        .into_iter()
        .map(Into::into)
        .collect::<Vec<PyDexCatchHandlerData>>())
    }

    // ----------------------------------------------------------------------------
    // string data
    // ----------------------------------------------------------------------------
    pub fn get_utf16_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_utf16_str_at(index)?, py))
    }

    pub fn get_utf16<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_utf16_str(string_id)?, py))
    }

    pub fn get_utf16_opt_at<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<Option<String>> {
        Ok(dex_action_impl!(self, get_utf16_str_opt_at(index)?, py))
    }

    pub fn get_utf16_lossy_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(dex_action_impl!(self, get_utf16_str_lossy_at(index)?, py))
    }

    pub fn get_utf16_lossy<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_utf16_str_lossy(string_id)?, py))
    }

    pub fn get_string_data<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<(u32, &'py [u8])> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(self, get_string_data(string_id)?, py))
    }

    // unsafe string API
    pub fn fast_get_utf8<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(dex_action_impl!(
            self,
            unsafe { fast_get_utf8_str },
            &string_id,
            py
        ))
    }

    pub fn fast_get_utf8_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(dex_action_impl!(
            self,
            unsafe { fast_get_utf8_str_at },
            index,
            py
        ))
    }
}

// final module
#[pyo3::pymodule(name = "file")]
pub(crate) mod py_file {

    #[pymodule_export]
    use super::{PyDexFileImpl, PyVerifyPreset};
}
