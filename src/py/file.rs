use std::sync::Arc;

use pyo3::{exceptions::PyValueError, Py, PyResult, Python};

use crate::file::{
    verifier::VerifyPreset, DexFile, DexLocation, FieldIndex, ProtoIndex, PyDexClassDef,
    PyDexFieldId, PyDexHeader, PyDexMethodId, PyDexProtoId, PyDexStringId, PyDexTypeId,
    PyDexTypeItem, PyFileDexContainer, PyInMemoryDexContainer, StringIndex, TypeIndex,
};
use crate::file::{
    AnnotationSetItem, PyCodeItemAccessor, PyDexAnnotationItem, PyDexCatchHandlerData,
    PyDexClassAnnotationsAccessor, PyDexTryItem,
};

use crate::file::class_accessor::PyClassAccessor;
use crate::file::signature::Signature;
use crate::py::structs::PyLocalInfo;

// ---------------------------------------------------------------------------
// PySignature
// ---------------------------------------------------------------------------

/// A decoded method signature: `"(param1param2...)return_type"`.
#[pyo3::pyclass(name = "Signature", module = "dexrs._internal.file")]
pub struct PySignature {
    inner: String,
    num_params: u32,
    is_void: bool,
}

impl From<Signature> for PySignature {
    fn from(s: Signature) -> Self {
        PySignature {
            is_void: s.is_void(),
            num_params: s.num_params(),
            inner: s.as_str().to_owned(),
        }
    }
}

#[pyo3::pymethods]
impl PySignature {
    /// Number of explicit parameters in the signature.
    #[getter]
    pub fn num_params(&self) -> u32 {
        self.num_params
    }

    /// `True` if the return type is `void`.
    #[getter]
    pub fn is_void(&self) -> bool {
        self.is_void
    }

    pub fn __str__(&self) -> &str {
        &self.inner
    }

    pub fn __repr__(&self) -> String {
        format!("Signature({:?})", self.inner)
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[pyo3::pyclass(name = "VerifyPreset", module = "dexrs._internal.file", eq, eq_int)]
pub enum PyVerifyPreset {
    ALL = 1,
    CHECKSUM_ONLY = 2,
    NONE = 3,
}

impl From<PyVerifyPreset> for VerifyPreset {
    fn from(val: PyVerifyPreset) -> Self {
        match val {
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
        #[allow(clippy::missing_transmute_annotations)]
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

fn check_container_alive<C: pyo3::PyClass>(container: &Py<C>, py: Python) -> PyResult<()> {
    if container.get_refcnt(py) == 0 {
        return Err(PyValueError::new_err(
            "DexFile: the backing container was deleted by Python",
        ));
    }
    Ok(())
}

/// Dispatch a closure over the inner `DexFile`, checking that the Python
/// container is still alive first.  The closure receives a reference to the
/// concrete `DexFile<'_, C>` and should return `PyResult<R>`.
macro_rules! with_dex {
    ($this:ident, $py:ident, |$dex:ident| $body:expr) => {
        match $this.inner.as_ref() {
            RsDexFile::InMemory {
                dex: $dex,
                container,
            } => {
                check_container_alive(container, $py)?;
                $body
            }
            RsDexFile::File {
                dex: $dex,
                container,
            } => {
                check_container_alive(container, $py)?;
                $body
            }
        }
    };
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
        Ok(with_dex!(self, py, |dex| dex.get_header().into()))
    }

    /// Returns `True` for CompactDex (`cdex` magic) files.
    pub fn is_compact_dex<'py>(&self, py: Python<'py>) -> PyResult<bool> {
        Ok(with_dex!(self, py, |dex| dex.is_compact_dex()))
    }

    /// Returns `True` for standard DEX (`dex\n` magic) files.
    pub fn is_standard_dex<'py>(&self, py: Python<'py>) -> PyResult<bool> {
        Ok(with_dex!(self, py, |dex| dex.is_standard_dex()))
    }

    // ----------------------------------------------------------------------------
    // String Ids
    // ----------------------------------------------------------------------------
    pub fn get_string_id<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<PyDexStringId> {
        Ok(with_dex!(self, py, |dex| dex.get_string_id(index)?.into()))
    }

    pub fn get_string_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<Option<PyDexStringId>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_string_id_opt(index)?.map(Into::into)))?)
    }

    pub fn num_string_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_string_ids()))
    }

    // ----------------------------------------------------------------------------
    // Type Ids
    // ----------------------------------------------------------------------------
    pub fn get_type_id<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<PyDexTypeId> {
        Ok(with_dex!(self, py, |dex| dex.get_type_id(index)?.into()))
    }

    pub fn get_type_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: TypeIndex,
    ) -> PyResult<Option<PyDexTypeId>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_type_id_opt(index)?.map(Into::into)))?)
    }

    pub fn num_type_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_type_ids()))
    }

    pub fn get_type_desc<'py>(
        &self,
        py: Python<'py>,
        type_id: Py<PyDexTypeId>,
    ) -> PyResult<String> {
        let rs_type_id = &type_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_type_desc_utf16(rs_type_id)?))
    }

    pub fn get_type_desc_at<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.get_type_desc_utf16_at(index)?))
    }

    pub fn pretty_type_at<'py>(&self, py: Python<'py>, index: TypeIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.pretty_type_at(index)))
    }

    pub fn pretty_type<'py>(&self, py: Python<'py>, type_id: Py<PyDexTypeId>) -> PyResult<String> {
        let rs_type_id = &type_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.pretty_type(rs_type_id)))
    }

    // ----------------------------------------------------------------------------
    // Field Ids
    // ----------------------------------------------------------------------------
    pub fn get_field_id<'py>(&self, py: Python<'py>, index: FieldIndex) -> PyResult<PyDexFieldId> {
        Ok(with_dex!(self, py, |dex| dex.get_field_id(index)?.into()))
    }

    pub fn get_field_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: FieldIndex,
    ) -> PyResult<Option<PyDexFieldId>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_field_id_opt(index)?.map(Into::into)))?)
    }

    pub fn num_field_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_field_ids()))
    }

    pub fn get_field_name<'py>(
        &self,
        py: Python<'py>,
        field_id: Py<PyDexFieldId>,
    ) -> PyResult<String> {
        let rs_field_id = &field_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_field_name(rs_field_id)?))
    }

    pub fn get_field_name_at<'py>(&self, py: Python<'py>, index: FieldIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.get_field_name_at(index)?))
    }

    // ----------------------------------------------------------------------------
    // Proto Ids
    // ----------------------------------------------------------------------------
    pub fn get_proto_id<'py>(&self, py: Python<'py>, index: ProtoIndex) -> PyResult<PyDexProtoId> {
        Ok(with_dex!(self, py, |dex| dex.get_proto_id(index)?.into()))
    }

    pub fn get_proto_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: ProtoIndex,
    ) -> PyResult<Option<PyDexProtoId>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_proto_id_opt(index)?.map(Into::into)))?)
    }

    pub fn num_proto_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_proto_ids()))
    }

    pub fn get_shorty<'py>(&self, py: Python<'py>, proto_id: Py<PyDexProtoId>) -> PyResult<String> {
        let rs_proto_id = &proto_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_shorty(rs_proto_id)?))
    }

    pub fn get_shorty_at<'py>(&self, py: Python<'py>, index: ProtoIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.get_shorty_at(index)?))
    }

    // ----------------------------------------------------------------------------
    // method ids
    // ----------------------------------------------------------------------------
    pub fn get_method_id<'py>(&self, py: Python<'py>, index: u32) -> PyResult<PyDexMethodId> {
        Ok(with_dex!(self, py, |dex| dex.get_method_id(index)?.into()))
    }

    pub fn get_method_id_opt<'py>(
        &self,
        py: Python<'py>,
        index: u32,
    ) -> PyResult<Option<PyDexMethodId>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_method_id_opt(index)?.map(Into::into)))?)
    }

    pub fn num_method_ids<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_method_ids()))
    }

    //------------------------------------------------------------------------------
    // ClassDefs
    //------------------------------------------------------------------------------
    pub fn get_class_def<'py>(&self, py: Python<'py>, index: u32) -> PyResult<PyDexClassDef> {
        Ok(with_dex!(self, py, |dex| dex.get_class_def(index)?.into()))
    }

    pub fn get_class_def_opt<'py>(
        &self,
        py: Python<'py>,
        index: u32,
    ) -> PyResult<Option<PyDexClassDef>> {
        Ok(with_dex!(self, py, |dex| Ok::<_, crate::error::DexError>(dex.get_class_def_opt(index)?.map(Into::into)))?)
    }

    pub fn num_class_defs<'py>(&self, py: Python<'py>) -> PyResult<u32> {
        Ok(with_dex!(self, py, |dex| dex.num_class_defs()))
    }

    pub fn get_class_desc<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<String> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_class_desc_utf16(rs_class_def)?))
    }

    pub fn get_interfaces_list<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<Option<Vec<PyDexTypeItem>>> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex
            .get_interfaces_list(rs_class_def)?
            .map(|x| x.iter().map(Into::into).collect())))
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
        Ok(with_dex!(self, py, |dex| dex.get_class_accessor(rs_class_def)?.map(Into::into)))
    }

    // ----------------------------------------------------------------------------
    // code item accessor
    // ----------------------------------------------------------------------------
    pub fn get_code_item_accessor<'py>(
        &self,
        py: Python<'py>,
        code_offset: u32,
    ) -> PyResult<PyCodeItemAccessor> {
        Ok(with_dex!(self, py, |dex| dex.get_code_item_accessor(code_offset)?.into()))
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
        Ok(with_dex!(self, py, |dex| dex
            .get_try_items(code_item_accessor)?
            .iter()
            .map(Into::into)
            .collect::<Vec<PyDexTryItem>>()))
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
        let iterator = with_dex!(self, py, |dex| dex.iter_catch_handlers(code_item_accessor, rs_try_item)?);
        match iterator {
            None => Ok(vec![]),
            Some(iterator) => Ok(iterator
                .into_iter()
                .map(Into::into)
                .collect::<Vec<PyDexCatchHandlerData>>()),
        }
    }

    //------------------------------------------------------------------------------
    // Annotations
    //------------------------------------------------------------------------------
    pub fn get_annotation_set<'py>(
        &self,
        py: Python<'py>,
        offset: u32,
    ) -> PyResult<AnnotationSetItem<'_>> {
        Ok(with_dex!(self, py, |dex| dex.get_annotation_set(offset)?))
    }

    pub fn get_annotation<'py>(
        &self,
        py: Python<'py>,
        offset: u32,
    ) -> PyResult<PyDexAnnotationItem> {
        Ok(with_dex!(self, py, |dex| dex.get_annotation(offset)?.into()))
    }

    pub fn get_class_annotation_accessor<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<PyDexClassAnnotationsAccessor> {
        let rs_class_def = &class_def.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_class_annotation_accessor(rs_class_def.annotations_off)?.into()))
    }

    // ----------------------------------------------------------------------------
    // string data
    // ----------------------------------------------------------------------------
    pub fn get_utf16_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.get_str_at(index)?))
    }

    pub fn get_utf16<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_str(string_id)?))
    }

    pub fn get_utf16_opt_at<'py>(
        &self,
        py: Python<'py>,
        index: StringIndex,
    ) -> PyResult<Option<String>> {
        Ok(with_dex!(self, py, |dex| dex.get_str_opt_at(index)?))
    }

    pub fn get_utf16_lossy_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        Ok(with_dex!(self, py, |dex| dex.get_str_lossy_at(index)?))
    }

    pub fn get_utf16_lossy<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_str_lossy(string_id)?))
    }

    pub fn get_string_data<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<(u32, &'py [u8])> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        Ok(with_dex!(self, py, |dex| dex.get_string_data(string_id)?))
    }

    // unsafe string API
    pub fn fast_get_utf8<'py>(
        &self,
        py: Python<'py>,
        py_string_id: Py<PyDexStringId>,
    ) -> PyResult<String> {
        let string_id = &py_string_id.try_borrow(py)?.0;
        // SAFETY: caller accepts that invalid MUTF-8 may produce garbage output
        Ok(with_dex!(self, py, |dex| unsafe { dex.fast_get_utf8_str(string_id)? }))
    }

    pub fn fast_get_utf8_at<'py>(&self, py: Python<'py>, index: StringIndex) -> PyResult<String> {
        // SAFETY: caller accepts that invalid MUTF-8 may produce garbage output
        Ok(with_dex!(self, py, |dex| unsafe { dex.fast_get_utf8_str_at(index)? }))
    }

    // ----------------------------------------------------------------------------
    // ART-parity additions
    // ----------------------------------------------------------------------------

    /// Returns the Java-visible access flags for a class def (lower 16 bits).
    pub fn get_java_access_flags<'py>(
        &self,
        py: Python<'py>,
        class_def: Py<PyDexClassDef>,
    ) -> PyResult<u32> {
        let cd = class_def.try_borrow(py)?;
        Ok(cd.0.access_flags & 0xFFFF)
    }

    /// Returns the parameter type list for a proto_id, or `None` if it has no parameters.
    pub fn get_proto_parameters<'py>(
        &self,
        py: Python<'py>,
        proto_id: Py<PyDexProtoId>,
    ) -> PyResult<Option<Vec<PyDexTypeItem>>> {
        let pid = proto_id.try_borrow(py)?;
        Ok(with_dex!(self, py, |dex| {
            dex.get_proto_parameters(&pid.0)?
                .map(|tl| tl.iter().map(Into::into).collect())
        }))
    }

    /// Returns the method signature as a rich `Signature` object.
    pub fn get_method_signature<'py>(
        &self,
        py: Python<'py>,
        method_idx: u32,
    ) -> PyResult<PySignature> {
        Ok(with_dex!(self, py, |dex| {
            dex.get_method_signature(method_idx)?.into()
        }))
    }

    /// Builds a `TypeLookupTable` for fast O(1) class lookup by type descriptor.
    pub fn build_type_lookup_table<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<crate::py::type_lookup_table::PyTypeLookupTable> {
        Ok(with_dex!(self, py, |dex| {
            crate::py::type_lookup_table::PyTypeLookupTable(dex.build_type_lookup_table())
        }))
    }

    /// Decodes the hidden-API flags stream for a given class.
    ///
    /// `class_def_idx` identifies the class; `count` is the total number of
    /// fields + methods (determines how many ULEB128 values to decode).
    pub fn get_hiddenapi_class_flags<'py>(
        &self,
        py: Python<'py>,
        class_def_idx: u32,
        count: usize,
    ) -> PyResult<Option<Vec<u32>>> {
        Ok(with_dex!(self, py, |dex| {
            dex.get_hiddenapi_class_flags(class_def_idx, count)
        }))
    }

    /// Returns the source line number for the given DEX program counter.
    ///
    /// `debug_info_off` is the offset from `CodeItem::debug_info_off`.
    /// Returns `None` if no position entry covers `dex_pc`.
    pub fn get_line_for_pc<'py>(
        &self,
        py: Python<'py>,
        debug_info_off: u32,
        dex_pc: u32,
    ) -> PyResult<Option<u32>> {
        Ok(with_dex!(self, py, |dex| {
            dex.get_debug_info_accessor(debug_info_off)?.get_line_for_pc(dex_pc)?
        }))
    }

    /// Decodes the local variable table from a debug info stream.
    ///
    /// Returns a list of `LocalInfo` entries (including still-live locals at
    /// end of method).  `num_regs` should be `CodeItem.registers_size`.
    pub fn decode_local_info<'py>(
        &self,
        py: Python<'py>,
        debug_info_off: u32,
        num_regs: u16,
    ) -> PyResult<Vec<PyLocalInfo>> {
        Ok(with_dex!(self, py, |dex| {
            let accessor = dex.get_debug_info_accessor(debug_info_off)?;
            let mut locals = Vec::new();
            accessor.decode_local_info(num_regs, |li| locals.push(PyLocalInfo::from(li)))?;
            locals
        }))
    }
}

// final module
#[pyo3::pymodule(name = "file")]
pub(crate) mod py_file {

    #[pymodule_export]
    use super::{PyDexFileImpl, PySignature, PyVerifyPreset};
}
