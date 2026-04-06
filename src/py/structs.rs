use crate::file::debug::LocalInfo;

/// Python representation of a local variable decoded from a debug info stream.
#[pyo3::pyclass(name = "LocalInfo", module = "dexrs._internal.structs")]
pub struct PyLocalInfo {
    #[pyo3(get)]
    pub name_idx: Option<u32>,
    #[pyo3(get)]
    pub descriptor_idx: Option<u32>,
    #[pyo3(get)]
    pub signature_idx: Option<u32>,
    #[pyo3(get)]
    pub start_address: u32,
    #[pyo3(get)]
    pub end_address: u32,
    #[pyo3(get)]
    pub reg: u16,
    #[pyo3(get)]
    pub is_live: bool,
}

impl From<&LocalInfo> for PyLocalInfo {
    fn from(li: &LocalInfo) -> Self {
        PyLocalInfo {
            name_idx: li.name_idx,
            descriptor_idx: li.descriptor_idx,
            signature_idx: li.signature_idx,
            start_address: li.start_address,
            end_address: li.end_address,
            reg: li.reg,
            is_live: li.is_live,
        }
    }
}

#[pyo3::pymethods]
impl PyLocalInfo {
    pub fn __repr__(&self) -> String {
        format!(
            "LocalInfo(reg={}, range={}..{}, name={:?})",
            self.reg, self.start_address, self.end_address, self.name_idx
        )
    }
}

#[pyo3::pymodule(name = "structs")]
pub(crate) mod py_structs {
    #[pymodule_export]
    use crate::file::structs::{
        PyDexAnnotationElement, PyDexAnnotationItem, PyDexAnnotationsDirectoryItem,
        PyDexCallSiteIdItem, PyDexCatchHandlerData, PyDexClassDef, PyDexCodeItem,
        PyDexEncodedAnnotation, PyDexEncodedValue, PyDexFieldAnnotationsItem, PyDexFieldId,
        PyDexMethodAnnotationsItem, PyDexMethodHandleItem, PyDexMethodId,
        PyDexParameterAnnotationsItem, PyDexProtoId, PyDexStringId, PyDexTryItem, PyDexTypeId,
        PyDexTypeItem,
    };

    #[pymodule_export]
    use crate::file::header::PyDexHeader;

    #[pymodule_export]
    use super::PyLocalInfo;
}
