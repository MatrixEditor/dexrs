use std::sync::Arc;

use pyo3::PyResult;

use crate::file::{ClassAccessor, Field, Method};

// Rust-side of the class accessor
//
// However, this may seem invalid, there's actually no need for us to
// use mem::transmute here, because only Rust can create instances of
// this type.
pub struct RsClassAccessor(ClassAccessor<'static>);

#[pyo3::pyclass(name = "ClassAccessor", module = "dexrs._internal.class_accessor")]
pub struct PyClassAccessor {
    inner: Arc<RsClassAccessor>,
}

impl PyClassAccessor {
    // Rust interface
    pub fn from_instance(class_accessor: ClassAccessor<'static>) -> PyClassAccessor {
        PyClassAccessor {
            inner: Arc::new(RsClassAccessor(class_accessor)),
        }
    }
}

impl From<ClassAccessor<'static>> for PyClassAccessor {
    fn from(class_accessor: ClassAccessor<'static>) -> Self {
        PyClassAccessor::from_instance(class_accessor)
    }
}


#[pyo3::pymethods]
impl PyClassAccessor {
    // no constructor
    #[getter]
    pub fn num_fields(&self) -> usize {
        self.inner.0.num_fields()
    }

    #[getter]
    pub fn num_methods(&self) -> usize {
        self.inner.0.num_methods()
    }

    #[getter]
    pub fn num_static_fields(&self) -> u32 {
        self.inner.0.num_static_fields
    }

    #[getter]
    pub fn num_instance_fields(&self) -> u32 {
        self.inner.0.num_instance_fields
    }

    #[getter]
    pub fn num_direct_methods(&self) -> u32 {
        self.inner.0.num_direct_methods
    }

    #[getter]
    pub fn num_virtual_methods(&self) -> u32 {
        self.inner.0.num_virtual_methods
    }

    pub fn get_fields(&self) -> PyResult<Vec<PyDexField>> {
        Ok(self.inner.0.get_fields().map(Into::into).collect())
    }

    pub fn get_static_fieds(&self) -> PyResult<Vec<PyDexField>> {
        Ok(self.inner.0.get_static_fieds().map(Into::into).collect())
    }

    pub fn get_instance_fields(&self) -> PyResult<Vec<PyDexField>> {
        Ok(self.inner.0.get_instance_fields().map(Into::into).collect())
    }

    pub fn get_methods(&self) -> PyResult<Vec<PyDexMethod>> {
        Ok(self.inner.0.get_methods()?.map(Into::into).collect())
    }

    pub fn get_virtual_methods(&self) -> PyResult<Vec<PyDexMethod>> {
        Ok(self
            .inner
            .0
            .get_virtual_methods()?
            .map(Into::into)
            .collect())
    }

    pub fn get_direct_methods(&self) -> PyResult<Vec<PyDexMethod>> {
        Ok(self.inner.0.get_direct_methods()?.map(Into::into).collect())
    }
}

#[pyo3::pyclass(name = "Method", module = "dexrs._internal.class_accessor")]
pub struct PyDexMethod(Arc<Method>);

impl From<Method> for PyDexMethod {
    fn from(method: Method) -> Self {
        PyDexMethod(Arc::new(method))
    }
}

#[pyo3::pymethods]
impl PyDexMethod {
    #[getter]
    pub fn index(&self) -> u32 {
        self.0.index
    }

    #[getter]
    pub fn access_flags(&self) -> u32 {
        self.0.access_flags
    }

    #[getter]
    pub fn code_offset(&self) -> u32 {
        self.0.code_offset
    }

    pub fn is_static_or_direct(&self) -> bool {
        self.0.is_static_or_direct
    }
}

#[pyo3::pyclass(name = "Field", module = "dexrs._internal.class_accessor")]
pub struct PyDexField(Arc<Field>);

impl From<Field> for PyDexField {
    fn from(field: Field) -> Self {
        PyDexField(Arc::new(field))
    }
}

#[pyo3::pymethods]
impl PyDexField {
    #[getter]
    pub fn index(&self) -> u32 {
        self.0.index
    }

    #[getter]
    pub fn access_flags(&self) -> u32 {
        self.0.access_flags
    }

    pub fn is_static(&self) -> bool {
        self.0.is_static
    }
}

#[pyo3::pymodule]
pub mod py_class_accessor {
    #[pymodule_export]
    use super::{PyClassAccessor, PyDexField, PyDexMethod};
}
