use crate::primitive::PrimitiveType;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[pyo3::pyclass(
    name = "PrimitiveType",
    module = "dexrs._internal.primitive",
    eq,
    eq_int
)]
pub enum PyPrimitiveType {
    Not = 0,
    Boolean = 1,
    Byte = 2,
    Char = 3,
    Short = 4,
    Int = 5,
    Long = 6,
    Float = 7,
    Double = 8,
    Void = 9,
}

impl From<PrimitiveType> for PyPrimitiveType {
    fn from(p: PrimitiveType) -> Self {
        match p {
            PrimitiveType::Not => PyPrimitiveType::Not,
            PrimitiveType::Boolean => PyPrimitiveType::Boolean,
            PrimitiveType::Byte => PyPrimitiveType::Byte,
            PrimitiveType::Char => PyPrimitiveType::Char,
            PrimitiveType::Short => PyPrimitiveType::Short,
            PrimitiveType::Int => PyPrimitiveType::Int,
            PrimitiveType::Long => PyPrimitiveType::Long,
            PrimitiveType::Float => PyPrimitiveType::Float,
            PrimitiveType::Double => PyPrimitiveType::Double,
            PrimitiveType::Void => PyPrimitiveType::Void,
        }
    }
}

impl From<PyPrimitiveType> for PrimitiveType {
    fn from(p: PyPrimitiveType) -> Self {
        match p {
            PyPrimitiveType::Not => PrimitiveType::Not,
            PyPrimitiveType::Boolean => PrimitiveType::Boolean,
            PyPrimitiveType::Byte => PrimitiveType::Byte,
            PyPrimitiveType::Char => PrimitiveType::Char,
            PyPrimitiveType::Short => PrimitiveType::Short,
            PyPrimitiveType::Int => PrimitiveType::Int,
            PyPrimitiveType::Long => PrimitiveType::Long,
            PyPrimitiveType::Float => PrimitiveType::Float,
            PyPrimitiveType::Double => PrimitiveType::Double,
            PyPrimitiveType::Void => PrimitiveType::Void,
        }
    }
}

#[pyo3::pymethods]
impl PyPrimitiveType {
    /// Returns the single-char DEX type descriptor, or `None` for `Not`.
    pub fn descriptor(&self) -> Option<&'static str> {
        PrimitiveType::from(*self).descriptor()
    }

    /// Returns the boxed class descriptor, or `None` for `Not`.
    pub fn boxed_descriptor(&self) -> Option<&'static str> {
        PrimitiveType::from(*self).boxed_descriptor()
    }

    /// Returns the storage size in bytes.
    pub fn component_size(&self) -> usize {
        PrimitiveType::from(*self).component_size()
    }

    /// Returns `True` for numeric primitive types.
    pub fn is_numeric(&self) -> bool {
        PrimitiveType::from(*self).is_numeric()
    }

    /// Returns `True` for 64-bit types (long or double).
    pub fn is_64bit(&self) -> bool {
        PrimitiveType::from(*self).is_64bit()
    }

    /// Returns the human-readable Java type name.
    pub fn pretty_name(&self) -> &'static str {
        PrimitiveType::from(*self).pretty_name()
    }

    pub fn __str__(&self) -> &'static str {
        PrimitiveType::from(*self).pretty_name()
    }

    /// Creates a `PrimitiveType` from a JVM descriptor character.
    #[staticmethod]
    pub fn from_char(c: char) -> PyPrimitiveType {
        PrimitiveType::from_char(c).into()
    }
}

#[pyo3::pymodule(name = "primitive")]
pub(crate) mod py_primitive {
    #[pymodule_export]
    use super::PyPrimitiveType;
}
