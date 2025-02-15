pub(crate) mod file;

macro_rules! rs_type_wrapper {
    ($src_type:ty, $py_type:ident, $rs_type:ident, name: $name:literal, module: $module:literal) => {
        #[cfg(feature = "python")]
        pub struct $rs_type($src_type);

        #[cfg(feature = "python")]
        #[pyo3::pyclass(name = $name, module = $module)]
        pub struct $py_type {
            inner: Arc<$rs_type>,
        }

        #[cfg(feature = "python")]
        impl From<$src_type> for $py_type {
            fn from(value: $src_type) -> Self {
                $py_type {
                    inner: Arc::new($rs_type(value)),
                }
            }
        }

        #[cfg(feature = "python")]
        impl $py_type {
            pub fn from_instance(value: $src_type) -> Self {
                $py_type::from(value)
            }
        }
    };
    ($src_type:ty, $py_type:ident, name: $name:literal, module: $module:literal) => {
        #[cfg(feature = "python")]
        #[pyo3::pyclass(name = $name, module = $module)]
        pub struct $py_type(Arc<$src_type>);

        #[cfg(feature = "python")]
        impl From<$src_type> for $py_type {
            fn from(value: $src_type) -> Self {
                $py_type(Arc::new(value))
            }
        }
    };
}

macro_rules! rs_struct_wrapper {
    ($name:literal, $py_type:ident, $rust_type:ident) => {
        #[cfg(feature = "python")]
        #[pyo3::pyclass(name = $name, module = "dexrs._internal.structs")]
        pub struct $py_type(pub Arc<$rust_type>);

        #[cfg(feature = "python")]
        impl<'a> From<&'a $rust_type> for $py_type {
            fn from(value: &'a $rust_type) -> Self {
                $py_type(Arc::new(value.clone()))
            }
        }
    };
}

macro_rules! rs_struct_fields {
    ($py_type:ident, { $(($name:ident, $rtype:ty),)+ }, $($extra:tt)*) => {
        #[cfg(feature = "python")]
        #[pyo3::pymethods]
        impl $py_type {
            $(
            #[getter]
            pub fn $name(&self) -> $rtype {
                    self.0.$name
                }
            )+

            $(
                $extra
            )*
        }
    };
}

pub(crate) use rs_type_wrapper;
pub(crate) use rs_struct_wrapper;
pub(crate) use rs_struct_fields;