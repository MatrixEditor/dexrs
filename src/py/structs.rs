use std::sync::{Arc, Mutex};

use crate::file::Header;

macro_rules! py_struct_wrapper {
    ($name:literal, $py_type:ident, $rust_type:ident) => {
        #[pyo3::pyclass(name = $name, module = "dexrs._internal.structs")]
        pub struct $py_type(pub Arc<$rust_type>);

        impl<'a> From<&'a $rust_type> for $py_type {
            fn from(value: &'a $rust_type) -> Self {
                $py_type(Arc::new(value.clone()))
            }
        }
    };
}

macro_rules! py_struct_fields {
    ($py_type:ident, { $(($name:ident, $rtype:ty),)+ }, $($extra:tt)*) => {
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

py_struct_wrapper!("Header", PyHeader, Header);

py_struct_fields!(PyHeader, {
    (checksum, u32),
    (file_size, u32),
    (header_size, u32),
    (endian_tag, u32),
    (link_size, u32),
    (link_off, u32),
    (string_ids_size, u32),
    (string_ids_off, u32),
    (type_ids_size, u32),
    (type_ids_off, u32),
    (proto_ids_size, u32),
    (proto_ids_off, u32),
    (field_ids_size, u32),
    (field_ids_off, u32),
    (method_ids_size, u32),
    (method_ids_off, u32),
    (class_defs_size, u32),
    (class_defs_off, u32),
    (data_size, u32),
    (data_off, u32),
},

#[getter]
pub fn signature(&self) -> Vec<u8> {
    self.0.get_signature().to_vec()
}

#[getter]
pub fn version_int(&self) -> u32 {
    self.0.get_version()
}

#[getter]
pub fn get_magic(&self) -> Vec<u8> {
    self.0.get_magic().to_vec()
}
);

#[pyo3::pymodule]
pub(crate) mod structs {

    #[pymodule_export]
    use super::PyHeader;
}
