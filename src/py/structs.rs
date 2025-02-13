use std::sync::Arc;

use crate::file::{
    ClassDef, FieldId, Header, MethodId, ProtoId, ProtoIndex, StringId, StringIndex, TypeId,
    TypeIndex, TypeItem,
};

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

// --------------------------------------------------------------------
// Header
// --------------------------------------------------------------------
py_struct_wrapper!("Header", PyDexHeader, Header);
py_struct_fields!(PyDexHeader, {
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

// --------------------------------------------------------------------
// StringId
// --------------------------------------------------------------------
py_struct_wrapper!("StringId", PyDexStringId, StringId);
py_struct_fields!(PyDexStringId, {
    (string_data_off, StringIndex),
},);

// --------------------------------------------------------------------
// TypeId
// --------------------------------------------------------------------
py_struct_wrapper!("TypeId", PyDexTypeId, TypeId);
py_struct_fields!(PyDexTypeId, {
    (descriptor_idx, StringIndex),
},);

// --------------------------------------------------------------------
// FieldId
// --------------------------------------------------------------------
py_struct_wrapper!("FieldId", PyDexFieldId, FieldId);
py_struct_fields!(PyDexFieldId, {
    (class_idx, TypeIndex),
    (type_idx, TypeIndex),
    (name_idx, StringIndex),
},);

// --------------------------------------------------------------------
// ProtoId
// --------------------------------------------------------------------
py_struct_wrapper!("ProtoId", PyDexProtoId, ProtoId);
py_struct_fields!(PyDexProtoId, {
    (shorty_idx, StringIndex),
    (return_type_idx, TypeIndex),
    (parameters_off, u32),
},);

// --------------------------------------------------------------------
// MethodId
// --------------------------------------------------------------------
py_struct_wrapper!("MethodId", PyDexMethodId, MethodId);
py_struct_fields!(PyDexMethodId, {
    (class_idx, TypeIndex),
    (proto_idx, ProtoIndex),
    (name_idx, StringIndex),
},);

// --------------------------------------------------------------------
// ClassDef
// --------------------------------------------------------------------
py_struct_wrapper!("ClassDef", PyDexClassDef, ClassDef);
py_struct_fields!(PyDexClassDef, {
    (class_idx, TypeIndex),
    (access_flags, u32),
    (superclass_idx, TypeIndex),
    (interfaces_off, u32),
    (source_file_idx, StringIndex),
    (annotations_off, u32),
    (class_data_off, u32),
    (static_values_off, u32),
},);

// --------------------------------------------------------------------
// TypeItem
// --------------------------------------------------------------------
py_struct_wrapper!("TypeItem", PyDexTypeItem, TypeItem);
py_struct_fields!(PyDexTypeItem, {
    (type_idx, TypeIndex),
},);

#[pyo3::pymodule(name = "structs")]
pub(crate) mod py_structs {

    #[pymodule_export]
    use super::{
        PyDexClassDef, PyDexFieldId, PyDexHeader, PyDexMethodId, PyDexProtoId, PyDexStringId,
        PyDexTypeId, PyDexTypeItem,
    };
}
