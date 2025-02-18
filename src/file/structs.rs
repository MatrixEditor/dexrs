use plain::Plain;

#[cfg(feature = "python")]
use crate::py::{rs_struct_fields, rs_struct_wrapper};
#[cfg(feature = "python")]
use std::sync::Arc;

// --------------------------------------------------------------------
// StringId
// --------------------------------------------------------------------
pub type StringIndex = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct StringId {
    pub string_data_off: u32,
}

unsafe impl plain::Plain for StringId {}

impl StringId {
    #[inline]
    pub const fn offset(&self) -> usize {
        self.string_data_off as usize
    }
}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("StringId", PyDexStringId, StringId);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexStringId, {
    (string_data_off, StringIndex),
},);
/// <<< end python export

// --------------------------------------------------------------------
// TypeId
// --------------------------------------------------------------------
pub type TypeIndex = u16;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TypeId {
    pub descriptor_idx: StringIndex,
}

unsafe impl plain::Plain for TypeId {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("TypeId", PyDexTypeId, TypeId);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexTypeId, {
    (descriptor_idx, StringIndex),
},);
/// <<< end python export

// --------------------------------------------------------------------
// FieldId
// --------------------------------------------------------------------
pub type FieldIndex = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FieldId {
    pub class_idx: TypeIndex,  // index into type_ids_ array for defining class
    pub type_idx: TypeIndex,   // index into type_ids_ array for field type
    pub name_idx: StringIndex, // index into string_ids_ array for field name
}

unsafe impl plain::Plain for FieldId {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("FieldId", PyDexFieldId, FieldId);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexFieldId, {
    (class_idx, TypeIndex),
    (type_idx, TypeIndex),
    (name_idx, StringIndex),
},);
/// <<< end python export

// --------------------------------------------------------------------
// ProtoId
// --------------------------------------------------------------------
pub type ProtoIndex = u16;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty_idx: StringIndex, // index into string_ids array for shorty descriptor
    pub return_type_idx: TypeIndex, // index into type_ids array for return type
    pad_: u16,                   // padding = 0
    pub parameters_off: u32,     // file offset to type_list for parameter types
}

unsafe impl plain::Plain for ProtoId {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("ProtoId", PyDexProtoId, ProtoId);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexProtoId, {
    (shorty_idx, StringIndex),
    (return_type_idx, TypeIndex),
    (parameters_off, u32),
},);
/// <<< end python export

// --------------------------------------------------------------------
// MethodId
// --------------------------------------------------------------------
pub type MethodIndex = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MethodId {
    pub class_idx: TypeIndex,  // index into type_ids_ array for defining class
    pub proto_idx: ProtoIndex, // index into proto_ids_ array for method signature
    pub name_idx: StringIndex, // index into string_ids_ array for method name
}

unsafe impl plain::Plain for MethodId {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("MethodId", PyDexMethodId, MethodId);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexMethodId, {
    (class_idx, TypeIndex),
    (proto_idx, ProtoIndex),
    (name_idx, StringIndex),
},);
// <<< end python export

// --------------------------------------------------------------------
// ClassDef
// --------------------------------------------------------------------
pub type ClassDefIndex = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ClassDef {
    pub class_idx: TypeIndex, // index into type_ids_ array for this class
    pad1_: u16,               // padding = 0
    pub access_flags: u32,
    pub superclass_idx: TypeIndex, // index into type_ids_ array for superclass
    pad2_: u16,                    // padding = 0
    pub interfaces_off: u32,       // file offset to TypeList
    pub source_file_idx: StringIndex, // index into string_ids_ for source file name
    pub annotations_off: u32,      // file offset to annotations_directory_item
    pub class_data_off: u32,       // file offset to class_data_item
    pub static_values_off: u32,    // file offset to EncodedArray
}

unsafe impl plain::Plain for ClassDef {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("ClassDef", PyDexClassDef, ClassDef);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexClassDef, {
    (class_idx, TypeIndex),
    (access_flags, u32),
    (superclass_idx, TypeIndex),
    (interfaces_off, u32),
    (source_file_idx, StringIndex),
    (annotations_off, u32),
    (class_data_off, u32),
    (static_values_off, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// Typeitem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TypeItem {
    pub type_idx: TypeIndex, // index into type_ids section
}

unsafe impl plain::Plain for TypeItem {}

pub type TypeList<'a> = &'a [TypeItem];

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("TypeItem", PyDexTypeItem, TypeItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexTypeItem, {
    (type_idx, TypeIndex),
},);
// <<< end python export

// --------------------------------------------------------------------
// MapItem (private)
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug)]
pub struct MapItem {
    // REVISIT: this may cause a panic on invalid input
    pub type_: MapItemType,
    unused_: u16,
    pub size: u32,
    pub off: u32,
}

unsafe impl plain::Plain for MapItem {}

pub type MapList<'a> = &'a [MapItem];

#[repr(u16)]
#[derive(Debug)]
pub enum MapItemType {
    HeaderItem = 0x0000,
    StringIdItem = 0x0001,
    TypeIdItem = 0x0002,
    ProtoIdItem = 0x0003,
    FieldIdItem = 0x0004,
    MethodIdItem = 0x0005,
    ClassDefItem = 0x0006,
    CallSiteIdItem = 0x0007,
    MethodHandleItem = 0x0008,
    MapList = 0x1000,
    TypeList = 0x1001,
    AnnotationSetRefList = 0x1002,
    AnnotationSetItem = 0x1003,
    ClassDataItem = 0x2000,
    CodeItem = 0x2001,
    StringDataItem = 0x2002,
    DebugInfoItem = 0x2003,
    AnnotationItem = 0x2004,
    EncodedArrayItem = 0x2005,
    AnnotationsDirectoryItem = 0x2006,
    HiddenapiClassData = 0xF000,
}

// --------------------------------------------------------------------
// MethodHandleItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MethodHandleItem {
    pub method_handle_type: TypeIndex,
    reserved1_: u16,
    pub field_or_method_idx: u16, // Field index for accessors, method index otherwise.
    reserved2_: u16,
}

unsafe impl plain::Plain for MethodHandleItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("MethodHandleItem", PyDexMethodHandleItem, MethodHandleItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexMethodHandleItem, {
    (method_handle_type, TypeIndex),
    (field_or_method_idx, u16),
},);
// <<< end python export

// --------------------------------------------------------------------
// CallSiteIdItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CallSiteIdItem {
    pub data_off: u32, // Offset into data section pointing to encoded array items.
}

unsafe impl plain::Plain for CallSiteIdItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("CallSiteIdItem", PyDexCallSiteIdItem, CallSiteIdItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexCallSiteIdItem, {
    (data_off, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// HiddenapiClassData (private)
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug)]
pub struct HiddenapiClassData<'a> {
    pub size: u32,
    flags_offset: &'a [u8],
}

impl<'a> HiddenapiClassData<'a> {
    pub fn get_flags_slice(&self, class_def_idx: u32) -> Option<&'a [u8]> {
        let offset = (class_def_idx * 4) as usize;
        match u32::from_bytes(&self.flags_offset[offset..]) {
            Ok(0) => None,
            // offset starts from beginning of this object
            Ok(start) => Some(&self.flags_offset[(*start - 4) as usize..]),
            _ => None,
        }
    }
}

unsafe impl<'a> plain::Plain for HiddenapiClassData<'a> {}

// --------------------------------------------------------------------
// CodeItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
}

unsafe impl plain::Plain for CodeItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("CodeItem", PyDexCodeItem, CodeItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexCodeItem, {
    (registers_size, u16),
    (ins_size, u16),
    (outs_size, u16),
    (tries_size, u16),
    (debug_info_off, u32),
    (insns_size, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// TryItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

unsafe impl plain::Plain for TryItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("TryItem", PyDexTryItem, TryItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexTryItem, {
    (start_addr, u32),
    (insn_count, u16),
    (handler_off, u16),
},);
// <<< end python export

// --------------------------------------------------------------------
// AnnotationsDirectoryItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub fields_size: u32,
    pub methods_size: u32,
    pub parameters_size: u32,
}

unsafe impl plain::Plain for AnnotationsDirectoryItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "AnnotationsDirectoryItem",
    PyDexAnnotationsDirectoryItem,
    AnnotationsDirectoryItem
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexAnnotationsDirectoryItem, {
    (class_annotations_off, u32),
    (fields_size, u32),
    (methods_size, u32),
    (parameters_size, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// FieldAnnotationsItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FieldAnnotationsItem {
    pub field_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for FieldAnnotationsItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "FieldAnnotationsItem",
    PyDexFieldAnnotationsItem,
    FieldAnnotationsItem
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexFieldAnnotationsItem, {
    (field_idx, u32),
    (annotations_off, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// MethodAnnotationsItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MethodAnnotationsItem {
    pub method_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for MethodAnnotationsItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "MethodAnnotationsItem",
    PyDexMethodAnnotationsItem,
    MethodAnnotationsItem
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexMethodAnnotationsItem, {
    (method_idx, u32),
    (annotations_off, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// ParameterAnnotationsItem
// --------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ParameterAnnotationsItem {
    pub method_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for ParameterAnnotationsItem {}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "ParameterAnnotationsItem",
    PyDexParameterAnnotationsItem,
    ParameterAnnotationsItem
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexParameterAnnotationsItem, {
    (method_idx, u32),
    (annotations_off, u32),
},);
// <<< end python export

// --------------------------------------------------------------------
// Annotations (private for now)
// --------------------------------------------------------------------
pub type AnnotationSetItem<'a> = &'a [u32];

pub type EncodedArray = Vec<EncodedValue>;

// --------------------------------------------------------------------
// Encoded Value
// --------------------------------------------------------------------
macro_rules! define_encoded_value {
    ({ $(($primitive_name:ident: $primitive_py_name:ident=$primitive_ty:ty),)* }) => {
        #[derive(Debug, Clone)]
        pub enum EncodedValue {
            $(
                $primitive_name($primitive_ty),
            )*
            Array(EncodedArray),
            Annotation(EncodedAnnotation),
            Null,
        }

// >>> begin python export
        // Python type will be an enum with variants from EncodedValue
        #[cfg(feature = "python")]
        #[derive(Clone)]
        #[pyo3::pyclass(name = "EncodedValue", module = "dexrs._internal.structs")]
        pub enum PyDexEncodedValue {
            $(
                $primitive_name { $primitive_py_name: $primitive_ty },
            )*
            Array{ elements: Vec<PyDexEncodedValue> },
            Annotation{ annotation: PyDexEncodedAnnotation },
            Null(),
        }

        #[cfg(feature = "python")]
        impl From<&EncodedValue> for PyDexEncodedValue {
            fn from(value: &EncodedValue) -> Self {
                match value {
                    $(
                        EncodedValue::$primitive_name(value) =>
                        PyDexEncodedValue::$primitive_name { $primitive_py_name: *value },
                    )*
                    EncodedValue::Array(v) => PyDexEncodedValue::Array {
                        elements: v.iter().map(Into::into).collect(),
                    },
                    EncodedValue::Annotation(v) => PyDexEncodedValue::Annotation {
                        annotation: v.into(),
                    },
                    EncodedValue::Null => PyDexEncodedValue::Null(),
                }
            }
        }
// <<< end python export
    };
}

define_encoded_value!({
    (Byte: value=i8),
    (Short: value=i16),
    (Char: value=u16),
    (Int: value=i32),
    (Long: value=i64),
    (Float: value=f32),
    (Double: value=f64),
    (MethodType: index=u32),
    (MethodHandle: index=u32),
    (String: index=u32),
    (Type: index=u32),
    (Field: index=u32),
    (Method: index=u32),
    (Enum: index=u32),
    (Boolean: value=bool),
});

// --------------------------------------------------------------------
// Annotation Element
// --------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct AnnotationElement {
    pub name_idx: u32,
    pub(crate) value: EncodedValue,
}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "AnnotationElement",
    PyDexAnnotationElement,
    AnnotationElement
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexAnnotationElement, {
    (name_idx, u32),
},

#[getter]
pub fn value(&self) -> PyDexEncodedValue {
    let value = &self.0.value;
    value.into()
}
);
// <<< end python export

// --------------------------------------------------------------------
// Encoded Annotation
// --------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    pub(crate) elements: Vec<AnnotationElement>,
}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!(
    "EncodedAnnotation",
    PyDexEncodedAnnotation,
    EncodedAnnotation
);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexEncodedAnnotation, {
    (type_idx, u32),
},

#[getter]
pub fn elements(&self) -> Vec<PyDexAnnotationElement> {
    self.0.elements.iter().map(Into::into).collect()
}
);
// <<< end python export

// --------------------------------------------------------------------
// Annotation Item
// --------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

// >>> begin python export
#[cfg(feature = "python")]
rs_struct_wrapper!("AnnotationItem", PyDexAnnotationItem, AnnotationItem);
#[cfg(feature = "python")]
rs_struct_fields!(PyDexAnnotationItem, {
    (visibility, u8),
},

#[getter]
pub fn annotation(&self) -> PyDexEncodedAnnotation {
    let a = &self.0.annotation;
    a.into()
}
);
// <<< end python export

// --------------------------------------------------------------------
// Python API
// --------------------------------------------------------------------
// >>> begin python module export
#[cfg(feature = "python")]
#[pyo3::pymodule(name = "structs")]
pub(crate) mod py_structs {

    #[pymodule_export]
    use super::{
        PyDexAnnotationElement, PyDexAnnotationItem, PyDexAnnotationsDirectoryItem,
        PyDexCallSiteIdItem, PyDexClassDef, PyDexCodeItem, PyDexEncodedAnnotation,
        PyDexEncodedValue, PyDexFieldAnnotationsItem, PyDexFieldId, PyDexMethodAnnotationsItem,
        PyDexMethodHandleItem, PyDexMethodId, PyDexParameterAnnotationsItem, PyDexProtoId,
        PyDexStringId, PyDexTryItem, PyDexTypeId, PyDexTypeItem,
    };

    #[pymodule_export]
    use crate::file::header::PyDexHeader;
}
// <<< end python module export
