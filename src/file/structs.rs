use plain::Plain;

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

pub type TypeIndex = u16;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TypeId {
    pub descriptor_idx: StringIndex,
}

unsafe impl plain::Plain for TypeId {}

pub type FieldIndex = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FieldId {
    pub class_idx: TypeIndex,  // index into type_ids_ array for defining class
    pub type_idx: TypeIndex,   // index into type_ids_ array for field type
    pub name_idx: StringIndex, // index into string_ids_ array for field name
}

unsafe impl plain::Plain for FieldId {}

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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MethodId {
    pub class_idx: TypeIndex,  // index into type_ids_ array for defining class
    pub proto_idx: ProtoIndex, // index into proto_ids_ array for method signature
    pub name_idx: StringIndex, // index into string_ids_ array for method name
}

unsafe impl plain::Plain for MethodId {}

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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TypeItem {
    pub type_idx: TypeIndex, // index into type_ids section
}

unsafe impl plain::Plain for TypeItem {}

pub type TypeList<'a> = &'a [TypeItem];

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

#[repr(C)]
#[derive(Debug)]
pub struct MethodHandleItem {
    pub method_handle_type: TypeIndex,
    reserved1_: u16,
    pub field_or_method_idx: u16, // Field index for accessors, method index otherwise.
    reserved2_: u16,
}

unsafe impl plain::Plain for MethodHandleItem {}

#[repr(C)]
#[derive(Debug)]
pub struct CallSiteIdItem {
    pub data_off: u32, // Offset into data section pointing to encoded array items.
}

unsafe impl plain::Plain for CallSiteIdItem {}

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

#[repr(C)]
#[derive(Debug)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
}

unsafe impl plain::Plain for CodeItem {}

#[repr(C)]
#[derive(Debug)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

unsafe impl plain::Plain for TryItem {}

#[repr(C)]
#[derive(Debug)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub fields_size: u32,
    pub methods_size: u32,
    pub parameters_size: u32,
}

unsafe impl plain::Plain for AnnotationsDirectoryItem {}

#[repr(C)]
#[derive(Debug)]
pub struct FieldAnnotationsItem {
    pub field_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for FieldAnnotationsItem {}

#[repr(C)]
#[derive(Debug)]
pub struct MethodAnnotationsItem {
    pub method_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for MethodAnnotationsItem {}

#[repr(C)]
#[derive(Debug)]
pub struct ParameterAnnotationsItem {
    pub method_idx: u32,
    pub annotations_off: u32,
}

unsafe impl plain::Plain for ParameterAnnotationsItem {}

pub type AnnotationSetItem<'a> = &'a [u32];

pub type EncodedArray = Vec<EncodedValue>;

#[derive(Debug)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(EncodedArray),
    Annotation(EncodedAnnotation),
    Null,
    True,
    False,
}

#[derive(Debug)]
pub struct AnnotationElement {
    pub name_idx: u32,
    pub(crate) value: EncodedValue,
}

#[derive(Debug)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    pub(crate) elements: Vec<AnnotationElement>,
}

#[derive(Debug)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}