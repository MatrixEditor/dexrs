use super::encoded_value::{EncodedField, EncodedMethod};
use super::{types::*, EncodedCatchHandlerList};
use binrw::meta::{EndianKind, ReadEndian};
use binrw::{binrw, BinRead, Endian};
use std::io;

/// A string identifier item stores the offset from the start of the file
/// to the string data.
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct StringIdItem {
    /// offset from the start of the file to the string data of this
    /// item.
    pub offset: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct TypeIdItem {
    /// index into the `string_ids` list for the descriptor string of this type.
    pub descriptor_idx: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct ProtoIdItem {
    /// index into the `string_ids` list for the shorty string of this prototype.
    pub shorty_idx: UInt,

    /// index into the `type_ids` list for the return type of this prototype.
    pub return_type_idx: UInt,

    /// offset from the start of the file to the parameters of this prototype.
    pub parameters_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct FieldIdItem {
    /// index into the `type_ids` list for the enclosing type of this field.
    pub class_idx: UShort,

    /// index into the `type_ids` list for the type of this field.
    pub type_idx: UShort,

    /// index into the `string_ids` list for the name of this field.
    pub name_idx: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct MethodIdItem {
    /// index into the `type_ids` list for the declaring class of this method.
    pub class_idx: UShort,

    /// index into the `proto_ids` list for the prototype of this method.
    pub proto_idx: UShort,

    /// index into the `string_ids` list for the name of this method.
    pub name_idx: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct ClassDefItem {
    /// index into the `type_ids` list for this class.
    pub class_idx: UInt,

    /// access flags for this class.
    pub access_flags: UInt,

    /// index into the `type_ids` list for the superclass of this class. The
    /// value `NO_INDEX` may be used to indicate that this class has no
    /// superclass.
    pub superclass_idx: UInt,

    /// offset from the start of the file to the list of interfaces implemented
    /// by this class or `0` if this class does not implement any interfaces.
    pub interfaces_off: UInt,

    /// index to the `string_ids` list for the source file from which this
    /// class was compiled. The value `NO_INDEX` may be used to indicate that
    /// there is no source file information present.
    pub source_file_idx: UInt,

    /// offset from the start of the file to the list of annotations for this
    /// class or `0` if there are no annotations.
    pub annotations_off: UInt,

    /// offset from the start of the file to the list of class data for this
    /// class or `0` if there is no class data.
    pub class_data_off: UInt,

    /// offset from the start of the file to the list of static values for this
    /// class or `0` if there are no static values (initial values for static
    /// fields).
    pub static_values_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct CallSiteIdItem {
    /// offset from the start of the file to the call site definition
    pub call_side_off: UInt,
}

/// An item storing string data.
#[derive(Debug)]
pub struct StringDataItem {
    /// a series of MUTF-8 code units (a.k.a. octets, a.k.a. bytes) followed by a byte
    /// of value 0. Use .mutf8 to decode the string data.
    pub data: Option<String>,
}

impl ReadEndian for StringDataItem {
    const ENDIAN: EndianKind = EndianKind::Runtime;
}

impl BinRead for StringDataItem {
    type Args<'a> = ();
    fn read_options<R: io::Read + io::Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        Ok(Self {
            data: Some(mutf8::read(reader)?),
        })
    }
}

#[binrw]
#[brw(repr(UShort), little)]
#[derive(Debug)]
pub enum MethodHandleType {
    /// Method handle is a static field setter (accessor)
    StaticPut = 0x00,

    /// Method handle is a static field getter (accessor)
    StaticGet = 0x01,

    /// Method handle is a instance field setter (accessor)
    InstancePut = 0x02,

    /// Method handle is a instance field getter (accessor)
    InstanceGet = 0x03,

    /// Method handle is a static method invoke
    StaticInvoke = 0x04,

    /// Method handle is an instance method invoke
    InstanceInvoke = 0x05,

    /// Method handle is a constructor invoke
    InvokeConstructor = 0x06,

    /// Method handle is an instance method invoke
    InvokeDirect = 0x07,

    /// Method handle is an instance method invoke
    InvokeStatic = 0x08,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct MethodHandleItem {
    /// type of this method handle
    #[brw(align_after = 4)]
    pub method_handle_type: MethodHandleType,

    /// Field or method id depending on whether the method handle type is an
    /// accessor or a method invoker
    #[brw(align_after = 4)]
    pub field_or_method_id: UShort,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct TypeItem {
    /// index into the `type_ids` list for the type of this item
    pub type_idx: UShort,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct TypeList {
    /// the number of items in this list
    pub size: UInt,

    /// elements of this list
    #[br(count = size as usize)]
    #[brw(align_after = 4)]
    pub list: Vec<TypeItem>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct TryItem {
    /// start address of the block of code covered by this entry. The
    /// address is a count of 16-bit code units to the start of the
    /// first covered instruction.
    pub start_addr: UInt,

    /// number of 16-bit code units covered by this entry. The last
    /// code unit covered (inclusive) is `start_addr + insn_count - 1`.
    pub insn_count: UShort,

    /// offset in bytes from the start of the associated encoded_catch_hander_list
    /// to the encoded_catch_handler for this entry. This must be an offset to the
    /// start of an encoded_catch_handler.
    pub handler_off: UShort,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationSetItem {
    /// the number of elements in this list
    #[bw(calc = list.len() as u32)]
    pub size: UInt,

    /// elements of this list
    #[br(count = size)]
    pub list: Vec<AnnotationOffItem>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationOffItem {
    /// offset from the start of the file to the annotation.
    ///
    /// @references: `annotation_item`
    pub annotation_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationSetRefList {
    /// the number of items in this list
    #[bw(calc = list.len() as u32)]
    pub size: UInt,

    /// elements of this list
    #[br(count = size)]
    pub list: Vec<AnnotationSetRefItem>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationSetRefItem {
    /// offset from the start of the file to the annotations.
    ///
    /// @references: `annotation_set_item`
    pub annotations_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct FieldAnnotation {
    /// index into the `field_ids` list for the field
    pub field_idx: UInt,

    /// offset from the start of the file to the annotations for the field.
    ///
    /// @references: `annotation_set_item`
    pub annotations_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct MethodAnnotation {
    /// index into the `method_ids` list for the method
    pub method_idx: UInt,

    /// offset from the start of the file to the annotations for the method
    ///
    /// @references: `annotation_set_item`
    pub annotations_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct ParameterAnnotation {
    /// index into the `method_ids` list for the method
    pub method_idx: UInt,

    /// offset from the start of the file to the annotations for the method
    ///
    /// @references: `annotation_set_ref_list`
    pub annotations_off: UInt,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationsDirectoryItem {
    /// offset from the start of the file to the annotations made directly
    /// on a class.
    pub class_annotations_off: UInt,

    /// the number of fields annotated by this item
    #[bw(calc = field_annotations.len() as u32)]
    pub fields_size: UInt,

    /// the number of methods annotated by this item
    #[bw(calc = method_annotations.len() as u32)]
    pub annotated_methods_size: UInt,

    /// the number of parameters annotated by this item
    #[bw(calc = parameter_annotations.len() as u32)]
    pub annotated_parameters_size: UInt,

    /// list of associated field annotations. The elements of the list must
    /// be sorted in increasing order, by `field_idx`.
    #[br(count = fields_size)]
    pub field_annotations: Vec<FieldAnnotation>,

    /// list of associated method annotations. The elements of the list must
    /// be sorted in increasing order, by `method_idx`.
    #[br(count = annotated_methods_size)]
    pub method_annotations: Vec<MethodAnnotation>,

    /// list of associated parameter annotations. The elements of the list must
    /// be sorted in increasing order, by `method_idx`.
    #[br(count = annotated_parameters_size)]
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct CodeItem {
    /// the number of registers pushed by this code
    pub registers_size: UShort,

    /// the number of words of incoming arguments to the method that
    /// this code is for
    pub ins_size: UShort,

    /// the number of words of outgoing argument space
    pub outs_size: UShort,

    /// the number of `TryItem` for this instance
    pub tries_size: UShort,

    /// offset from the start of the file to the debug info (line
    /// numbers + local variable info) sequence for this code, or `0`
    /// if there simply is no information.
    pub debug_info_off: UInt,

    /// size of the instructions list, in 16-bit code units
    pub insns_size: UInt,

    /// actual array of bytecode.
    #[br(count = insns_size * 2)]
    pub insns: Vec<UByte>,

    #[br(if(tries_size != 0))]
    #[bw(if(*tries_size != 0))]
    padding: Option<UShort>,

    /// array indicating where in the code exceptions are caught and how
    /// to handle them.
    #[br(count = tries_size as usize)]
    pub tries: Vec<TryItem>,
    // bytes representing a list of lists of catch types and associated
    // handler addresses.
    // #[br(if(tries_size != 0))]
    // #[bw(if(*tries_size != 0))]
    // pub handlers: EncodedCatchHandlerList,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct ClassDataItem {
    /// the number of static fields in this item
    #[bw(calc = ULeb128(static_fields.len() as u32))]
    pub static_fields_size: ULeb128,

    /// the number of instance fields in this item
    #[bw(calc = ULeb128(instance_fields.len() as u32))]
    pub instance_fields_size: ULeb128,

    /// the number of direct methods in this item
    #[bw(calc = ULeb128(direct_methods.len() as u32))]
    pub direct_methods_size: ULeb128,

    /// the number of virtual methods in this item
    #[bw(calc = ULeb128(virtual_methods.len() as u32))]
    pub virtual_methods_size: ULeb128,

    /// the defined static fields, represented as a sequence of
    /// encoded elements. The fields must be sorted by field_idx
    /// in increasing order.
    #[br(count = static_fields_size.0 as usize)]
    pub static_fields: Vec<EncodedField>,

    /// the defined instance fields, represented as a sequence of
    /// encoded elements. The fields must be sorted by field_idx
    /// in increasing order.
    #[br(count = instance_fields_size.0 as usize)]
    pub instance_fields: Vec<EncodedField>,

    /// the defined direct methods, represented as a sequence of
    /// encoded elements. The methods must be sorted by method_idx
    /// in increasing order.
    #[br(count = direct_methods_size.0 as usize)]
    pub direct_methods: Vec<EncodedMethod>,

    /// the defined virtual methods, represented as a sequence of
    /// encoded elements. The methods must be sorted by method_idx
    /// in increasing order.
    #[br(count = virtual_methods_size.0 as usize)]
    pub virtual_methods: Vec<EncodedMethod>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct HiddenAPIClassDataItem {
    /// total size of the section
    #[bw(calc = data.len() as u32)]
    pub size: UInt,

    // array of offsets indexed by class_idx. A zero array entry at index class_idx
    // means that either there is no data for this class_idx, or all hidden API flags
    // are zero. Otherwise the array entry is non-zero and contains an offset from
    // the beginning of the section to an array of hidden API flags for this class_idx.
    // pub offsets: Vec<UInt>,

    // concatenated arrays of hidden API flags for each class. Flags are encoded in
    // the same order as fields and methods are encoded in class data.
    // flags: Vec<ULeb128>,
    #[br(count = size as usize)]
    pub data: Vec<UByte>,
}

impl HiddenAPIClassDataItem {
    /// Interfaces that can be freely used and are supported as part of the officially
    /// documented Android framework Package Index.
    pub const FLAG_WHITELIST: UInt = 0x00;

    /// Non-SDK interfaces that can be used regardless of the application's target API
    /// level.
    pub const FLAG_GREYLIST: UInt = 0x01;

    /// Non-SDK interfaces that cannot be used regardless of the application's target API
    /// level. Accessing one of these interfaces causes a runtime error.
    pub const FLAG_BLACKLIST: UInt = 0x02;

    /// Non-SDK interfaces that can be used for Android 8.x and below unless they are
    /// restricted.
    pub const FLAG_GREYLIST_MAX_O: UInt = 0x03;

    /// Non-SDK interfaces that can be used for Android 9.x and below unless they are
    /// restricted.
    pub const FLAG_GREYLIST_MAX_P: UInt = 0x04;

    /// Non-SDK interfaces that can be used for Android 10.x and below unless they are
    /// restricted.
    pub const FLAG_GREYLIST_MAX_Q: UInt = 0x05;

    /// Non-SDK interfaces that can be used for Android 11.x and below unless they are
    /// restricted.
    pub const FLAG_GREYLIST_MAX_R: UInt = 0x06;
}

// custom instruction payload data
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct FillArrayData {
    /// number of bytes in each element
    pub width: u16,

    /// number of elements in the table
    pub size: u32,

    /// data values
    #[br(count = (size * width as u32) as usize)]
    pub data: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct PackedSwitch {
    /// number of keys
    pub size: u16,

    /// first key
    pub first_key: i32,

    /// target offsets
    #[br(count = size as usize)]
    pub targets: Vec<i32>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct SparseSwitch {
    /// number of keys
    pub size: u16,

    /// keys
    #[br(count = size)]
    pub keys: Vec<i32>,

    /// target offsets
    #[br(count = size)]
    pub targets: Vec<i32>,
}
