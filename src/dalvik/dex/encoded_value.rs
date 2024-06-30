use super::types::*;
use binrw::{binrw, BinRead, BinWrite, Endian};
use byteorder::{LittleEndian, ReadBytesExt};
use std::{
    ffi::{c_double, c_float},
    io,
};

/// ## EncodedValue
/// ### Structure
/// - `value_type`: byte indicating the type of the immediately subsequent value along with
///   an optional clarifying argument in the high-order three bits.
///   In most cases, `value_arg` encodes the length of the immediately-subsequent
///   value in bytes, as (`size - 1`), e.g., `0` means that the value requires
///   one byte, and `7` means it requires eight bytes;
/// - `value`: bytes representing the value, variable in length and interpreted differently
///   for different value_type bytes, though always little-endian.
#[derive(Debug)]
pub enum EncodedValue {
    /// signed one-byte integer value
    ///
    /// @value_arg: none, must be 0
    /// @value_format: `UByte[1]`
    Byte(i8),

    /// signed two-byte integer value, sign-extended
    ///
    /// @value_arg: `size - 1` (0..1)
    /// @value_format: `UByte[size]`
    Short(i16),

    /// unsigned two-byte integer value, zero-extended
    ///
    /// @value_arg: size - 1 (0..1)
    /// @value_format: `UByte[size]`
    Char(char),

    /// signed four-byte integer value, sign-extended
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Int(i32),

    /// signed eight-byte integer value, sign-extended
    ///
    /// @value_arg: `size - 1` (0..7)
    /// @value_format: `UByte[size]`
    Long(i64),

    /// four-byte bit pattern, zero-extended to the right,
    /// and interpreted as an IEEE754 32-bit floating point value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Float(f32),

    /// eight-byte bit pattern, zero-extended to the right,
    /// and interpreted as an IEEE754 64-bit floating point value.
    ///
    /// @value_arg: `size - 1` (0..7)
    /// @value_format: `UByte[size]`
    Double(f64),

    /// unsigned (zero-extended) four-byte integer value, interpreted
    /// as an index into the `proto_ids` section and representing a
    /// method type value
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    MethodType(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted
    /// as an index into the method_handles section and representing a
    /// method handle value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    MethodHandle(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted as
    /// an index into the string_ids section and representing a string value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    String(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted as
    /// an index into the type_ids section and representing a type value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Type(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted as
    /// an index into the field_ids section and representing a field value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Field(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted as
    /// an index into the method_ids section and representing a method value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Method(u32),

    /// unsigned (zero-extended) four-byte integer value, interpreted as
    /// an index into the field_ids section and representing an enum value.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: `UByte[size]`
    Enum(u32),

    /// An array of values, in the format specified by "encoded_array format"
    /// The size of the value is implicit in the encoding.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: [EncodedArray]
    Array(EncodedArray),

    /// a sub-annotation, in the format specified by "encoded_annotation format".
    /// The size of the value is implicit in the encoding.
    ///
    /// @value_arg: `size - 1` (0..3)
    /// @value_format: [EncodedAnnotation]
    Annotation(EncodedAnnotation),

    /// null reference value
    ///
    /// @value_arg: 0
    /// @value_format: none
    Null,

    /// one-bit value; 0 for false and 1 for true. The bit is represented in
    /// the `value_arg`.
    ///
    /// @value_arg: boolean (0..1)
    /// @value_format: none
    True,
    False,
}

impl EncodedValue {
    pub const VALUE_BYTE: UByte = 0x00;
    pub const VALUE_SHORT: UByte = 0x02;
    pub const VALUE_CHAR: UByte = 0x03;
    pub const VALUE_INT: UByte = 0x04;
    pub const VALUE_LONG: UByte = 0x06;
    pub const VALUE_FLOAT: UByte = 0x10;
    pub const VALUE_DOUBLE: UByte = 0x11;
    pub const VALUE_METHOD_TYPE: UByte = 0x15;
    pub const VALUE_METHOD_HANDLE: UByte = 0x16;
    pub const VALUE_STRING: UByte = 0x17;
    pub const VALUE_TYPE: UByte = 0x18;
    pub const VALUE_FIELD: UByte = 0x19;
    pub const VALUE_METHOD: UByte = 0x1A;
    pub const VALUE_ENUM: UByte = 0x1B;
    pub const VALUE_ARRAY: UByte = 0x1C;
    pub const VALUE_ANNOTATION: UByte = 0x1D;
    pub const VALUE_NULL: UByte = 0x1E;
    pub const VALUE_BOOLEAN: UByte = 0x1F;
}

impl BinRead for EncodedValue {
    type Args<'a> = ();
    fn read_options<R: io::Read + io::Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let byte = reader.read_u8()?;

        let value_type = byte & 0x1F_u8 as u8;
        let value_size = ((byte & 0xE0) >> 5) as usize + 1;

        // return Ok(EncodedValue::Data(byte, data));
        // return Ok(EncodedValue::Int(byte[0] as i32));

        let value = match value_type {
            EncodedValue::VALUE_BYTE => {
                EncodedValue::Byte(reader.read_int::<LittleEndian>(value_size).unwrap() as i8)
            }
            EncodedValue::VALUE_SHORT => {
                EncodedValue::Short(reader.read_int::<LittleEndian>(value_size).unwrap() as i16)
            }
            EncodedValue::VALUE_CHAR => EncodedValue::Char(
                char::from_u32(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
                    .unwrap(),
            ),
            EncodedValue::VALUE_INT => {
                EncodedValue::Int(reader.read_int::<LittleEndian>(value_size).unwrap() as i32)
            }
            EncodedValue::VALUE_LONG => {
                EncodedValue::Long(reader.read_int::<LittleEndian>(value_size).unwrap())
            }
            EncodedValue::VALUE_FLOAT => EncodedValue::Float(c_float::from_bits(
                reader.read_uint::<LittleEndian>(value_size).unwrap() as u32,
            )),
            EncodedValue::VALUE_DOUBLE => EncodedValue::Double(c_double::from_bits(
                reader.read_uint::<LittleEndian>(value_size).unwrap(),
            )),
            EncodedValue::VALUE_METHOD_TYPE => EncodedValue::MethodType(
                reader.read_uint::<LittleEndian>(value_size).unwrap() as u32,
            ),
            EncodedValue::VALUE_METHOD_HANDLE => EncodedValue::MethodHandle(
                reader.read_uint::<LittleEndian>(value_size).unwrap() as u32,
            ),
            EncodedValue::VALUE_STRING => {
                EncodedValue::String(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
            }
            EncodedValue::VALUE_TYPE => {
                EncodedValue::Type(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
            }
            EncodedValue::VALUE_FIELD => {
                EncodedValue::Field(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
            }
            EncodedValue::VALUE_METHOD => {
                EncodedValue::Method(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
            }
            EncodedValue::VALUE_ENUM => {
                EncodedValue::Enum(reader.read_uint::<LittleEndian>(value_size).unwrap() as u32)
            }
            EncodedValue::VALUE_ARRAY => EncodedValue::Array(EncodedArray::read(reader).unwrap()),
            EncodedValue::VALUE_ANNOTATION => {
                EncodedValue::Annotation(EncodedAnnotation::read(reader).unwrap())
            }
            EncodedValue::VALUE_NULL => EncodedValue::Null,
            EncodedValue::VALUE_BOOLEAN => {
                if (byte & 0xE0) == 0x00 {
                    EncodedValue::False
                } else {
                    EncodedValue::True
                }
            }
            _ => panic!(
                "Unknown value type: {} with original byte {}",
                value_type, byte
            ),
        };
        return Ok(value);
    }
}

// TODO
impl BinWrite for EncodedValue {
    type Args<'a> = ();
    fn write_options<W: io::Write>(
        &self,
        _: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        todo!();
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedArray {
    /// the number of elements in this array
    #[bw(calc = ULeb128(values.len() as u32))]
    pub size: ULeb128,

    /// a series of size encoded_value byte sequences in the format specified by
    /// this section, concatenated sequentially.
    #[br(count = size.0)]
    pub values: Vec<EncodedValue>,
}

/// bytes representing the encoded array value
pub type EncodedArrayItem = EncodedArray;

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedTypeAddrPair {
    /// index into the `type_ids` list for the type of the exception to catch
    pub type_idx: ULeb128,

    /// bytecode address of the associated exception handler
    pub addr: ULeb128,
}

//TODO
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedCatchHandler {
    /// number of catch types in this list. If non-positive, then this is the negative
    /// of the number of catch types, and the catches are followed by a catch-all
    /// handler. For example: A size of 0 means that there is a catch-all but no
    /// explicitly typed catches. A size of 2 means that there are two explicitly typed
    /// catches and no catch-all. And a size of -1 means that there is one typed catch
    /// along with a catch-all.
    pub size: SLeb128,

    /// stream of `abs(size)` encoded items, one for each caught type, in the order that
    /// the types should be tested.
    #[br(count = if size.0 != 0 { size.0.abs() } else { 0 })]
    pub handlers: Vec<EncodedTypeAddrPair>,

    /// bytecode address of the catch-all handler. This element is only present if size
    /// is non-positive.
    #[br(if(size.0 <= 0))]
    pub catch_all_addr: Option<ULeb128>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedCatchHandlerList {
    /// the number of entries in this list
    pub size: ULeb128,

    // elements of this list
    // #[br(count = size.0 as usize)]
    // pub list: Vec<EncodedCatchHandler>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedField {
    /// index into the `field_ids` list for the identity of this field (includes the
    /// name and descriptor), represented as a difference from the index of
    /// previous element in the list. The index of the first element in a list is
    /// represented directly.
    pub field_idx_diff: ULeb128,

    /// access flags for this field
    pub access_flags: ULeb128,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedMethod {
    /// index into the `method_ids` list for the identity of this method (includes the
    /// name and descriptor), represented as a difference from the index of
    /// previous element in the list. The index of the first element in a list is
    /// represented directly.
    pub method_idx_diff: ULeb128,

    /// access flags for this method
    pub access_flags: ULeb128,

    /// offset from the start of the file to the code for this method
    pub code_off: ULeb128,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug)]
pub enum AnnotationVisibility {
    /// intended only to be visible at build time (e.g., during compilation of other code)
    BUILD = 0x00,

    /// intended to visible at runtime
    RUNTIME = 0x01,

    /// intended to visible at runtime, but only to the underlying system (and not to
    /// regular user code)
    SYSTEM = 0x02,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationItem {
    /// visibility of the annotation
    pub visibility: AnnotationVisibility,

    /// encoded annotation contents
    pub annotation: EncodedAnnotation,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct EncodedAnnotation {
    /// type of the annotation. This must be a class (not array or
    /// primitive) type.
    pub type_idx: ULeb128,

    /// number of name-value mappings in this annotation
    #[bw(calc = ULeb128(elements.len() as u32))]
    pub size: ULeb128,

    /// elements of the annotation, represented directly in-line (not as
    /// offsets).
    #[br(count = size.0)]
    pub elements: Vec<AnnotationElement>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct AnnotationElement {
    /// element name, represented as an index into the `string_ids` section.
    pub name_idx: ULeb128,

    /// element value
    pub value: EncodedValue,
}
