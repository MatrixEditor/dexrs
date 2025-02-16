use crate::{dex_err, error::DexError, leb128::decode_leb128, Result};

use super::{
    AnnotationElement, AnnotationItem, AnnotationSetItem, AnnotationsDirectoryItem, ClassDef,
    DexContainer, DexFile, EncodedAnnotation, EncodedArray, EncodedValue, FieldAnnotationsItem,
    MethodAnnotationsItem, ParameterAnnotationsItem,
};

//------------------------------------------------------------------------------
// ClassAnnotationsAccessor
//------------------------------------------------------------------------------
pub struct ClassAnnotationsAccessor<'a> {
    class_def: &'a ClassDef,

    field_annotations: &'a [FieldAnnotationsItem],
    method_annotations: &'a [MethodAnnotationsItem],
    parameter_annotations: &'a [ParameterAnnotationsItem],
    class_annotations: AnnotationSetItem<'a>,
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn get_class_annotation_accessor(
        &'a self,
        class_def: &'a ClassDef,
    ) -> Result<ClassAnnotationsAccessor<'a>> {
        ClassAnnotationsAccessor::new(self, class_def)
    }
}

macro_rules! read_annotations {
    ($dex:ident, $offset:ident, $size:expr, $ty:ty) => {
        match $size {
            0 => &[],
            s => $dex.non_null_array_data_ptr::<$ty>($offset as u32, s as usize)?,
        }
    };
}

impl<'a> ClassAnnotationsAccessor<'a> {
    pub fn new<C>(dex: &'a DexFile<'a, C>, class_def: &'a ClassDef) -> Result<Self>
    where
        C: DexContainer<'a>,
    {
        match dex.data_ptr::<AnnotationsDirectoryItem>(class_def.annotations_off)? {
            None => Ok(ClassAnnotationsAccessor::new_empty(class_def)),
            Some(item) => {
                let mut start_offset = class_def.annotations_off as usize
                    + std::mem::size_of::<AnnotationsDirectoryItem>();

                let field_annotations =
                    read_annotations!(dex, start_offset, item.fields_size, FieldAnnotationsItem);
                start_offset +=
                    item.fields_size as usize * std::mem::size_of::<FieldAnnotationsItem>();

                let method_annotations =
                    read_annotations!(dex, start_offset, item.methods_size, MethodAnnotationsItem);
                start_offset +=
                    item.methods_size as usize * std::mem::size_of::<MethodAnnotationsItem>();

                let parameter_annotations = read_annotations!(
                    dex,
                    start_offset,
                    item.parameters_size,
                    ParameterAnnotationsItem
                );

                let class_annotations = dex.get_annotation_set(item.class_annotations_off)?;
                Ok(Self {
                    class_def,
                    field_annotations,
                    method_annotations,
                    parameter_annotations,
                    class_annotations,
                })
            }
        }
    }

    pub fn new_empty(class_def: &'a ClassDef) -> Self {
        Self {
            class_def,
            field_annotations: &[],
            method_annotations: &[],
            parameter_annotations: &[],
            class_annotations: &[],
        }
    }

    #[inline]
    pub fn get_class_def(&self) -> &'a ClassDef {
        self.class_def
    }

    #[inline]
    pub fn get_field_ann(&self) -> &'a [FieldAnnotationsItem] {
        self.field_annotations
    }

    #[inline]
    pub fn get_method_ann(&self) -> &'a [MethodAnnotationsItem] {
        self.method_annotations
    }

    #[inline]
    pub fn get_parameter_ann(&self) -> &'a [ParameterAnnotationsItem] {
        self.parameter_annotations
    }

    #[inline]
    pub fn get_class_ann(&self) -> AnnotationSetItem<'a> {
        self.class_annotations
    }
}

// Encoded values require special handling and they can't be parsed using
// zero-copy.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub enum EncodedValueType {
    Byte          = 0x00,
    Short         = 0x02,
    Char          = 0x03,
    Int           = 0x04,
    Long          = 0x06,
    Float         = 0x10,
    Double        = 0x11,
    MethodType    = 0x15,
    MethodHandle  = 0x16,
    String        = 0x17,
    Type          = 0x18,
    Field         = 0x19,
    Method        = 0x1a,
    Enum          = 0x1b,
    Array         = 0x1c,
    Annotation    = 0x1d,
    Null          = 0x1e,
    Boolean       = 0x1f,
}

#[derive(Debug, PartialEq, Eq)]
enum FillStrategy {
    Left,
    Right,
}

impl AnnotationItem {
    pub fn from_raw_parts(value: &[u8]) -> Result<AnnotationItem> {
        Ok(Self {
            visibility: value[0],
            annotation: EncodedAnnotation::new(&value[1..])?,
        })
    }
}

//------------------------------------------------------------------------------
// AnnotationElement
//------------------------------------------------------------------------------
impl AnnotationElement {
    pub fn value(&self) -> &EncodedValue {
        &self.value
    }

    fn from_raw_parts(value: &[u8], offset: &mut usize) -> Result<AnnotationElement> {
        let (name_idx, size) = decode_leb128::<u32>(&value[*offset..])?;
        *offset += size;
        let value = EncodedValue::from_raw_parts(value, offset)?;
        Ok(AnnotationElement { name_idx, value })
    }
}

//------------------------------------------------------------------------------
// EncodedAnnotation
//------------------------------------------------------------------------------
impl EncodedAnnotation {
    pub fn elements(&self) -> &[AnnotationElement] {
        &self.elements
    }

    pub fn new(value: &'_ [u8]) -> Result<EncodedAnnotation> {
        let mut offset = 0;
        EncodedAnnotation::from_raw_parts(value, &mut offset)
    }

    fn from_raw_parts(value: &[u8], offset: &mut usize) -> Result<EncodedAnnotation> {
        let (type_idx, size) = decode_leb128::<u32>(&value[*offset..])?;
        *offset += size;
        let (length, size) = decode_leb128::<u32>(&value[*offset..])?;
        *offset += size;
        // the value must not overflow assuming each item occupies at least two bytes
        if *offset + (length as usize * 2) >= value.len() {
            return dex_err!(BadEncodedArrayLength {
                value_type: EncodedValueType::Annotation as u8,
                size: value.len(),
                offset: *offset,
                max: value.len()
            });
        }

        let mut elements = Vec::with_capacity(length as usize);
        for _ in 0..length {
            elements.push(AnnotationElement::from_raw_parts(value, offset)?);
        }
        Ok(EncodedAnnotation { type_idx, elements })
    }
}

//------------------------------------------------------------------------------
// wrapper
//------------------------------------------------------------------------------
fn check_size<T: Sized>(
    value_arg: u8,
    value_type: u8,
    width: usize,
    offset: usize,
    value: &[u8],
) -> Result<()> {
    let size = std::mem::size_of::<T>();
    if value_arg as usize + 1 >= size {
        return dex_err!(BadEncodedValueSize {
            value_type: value_type,
            size: value_arg as usize,
            max: size
        });
    }

    if offset + width >= value.len() {
        return dex_err!(InvalidEncodedValue {
            value_type: value_type,
            offset: offset + width,
            size: value.len()
        });
    }
    Ok(())
}

macro_rules! as_int {
    // signed
    ($target:ty, $value:ident, $value_arg:ident, $value_type:ident, $offset:ident, $target_unsigned:ty) => {{
        let width = $value_arg as usize + 1;
        let bytes = std::mem::size_of::<$target>() as u8;
        let bits = bytes * 8;
        check_size::<$target>($value_arg, $value_type, width, *$offset, $value)?;
        let mut val: $target = 0;
        for i in (0..width).rev() {
            val = ((val as $target_unsigned) >> 8) as $target
                | (($value[i + *$offset] as $target) << (bits - 8));
        }
        val >>= ((bytes - 1) - $value_arg) * 8;
        *$offset += width;
        val
    }};

    // unsigned
    ($target:ty, $value:ident, $value_arg:ident, $value_type:ident, $offset:ident, strategy: $strategy:ident) => {{
        let width = $value_arg as usize + 1;
        let bytes = std::mem::size_of::<$target>() as u8;
        let bits = bytes * 8;
        check_size::<$target>($value_arg, $value_type, width, *$offset, $value)?;
        let mut val: $target = 0;
        for i in (0..width).rev() {
            val = ((val as $target) >> 8) as $target
                | (($value[i + *$offset] as $target) << (bits - 8));
        }
        val >>= ((bytes - 1) - $value_arg) * 8;
        *$offset += width;
        match $strategy {
            FillStrategy::Left => val,
            FillStrategy::Right => val >> ((bits - 1) - $value_arg * 8),
        }
    }};
}

#[inline]
fn as_signed_int(value: &[u8], value_arg: u8, value_type: u8, offset: &mut usize) -> Result<i32> {
    Ok(as_int!(i32, value, value_arg, value_type, offset, u32))
}

#[inline]
fn as_signed_long(value: &[u8], value_arg: u8, value_type: u8, offset: &mut usize) -> Result<i64> {
    Ok(as_int!(i64, value, value_arg, value_type, offset, u64))
}

#[inline]
fn as_unsigned_int(
    value: &[u8],
    value_arg: u8,
    value_type: u8,
    offset: &mut usize,
    fill_strategy: FillStrategy,
) -> Result<u32> {
    Ok(as_int!(u32, value, value_arg, value_type, offset, strategy: fill_strategy))
}

#[inline]
fn as_unsigned_long(
    value: &[u8],
    value_arg: u8,
    value_type: u8,
    offset: &mut usize,
    fill_strategy: FillStrategy,
) -> Result<u64> {
    Ok(as_int!(u64, value, value_arg, value_type, offset, strategy: fill_strategy))
}

//------------------------------------------------------------------------------
// EncodedValue
//------------------------------------------------------------------------------
impl EncodedValue {
    pub fn new(value: &'_ [u8]) -> Result<EncodedValue> {
        let mut offset = 0;
        EncodedValue::from_raw_parts(value, &mut offset)
    }

    #[rustfmt::skip]
    fn from_raw_parts(value: &'_ [u8], offset: &mut usize) -> Result<EncodedValue> {
        if *offset >= value.len() {
            return dex_err!(EmptyEncodedValue);
        }

        let header_byte = value[*offset];
        let value_type = header_byte & 0x1F_u8 as u8;
        let value_arg = ((header_byte & 0xE0) >> 5) as u8;
        if !EncodedValueType::is_valid(value_type) {
            return dex_err!(BadEncodedValueType, value_type);
        }

        *offset += 1;
        Ok(match EncodedValueType::from(value_type) {
            EncodedValueType::Byte => EncodedValue::Byte(as_signed_int(value, value_arg, value_type, offset)? as i8),
            EncodedValueType::Short => EncodedValue::Short(as_signed_int(value, value_arg, value_type, offset)? as i16),
            EncodedValueType::Char => EncodedValue::Char(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)? as u16),
            EncodedValueType::Int => EncodedValue::Int(as_signed_int(value, value_arg, value_type, offset)?),
            EncodedValueType::Long => EncodedValue::Long(as_signed_long(value, value_arg, value_type, offset)?),
            EncodedValueType::Float => EncodedValue::Float(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Right)? as f32),
            EncodedValueType::Double => EncodedValue::Double(as_unsigned_long(value, value_arg, value_type, offset, FillStrategy::Right)? as f64),
            EncodedValueType::MethodType => EncodedValue::MethodType(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::MethodHandle => EncodedValue::MethodHandle(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::String => EncodedValue::String(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::Type => EncodedValue::Type(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::Field => EncodedValue::Field(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::Method => EncodedValue::Method(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::Enum => EncodedValue::Enum(as_unsigned_int(value, value_arg, value_type, offset, FillStrategy::Left)?),
            EncodedValueType::Array => EncodedValue::Array(EncodedValue::from_encoded_array(value, offset)?),
            EncodedValueType::Annotation => EncodedValue::Annotation(EncodedValue::from_encoded_annotation(value, offset)?),
            EncodedValueType::Null => EncodedValue::Null,
            EncodedValueType::Boolean => EncodedValue::Boolean(value_arg != 0),
        })
    }

    fn from_encoded_array(value: &'_ [u8], offset: &mut usize) -> Result<EncodedArray> {
        let (length, size) = decode_leb128::<u32>(&value[*offset..])?;
        *offset += size;
        // make sure we don't parse bogus data
        if *offset >= value.len() {
            return dex_err!(InvalidEncodedValue {
                value_type: EncodedValueType::Array as u8,
                offset: *offset,
                size: value.len()
            });
        }

        // the value must not overflow assuming each item occupies at least two bytes
        if *offset + (length as usize * 2) >= value.len() {
            return dex_err!(BadEncodedArrayLength {
                value_type: EncodedValueType::Array as u8,
                size: value.len(),
                offset: *offset,
                max: value.len()
            });
        }

        let mut values = Vec::with_capacity(length as usize);
        for _ in 0..length {
            values.push(EncodedValue::from_raw_parts(value, offset)?);
        }
        Ok(values)
    }

    fn from_encoded_annotation(value: &'_ [u8], offset: &mut usize) -> Result<EncodedAnnotation> {
        EncodedAnnotation::from_raw_parts(value, offset)
    }
}

impl EncodedValueType {
    #[inline]
    pub fn is_valid(value_type: u8) -> bool {
        match value_type {
            0x00 | 0x02..=0x04 | 0x06 | 0x10 | 0x11 | 0x15..=0x1F => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_primitive(value_type: u8) -> bool {
        match value_type {
            0x00 | 0x02..=0x06 | 0x10 | 0x11 => true,
            _ => false,
        }
    }
}

impl From<u8> for EncodedValueType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => EncodedValueType::Byte,
            0x02 => EncodedValueType::Short,
            0x03 => EncodedValueType::Char,
            0x04 => EncodedValueType::Int,
            0x06 => EncodedValueType::Long,
            0x10 => EncodedValueType::Float,
            0x11 => EncodedValueType::Double,
            0x15 => EncodedValueType::MethodType,
            0x16 => EncodedValueType::MethodHandle,
            0x17 => EncodedValueType::String,
            0x18 => EncodedValueType::Type,
            0x19 => EncodedValueType::Field,
            0x1a => EncodedValueType::Method,
            0x1b => EncodedValueType::Enum,
            0x1c => EncodedValueType::Array,
            0x1d => EncodedValueType::Annotation,
            0x1e => EncodedValueType::Null,
            0x1f => EncodedValueType::Boolean,
            _ => unreachable!(),
        }
    }
}
