use std::rc::Rc;

use crate::dalvik::{
    dex::*,
    error::{Error, Result},
};

use super::{annotation::DexAnnotation, method::DexPrototype, IDexRef};

#[derive(Debug)]
pub enum DexValue {
    Byte(i8),
    Short(i16),
    Char(char),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(Rc<String>),
    Type(Rc<DexType>),
    Annotation(DexAnnotation),
    MethodType(Rc<DexPrototype>),
    MethodRef(u32, Rc<MethodIdItem>),
    FieldRef(Rc<FieldIdItem>),
    MethodHandle(Rc<MethodHandleItem>),
    Array(Vec<DexValue>),
    True,
    False,
    Null,
    Enum(Rc<FieldIdItem>),
    Data(u8, Vec<u8>),
}

impl DexValue {
    pub fn from_array(array: &EncodedArray, dex: IDexRef<'_>) -> Result<DexValue> {
        let mut values = Vec::with_capacity(array.values.len());
        for value in &array.values {
            values.push(DexValue::from(value, dex)?);
        }
        Ok(DexValue::Array(values))
    }

    pub fn from(value: &EncodedValue, dex: IDexRef<'_>) -> Result<Self> {
        match value {
            EncodedValue::Byte(v) => Ok(DexValue::Byte(*v)),
            EncodedValue::Short(v) => Ok(DexValue::Short(*v)),
            EncodedValue::Char(v) => Ok(DexValue::Char(*v)),
            EncodedValue::Int(v) => Ok(DexValue::Int(*v)),
            EncodedValue::Long(v) => Ok(DexValue::Long(*v)),
            EncodedValue::Float(v) => Ok(DexValue::Float(*v)),
            EncodedValue::Double(v) => Ok(DexValue::Double(*v)),
            EncodedValue::String(v) => Ok(DexValue::String(dex.get_string(*v)?)),
            EncodedValue::Type(v) => Ok(DexValue::Type(dex.get_type(*v)?)),
            EncodedValue::MethodType(v) => Ok(DexValue::MethodType(dex.get_proto(*v)?)),
            EncodedValue::Annotation(v) => {
                Ok(DexValue::Annotation(DexAnnotation::from_encoded(v, dex)?))
            }
            EncodedValue::Field(v) => Ok(DexValue::FieldRef(dex.get_field(*v)?)),
            EncodedValue::Method(v) => Ok(DexValue::MethodRef(*v, dex.get_method(*v)?)),
            EncodedValue::MethodHandle(v) => Ok(DexValue::MethodHandle(dex.get_method_handle(*v)?)),
            EncodedValue::Array(v) => DexValue::from_array(v, dex),
            EncodedValue::True => Ok(DexValue::True),
            EncodedValue::False => Ok(DexValue::False),
            EncodedValue::Null => Ok(DexValue::Null),
            EncodedValue::Enum(v) => Ok(DexValue::Enum(dex.get_field(*v)?)), // _ => unreachable!("unhandled value type"),
        }
    }
}
