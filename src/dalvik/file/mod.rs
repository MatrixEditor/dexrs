use super::{
    dex::{CallSiteIdItem, DexType, FieldIdItem, MethodHandleItem, MethodIdItem},
    error::Result,
};
use std::rc::Rc;

pub mod value;
pub use value::*;

pub mod class_def;
pub use class_def::*;

pub mod lazy_file;
pub use lazy_file::*;

pub mod annotation;
pub mod debug;
pub mod field;
pub mod method;

// public interfaces that define behaviour of all classes

pub trait IDex {
    fn get_string(&mut self, index: u32) -> Result<Rc<String>>;
    fn get_proto(&mut self, index: u32) -> Result<Rc<method::DexPrototype>>;
    fn get_type(&mut self, index: u32) -> Result<Rc<DexType>>;
    fn get_method_handle(&mut self, index: u32) -> Result<Rc<MethodHandleItem>>;
    fn get_field(&mut self, index: u32) -> Result<Rc<FieldIdItem>>;
    fn get_method(&mut self, index: u32) -> Result<Rc<MethodIdItem>>;
    fn get_call_site(&mut self, index: u32) -> Result<Rc<CallSiteIdItem>>;
    fn get_class_def(&mut self, index: u32) -> Result<Rc<DexClassDef>>;
}

pub type IDexRef<'a> = &'a mut dyn IDex;
pub type IDexRc = Box<dyn IDex>;
