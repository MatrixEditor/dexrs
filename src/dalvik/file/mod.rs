use super::{
    dex::{AccessFlags, CallSiteIdItem, DexType, FieldIdItem, MethodHandleItem, MethodIdItem},
    error::Result,
};
use std::{cell::RefCell, rc::Rc};

pub mod value;
use field::DexField;
pub use value::*;

pub mod class_def;
pub use class_def::*;

pub mod lazy_file;
pub use lazy_file::*;

pub mod field;
pub mod annotation;
pub mod method;
pub mod debug;

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

pub trait IClassDef {
    /// Returns the type of the class as [DexType].
    fn get_type(&self) -> Rc<DexType>;

    /// Returns the access flags of this class
    fn get_access_flags(&self) -> Option<AccessFlags>;

    /// Returns true if this class has a superclass
    fn has_superclass(&self) -> bool;

    /// Returns the superclass of this class
    fn get_superclass(&self) -> Option<Rc<DexType>>;

    /// Returns the interfaces implemented by this class
    fn get_interfaces(&self) -> Vec<Rc<DexType>>;

    /// Returns the instance fields of this class
    fn get_instance_fields(&self) -> Vec<DexField>;

    /// Returns all static fields of this class
    fn get_static_fields(&self) -> Vec<DexField>;

    /// returns the source file name of this class if it has one
    fn get_source_file_name(&self) -> Option<Rc<String>>;


}
