use crate::dalvik::dex::{AccessFlags, DexType, EncodedField};
use crate::dalvik::error::Result;

use super::annotation::DexAnnotation;
use super::{DexValue, IDexRef};
use std::rc::Rc;

#[derive(Debug)]
pub struct DexField {
    pub identity: u32,

    /// The declaring class of this field in the DEX file stored as
    /// a type reference.
    pub class: Rc<DexType>,

    /// The name of the field
    pub name: Rc<String>,

    /// The type of the field (may be primitive, class or array type)
    pub type_: Rc<DexType>,

    /// list of annotations associated with this field (optional)
    pub annotations: Vec<DexAnnotation>,

    /// The access flags for this field organized as a single [AccessFlags]
    /// instance.
    pub access_flags: Option<AccessFlags>,

    /// Stores the initial value for this field. This field is only
    /// present if a static initializer has been declared for this
    /// field.
    pub init_value: Option<DexValue>,
}

impl DexField {
    pub fn build(dex: IDexRef<'_>, field: &EncodedField, prev_diff: u32) -> Result<DexField> {
        let index = field.field_idx_diff.0 + prev_diff;
        let field_item = dex.get_field(index)?;
        Ok(DexField {
            type_: dex.get_type(field_item.type_idx as u32)?,
            class: dex.get_type(field_item.class_idx as u32)?,
            name: dex.get_string(field_item.name_idx)?,
            access_flags: AccessFlags::from_bits(field.access_flags.0),
            identity: index,
            // Annotations and the initial value will be added later on
            annotations: Vec::new(),
            init_value: None,
        })
    }
}
