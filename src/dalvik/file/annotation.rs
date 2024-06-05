use crate::dalvik::dex::{
    AccessFlags, AnnotationItem, AnnotationSetItem, AnnotationVisibility, DexType, EncodedAnnotation, EncodedField, FieldIdItem
};
use crate::dalvik::error::Result;

use super::{Dex, DexValue, IDexRef};
use binrw::{io, BinRead};
use std::collections::HashMap;
use std::io::{Read, Seek};
use std::rc::Rc;

#[derive(Debug)]
pub struct DexAnnotation {
    /// The referenced annotation type displayed as a shared reference
    /// to the [DexType].
    ///
    /// This value will never be null and an error will be reported if no
    /// type is associated with the parsed annotation.
    pub type_: Rc<DexType>,

    /// The visibility of the annotation.
    pub visibility: Option<AnnotationVisibility>,

    /// A key-value mapping binding the values of an annotation to their
    /// specified values. The key is a reference to the string pool of the
    /// DEX file and the value must be an instance of [DexValue], which
    /// may contain a reference to another object in the DEX file.
    pub values: HashMap<Rc<String>, DexValue>,
}

impl DexAnnotation {
    pub fn is_subannotation(&self) -> bool {
        // Subannotations are parsed from encoded values that don't specify
        // a visibility.
        self.visibility.is_none()
    }

    /// Reads an annotation from the given reader and returns it.
    ///
    /// @**Note**: This function assumes that the reader points to the
    ///            start of an [AnnotationItem] object in the DEX file.
    pub fn read<R>(dex: &mut Dex<'_, R>) -> Result<Self>
    where
        R: Read + Seek,
    {
        let annotation_item = AnnotationItem::read(dex.fd)?;
        let mut annotation = DexAnnotation::from_encoded(&annotation_item.annotation, dex)?;
        annotation.visibility = Some(annotation_item.visibility);
        Ok(annotation)
    }

    /// Decodes an encoded annotation object and returns a [DexAnnotation] object
    /// storing all resolved string and type references.
    pub fn from_encoded(
        encoded_annotation: &EncodedAnnotation,
        dex: IDexRef<'_>,
    ) -> Result<Self>
    {
        let mut annotation = DexAnnotation {
            type_: dex.get_type(encoded_annotation.type_idx.0)?.clone(),
            values: HashMap::with_capacity(encoded_annotation.elements.len()),
            visibility: None,
        };

        for element in &encoded_annotation.elements {
            let value = DexValue::from(&element.value, dex)?;
            annotation
                .values
                .insert(dex.get_string(element.name_idx.0)?, value);
        }
        Ok(annotation)
    }

    /// expects an [AnnotationSetItem] to be at reader's current position
    pub fn read_set<R>(dex: &mut Dex<'_, R>) -> Result<Vec<DexAnnotation>>
    where
        R: Read + Seek,
    {
        // REVISIT:
        let mut annotations: Vec<DexAnnotation> = Vec::new();
        DexAnnotation::read_set_into(dex, &mut annotations)?;
        Ok(annotations)
    }

    pub fn read_set_into<R>(
        dex: &mut Dex<'_, R>,
        target: &mut Vec<DexAnnotation>,
    ) -> Result<()>
    where
        R: Read + Seek,
    {
        AnnotationSetItem::read(dex.fd)?
            .list
            .iter()
            .try_for_each(|x| {
                dex.fd.seek(io::SeekFrom::Start(x.annotation_off as u64))?;
                target.push(DexAnnotation::read(dex)?);
                Ok(())
            })
    }

    pub fn get(&self, name: &String) -> Option<&DexValue> {
        self.values.get(name)
    }



}
