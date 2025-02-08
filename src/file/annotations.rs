use crate::Result;

use super::{
    AnnotationSetItem, AnnotationsDirectoryItem, ClassDef, DexContainer, DexFile,
    FieldAnnotationsItem, MethodAnnotationsItem, ParameterAnnotationsItem,
};

pub struct ClassAnnotationsAccessor<'a> {
    class_def: &'a ClassDef,

    field_annotations: &'a [FieldAnnotationsItem],
    method_annotations: &'a [MethodAnnotationsItem],
    parameter_annotations: &'a [ParameterAnnotationsItem],
    class_annotations: AnnotationSetItem<'a>,
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn class_annotations(
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
    pub fn get_field_annotations(&self) -> &'a [FieldAnnotationsItem] {
        self.field_annotations
    }

    #[inline]
    pub fn get_method_annotations(&self) -> &'a [MethodAnnotationsItem] {
        self.method_annotations
    }

    #[inline]
    pub fn get_parameter_annotations(&self) -> &'a [ParameterAnnotationsItem] {
        self.parameter_annotations
    }

    #[inline]
    pub fn get_class_annotations(&self) -> AnnotationSetItem<'a> {
        self.class_annotations
    }
}
