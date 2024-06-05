use crate::dalvik::{
    dex::*,
    error::{Error, Result},
};

use binrw::BinRead;
use std::{
    collections::{btree_map::Values, BTreeMap},
    fmt::Debug,
    io::{Read, Seek},
    rc::Rc,
};

use super::{
    annotation::DexAnnotation, field::DexField, lazy_file::Dex, method::*, DexValue, IDex,
};

#[derive(Debug)]
pub struct DexClassDef {
    pub identity: u32,
    /// The type reference storing the package name and the simple
    /// name of this class.
    pub type_: Rc<DexType>,

    /// Same as [DexMethod] and [DexField], access flags of this class are
    /// stored as a single [AccessFlags] instance. Use [AccessFlags::iter]
    /// to retrieve all matched access flags.
    pub flags: Option<AccessFlags>,

    /// Optional reference to the superclass of this class.
    pub super_class: Option<Rc<DexType>>,

    /// List of interfaces implemented by this class.
    pub interfaces: Vec<Rc<DexType>>,

    /// Optional debug information which lists the source file name.
    pub source_file: Option<Rc<String>>,

    /// List of annotations associated with this class or empty if
    /// none were specified.
    pub annotations: Vec<DexAnnotation>,

    /// List of static fields defined in this class.
    static_fields: BTreeMap<u32, DexField>,

    /// List of instance fields defined in this class.
    instance_fields: BTreeMap<u32, DexField>,

    /// List of direct methods defined in this class.
    direct_methods: BTreeMap<u32, DexMethod>,

    /// List of virtual methods defined in this class.
    virtual_methods: BTreeMap<u32, DexMethod>,
}

impl DexClassDef {
    pub fn new<R: Read + Seek>(dex: &mut Dex<'_, R>, index: u32) -> Result<DexClassDef> {
        let class_def_item = ClassDefItem::read(dex.fd)?;
        let mut class_def = DexClassDef {
            identity: index,
            type_: dex.get_type(class_def_item.class_idx)?,
            flags: AccessFlags::from_bits(class_def_item.access_flags),
            super_class: None,
            // dynamic: will be added in #process_definition
            interfaces: Vec::new(),
            source_file: None,
            // annotations: will be added in #process_annotations
            annotations: Vec::new(),
            // will be added after #process_definition
            static_fields: BTreeMap::new(),
            instance_fields: BTreeMap::new(),
            direct_methods: BTreeMap::new(),
            virtual_methods: BTreeMap::new(),
        };

        class_def.process_definition(&class_def_item, dex)?;
        if class_def_item.class_data_off != 0 {
            dex.seeks(class_def_item.class_data_off as u64)?;
            let class_data = ClassDataItem::read(dex.fd)?;

            // process fields and methods
            class_def.process_fields(&class_data, dex)?;
            class_def.process_methods(&class_data, dex)?;

            // lastly, identify possible static values
            class_def.process_init_values(&class_def_item, &class_data, dex)?;
        }

        // annotations are parsed regardless of class_data_off
        class_def.process_annotations(&class_def_item, dex)?;
        Ok(class_def)
    }

    /* private impl */

    fn process_definition<R>(&mut self, def: &ClassDefItem, dex: &mut Dex<'_, R>) -> Result<()>
    where
        R: Read + Seek,
    {
        if def.superclass_idx != NO_INDEX {
            self.super_class = Some(dex.get_type(def.superclass_idx)?);
        }

        if def.interfaces_off != 0 {
            /*Format:
            ┌─────────────────────┐         ┌────────────────────────┐
            │ TypeList            │     ┌──►│ TypeIdItem             │
            ├─────────────────────┤     │   ├────────────────────────┤
            │ items: TypeIdItem[] ├─────┘   │ type_idx: u16          ├──────┐
            └─────────────────────┘         └────────────────────────┘      │
                                                                            │
                                            ┌────────────────────────┐      │
                                            │ StringIdItem           │◄─────┘
                                            ├────────────────────────┤
                                            │ descriptor_idx: u32    ├──────┐
                                            └────────────────────────┘      │
                                                                            │
                                            ┌────────────────────────┐      │
                                            │ StringDataItem         │◄─────┘
                                            ├────────────────────────┤
                                            │ data: u8[]             │
                                            └────────────────────────┘
             */
            dex.seeks(def.interfaces_off as u64)?;
            let types = TypeList::read(dex.fd)?;
            for type_item in &types.list {
                self.interfaces
                    .push(dex.get_type(type_item.type_idx as u32)?);
            }
        }

        if def.source_file_idx != NO_INDEX {
            self.source_file = Some(dex.get_string(def.source_file_idx)?);
        }
        Ok(())
    }

    fn process_fields<R>(&mut self, data: &ClassDataItem, dex: &mut Dex<'_, R>) -> Result<()>
    where
        R: Read + Seek,
    {
        // TODO: explain
        macro_rules! _process {
            ($attr:ident) => {
                let mut i = 0;
                for encoded_field in &data.$attr {
                    let field = DexField::build(dex, encoded_field, i)?;
                    i += encoded_field.field_idx_diff.0;
                    self.$attr.insert(field.identity, field);
                }
            };
        }
        _process!(static_fields);
        _process!(instance_fields);
        Ok(())
    }

    fn process_methods<R>(&mut self, data: &ClassDataItem, dex: &mut Dex<'_, R>) -> Result<()>
    where
        R: Read + Seek,
    {
        // TODO: explain
        macro_rules! _process {
            ($attr:ident) => {
                let mut i = 0;
                for encoded_method in &data.$attr {
                    let method = DexMethod::build(dex, encoded_method, i)?;
                    i += encoded_method.method_idx_diff.0;
                    self.$attr.insert(method.identity, method);
                }
            };
        }
        _process!(direct_methods);
        _process!(virtual_methods);
        Ok(())
    }

    fn process_annotations<R>(&mut self, def: &ClassDefItem, dex: &mut Dex<'_, R>) -> Result<()>
    where
        R: Read + Seek,
    {
        if def.annotations_off == 0 {
            return Ok(());
        }

        /*Format:
        ┌──────────────────────────────────────────────┐
        │ AnnotationsDirectoryItem                     │
        ├──────────────────────────────────────────────┤
        │ cls_annotations_off: u32 (ref to set)        │
        │ method_annotations: MethodAnnotation[]       │
        │ field_annotations:  FieldAnnotation[]        │
        │ parameter_annotations: ParameterAnnotation[] │
        └──────────────────────────────────────────────┘
         */
        dex.seeks(def.annotations_off as u64)?;
        let directory_item = AnnotationsDirectoryItem::read(dex.fd)?;

        if directory_item.class_annotations_off != 0 {
            // parse class annotations (REVISIT: maybe inspect them directly?)
            dex.seeks(directory_item.class_annotations_off as u64)?;
            DexAnnotation::read_set_into(dex, &mut self.annotations)?;
        }

        macro_rules! iter_annotations {
            ($attr:ident, $sattr:ident, $mth:ident, $error:ident) => {
                for _a in &directory_item.$attr {
                    if _a.annotations_off == 0 {
                        continue; // ignore irrelevant items
                    }

                    let item = self.$mth(_a.$sattr as u32);
                    // REVISIT: what should we do in case of error?
                    if item.is_none() {
                        return Err(Error::$error(_a.$sattr as usize));
                    }

                    dex.seeks(_a.annotations_off as u64)?;
                    DexAnnotation::read_set_into(dex, &mut item.unwrap().annotations)?;
                }
            };
        }

        iter_annotations!(
            method_annotations,
            method_idx,
            get_method_mut,
            MethodNotFound
        );
        iter_annotations!(field_annotations, field_idx, get_field_mut, FieldNotFound);

        // parameters are handled differently:
        let mut param_idx = 0;
        let mut method_idx = 0;
        for param_annotation in &directory_item.parameter_annotations {
            // if the method index differs from the previous one, the parameter index
            // needs to be reset
            if method_idx != param_annotation.method_idx {
                method_idx = param_annotation.method_idx;
                param_idx = 0;
            }

            let method = self.get_method_mut(method_idx);
            if method.is_none() {
                return Err(Error::MethodNotFound(method_idx as usize));
            }

            let parameter = method.unwrap().parameters.get_mut(param_idx as usize);
            if parameter.is_none() {
                return Err(Error::ParameterNotFound(param_idx as usize));
            }

            dex.seeks(param_annotation.annotations_off as u64)?;
            parameter.unwrap().read_annotations(dex)?;
        }

        Ok(())
    }

    fn process_init_values<R>(
        &mut self,
        def: &ClassDefItem,
        class_data: &ClassDataItem,
        dex: &mut Dex<'_, R>,
    ) -> Result<()>
    where
        R: Read + Seek,
    {
        if def.static_values_off == 0 {
            return Ok(());
        }

        dex.seeks(def.static_values_off as u64)?;
        let data = EncodedArray::read(&mut dex.fd)?;
        if data.values.len() > self.static_fields.len() {
            return Err(Error::InvalidData("Too many static values".to_string()));
        }

        let mut diff = 0;
        for (i, value) in data.values.iter().enumerate() {
            let field_item = &class_data.static_fields[i];
            let idx = field_item.field_idx_diff.0 + diff;
            let field = self.static_fields.get_mut(&idx).unwrap();
            field.init_value = Some(DexValue::from(value, dex)?);

            diff += field_item.field_idx_diff.0;
        }

        Ok(())
    }
}

macro_rules! _at {
    ($name:ident, $attr:ident, $type:ty) => {
        pub fn $name(&self, index: u32) -> Option<&$type> {
            if index >= self.$attr.len() as u32 {
                return None;
            }

            let pos = if index == 0 { 0 } else { index - 1 } as usize;
            self.$attr.values().skip(pos).next()
        }
    };

    ($name:ident, $attr:ident, $attr_fallback:ident, $($type:tt)*) => {
        pub fn $name(&mut self, index: u32) -> Option<&$($type)*> {
            self.$attr
                .get_mut(&index)
                .or_else(|| self.$attr_fallback.get_mut(&index))
        }
    }
}

/* public API */
impl DexClassDef {
    _at!(get_method_mut, direct_methods, virtual_methods, mut DexMethod);
    _at!(get_field_mut, static_fields, instance_fields, mut DexField);
    _at!(get_direct_method, direct_methods, DexMethod);
    _at!(get_virtual_method, virtual_methods, DexMethod);
    _at!(get_static_field, static_fields, DexField);
    _at!(get_instance_field, instance_fields, DexField);

    pub fn get_direct_methods(&self) -> Values<u32, DexMethod> {
        self.direct_methods.values()
    }

    pub fn get_virtual_methods(&self) -> Values<u32, DexMethod> {
        self.virtual_methods.values()
    }

    pub fn get_methods(&self) -> impl Iterator<Item = (&u32, &DexMethod)> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
    }

    pub fn get_static_fields(&self) -> Values<u32, DexField> {
        self.static_fields.values()
    }

    pub fn get_instance_fields(&self) -> Values<u32, DexField> {
        self.instance_fields.values()
    }

    pub fn get_fields(&self) -> impl Iterator<Item = (&u32, &DexField)> {
        self.static_fields
            .iter()
            .chain(self.instance_fields.iter())
    }
}





