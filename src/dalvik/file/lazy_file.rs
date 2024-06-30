use crate::dalvik::{
    dex::*,
    error::{Error, Result},
};

use binrw::BinRead;
use std::{
    collections::{btree_map::Entry::Vacant, BTreeMap},
    fmt::Debug,
    io::{self, Read, Seek},
    rc::Rc,
};

use super::{method::DexPrototype, DexClassDef, IDex};

type Pool<T> = BTreeMap<u32, Rc<T>>;

#[derive(Debug)]
pub struct Dex<'a, R: Read + Seek> {
    pub(super) fd: &'a mut R,

    /// ## Dex Header
    /// All publicly available header information are stored in this field
    /// and should not be modified. They can be used to parse the desired
    /// section, although that is not recommended.
    pub header: HeaderItem,

    // Internal fields to provide fast access to method handles and call sites
    method_handles_size: u32,
    method_handles_off: u32,
    call_sites_size: u32,
    call_sites_off: u32,

    /// All types defined by a DEX file parsed from the map list. Note that
    /// types can be retrieved by providing the referenced index value using
    /// `.type_at(index)`.
    types: Pool<DexType>,

    /// ## String Table
    /// The map is allocated by the number of string id items defined in
    /// the map list for [StringIdItem]. All strings used throughout the other
    /// objects are referencing objects within this vector.
    strings: Pool<String>,

    /// ## Method Prototypes
    /// Internal list of all prototypes defined within the DEX file.
    protos: Pool<DexPrototype>,

    // ## Field items
    fields: Pool<FieldIdItem>,

    // ## Method items
    methods: Pool<MethodIdItem>,

    // Internal fields to provide fast access to method handles and call sites
    methods_handles: Pool<MethodHandleItem>,
    call_sites: Pool<CallSiteIdItem>,
    classes: Pool<DexClassDef>,
}

macro_rules! check_index {
    ($index: expr, item_size=$item_size: expr, $size: expr, $offset: expr) => {{
        let _offset = $offset + $index * $item_size;
        if _offset >= ($size * $item_size) + $offset {
            return Err(Error::InvalidIndex($index as usize));
        }
        _offset
    }};
}

impl<'b, R: Read + Seek> Dex<'b, R> {
    // fundamental seek methods
    pub(super) fn seeks(&mut self, offset: u64) -> Result<()> {
        self.fd.seek(io::SeekFrom::Start(offset))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn seekc(&mut self, offset: i64) -> Result<()> {
        self.fd.seek(io::SeekFrom::Current(offset))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn seeke(&mut self, offset: i64) -> Result<()> {
        self.fd.seek(io::SeekFrom::End(offset))?;
        Ok(())
    }

    pub fn read(mut reader: &mut R, verify: bool) -> Result<Dex<'_, R>>
    where
        R: Read + Seek,
    {
        let header = HeaderItem::read(&mut reader)?;
        if verify {
            // validate the header against Android's global constraints
            header.verify(&mut reader, 0)?;
        }
        // In order to parse all other items, we need to create the map
        // list first.
        reader.seek(io::SeekFrom::Start(header.map_off as u64))?;
        let map_list = MapList::read(&mut reader)?;
        Ok(Dex {
            fd: reader,
            header,
            method_handles_off: map_list.item_offset(MapListItemType::MethodHandleItem) as u32,
            call_sites_off: map_list.item_offset(MapListItemType::CallSiteIdItem) as u32,
            method_handles_size: map_list.item_size(MapListItemType::MethodHandleItem) as u32,
            call_sites_size: map_list.item_size(MapListItemType::CallSiteIdItem) as u32,
            // parsing is done lazily: types, strings, and protos will be
            // populated on demand
            types: BTreeMap::new(),
            strings: BTreeMap::new(),
            protos: BTreeMap::new(),
            fields: BTreeMap::new(),
            methods: BTreeMap::new(),
            methods_handles: BTreeMap::new(),
            call_sites: BTreeMap::new(),
            classes: BTreeMap::new(),
        })
    }

    // pub fn string_at<'a>(&'a self, index: u32) -> Result<&'a String> {
    //     // first tries to find the string in the string table
    //     match self.strings.get(&index) {
    //         Some(x) => Ok(x),
    //         None => Err(Error::InvalidIndex(index as usize)),
    //     }
    // }

    /// ### Format:
    /// ```text
    /// ┌──────────────────────┐          ┌──────────────┐            ┌────────────────────┐
    /// │ ProtoIdItem          │          │ StringIdItem │            │ StringDataItem     │
    /// ├──────────────────────┤          ├──────────────┤            ├────────────────────┤
    /// │ shorty_idx: u32      ├─────────►│ offset: u32  ├───────────►│ data: mutf8_string │
    /// │                      │          └─────────▲────┘            └────────────────────┘
    /// │ return_type_idx: u32 ├─────┐              │
    /// │ parameters_off: u32  │     │              └───────────────┐
    /// └─┬────────────────────┘     │                              │
    ///   │                          │    ┌─────────────────────┐   │
    ///   │                          │    │ TypeIdItem          │   │
    ///   │                          │    ├─────────────────────┤   │
    ///   │                          └───►│ descriptor_idx: u32 ├───┘
    ///   │                               └─────────▲───────────┘
    ///   │                                         │
    ///   │                                         └─────────────────┐
    ///   │                                                           │
    ///   │                               ┌──────────────────────┐    │
    ///   │                               │ TypeList             │    │
    ///   │                               ├──────────────────────┤    │
    ///   └──────────────────────────────►│ items: TypeIdItem[]  ├────┘
    ///                                   └──────────────────────┘
    ///```
    fn parse_proto(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 12,
            self.header.proto_ids_size,
            self.header.proto_ids_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;

        let proto_item = ProtoIdItem::read(self.fd)?;
        let shorty = self.get_string(proto_item.shorty_idx)?;
        let return_type = self.get_type(proto_item.return_type_idx)?;
        let mut proto = DexPrototype {
            shorty,
            return_type,
            parameters: Vec::new(),
        };

        if proto_item.parameters_off != 0 {
            // type list only present if offset is != 0
            self.fd
                .seek(io::SeekFrom::Start(proto_item.parameters_off as u64))?;
            let params = TypeList::read(self.fd)?;
            for j in 0..params.size {
                // the parameter item stores the type index of the parameter
                let index = params.list[j as usize].type_idx;
                let ty = self.get_type(index as u32)?;
                proto.parameters.push(ty);
            }
        }

        self.protos.insert(index, Rc::new(proto));
        Ok(())
    }

    /* Format:
    ┌─────────────────────┐
    │ TypeIdItem          │
    ├─────────────────────┤
    │ descriptor_idx: u32 ├───┐
    └─────────────────────┘   │
                              │
           ┌──────────────────┘
           │
    ┌──────▼───────┐            ┌────────────────────┐
    │ StringIdItem │            │ StringDataItem     │
    ├──────────────┤            ├────────────────────┤
    │ offset: u32  ├───────────►│ data: mutf8_string │
    └──────────────┘            └────────────────────┘
        */
    fn parse_type(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 4,
            self.header.type_ids_size,
            self.header.type_ids_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;
        let type_item = TypeIdItem::read(self.fd)?;

        let string = self.get_string(type_item.descriptor_idx)?;
        let dtype = DexType::read(&string)?;

        self.types.insert(index, Rc::new(dtype));
        Ok(())
    }

    fn parse_field(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 8,
            self.header.field_ids_size,
            self.header.field_ids_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;
        let field_item = FieldIdItem::read(self.fd)?;

        self.fields.insert(index, Rc::new(field_item));
        Ok(())
    }

    fn parse_method(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 8,
            self.header.method_ids_size,
            self.header.method_ids_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;
        let method_item = MethodIdItem::read(self.fd)?;

        self.methods.insert(index, Rc::new(method_item));
        Ok(())
    }

    fn parse_method_handle(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 4,
            self.method_handles_size,
            self.method_handles_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;
        let method_handle = MethodHandleItem::read(self.fd)?;
        self.methods_handles.insert(index, Rc::new(method_handle));
        Ok(())
    }

    fn parse_call_site(&mut self, index: u32) -> Result<()> {
        let offset = check_index!(
            index,
            item_size = 4,
            self.call_sites_size,
            self.call_sites_off
        );
        self.fd.seek(io::SeekFrom::Start(offset as u64))?;
        let call_site = CallSiteIdItem::read(self.fd)?;
        self.call_sites.insert(index, Rc::new(call_site));
        Ok(())
    }
}

impl<'a, R: Read + Seek> IDex for Dex<'a, R> {
    /* Format:
    ┌──────────────┐            ┌────────────────────┐
    │ StringIdItem │            │ StringDataItem     │
    ├──────────────┤            ├────────────────────┤
    │ offset: u32  ├───────────►│ data: mutf8_string │
    └──────────────┘            └────────────────────┘
        */
    fn get_string(&mut self, index: u32) -> Result<Rc<String>> {
        // first tries to find the string in the string table
        // if not found, tries to read it from the file
        if let Vacant(e) = self.strings.entry(index) {
            let offset = check_index!(
                index,
                item_size = 4,
                self.header.string_ids_size,
                self.header.string_ids_off
            );

            self.fd.seek(io::SeekFrom::Start(offset as u64))?;
            let string_item = StringIdItem::read(self.fd)?;
            self.fd
                .seek(io::SeekFrom::Start(string_item.offset as u64))?;
            e.insert(Rc::new(mutf8::read(self.fd)?));
        }
        Ok(self.strings[&index].clone())
    }

    /// Returns the prototype at the given index.
    ///
    /// If the index is out of bounds, an error is returned. Note that
    /// this method will cache the prototype in the dex file.
    fn get_proto(&mut self, index: u32) -> Result<Rc<DexPrototype>> {
        // same as before: first tries to find the proto in the proto table
        // if not found, tries to read it from the file
        if !self.protos.contains_key(&index) {
            self.parse_proto(index)?;
        }
        Ok(self.protos[&index].clone())
    }

    fn get_type(&mut self, index: u32) -> Result<Rc<DexType>> {
        // same as before: first tries to find the type in the type table
        // if not found, tries to read it from the file
        if !self.types.contains_key(&index) {
            self.parse_type(index)?;
        }

        Ok(self.types[&index].clone())
    }

    fn get_method_handle(&mut self, index: u32) -> Result<Rc<MethodHandleItem>> {
        // same as before: first tries to find the proto in the proto table
        // if not found, tries to read it from the file
        if !self.methods_handles.contains_key(&index) {
            self.parse_method_handle(index)?;
        }
        Ok(self.methods_handles[&index].clone())
    }

    fn get_field(&mut self, index: u32) -> Result<Rc<FieldIdItem>> {
        if !self.fields.contains_key(&index) {
            self.parse_field(index)?;
        }
        Ok(self.fields[&index].clone())
    }

    fn get_method(&mut self, index: u32) -> Result<Rc<MethodIdItem>> {
        if !self.methods.contains_key(&index) {
            self.parse_method(index)?;
        }
        Ok(self.methods[&index].clone())
    }

    fn get_call_site(&mut self, index: u32) -> Result<Rc<CallSiteIdItem>> {
        if !self.call_sites.contains_key(&index) {
            self.parse_call_site(index)?;
        }
        Ok(self.call_sites[&index].clone())
    }

    fn get_class_def(&mut self, index: u32) -> Result<Rc<DexClassDef>> {
        // Note: we can't use btree_map::Entry::Vacant here as it would
        // introduce a second mutable borrow of 'self'
        if !self.classes.contains_key(&index) {
            let offset = check_index!(
                index,
                item_size = 32,
                self.header.class_defs_size,
                self.header.class_defs_off
            );

            self.fd.seek(io::SeekFrom::Start(offset as u64))?;
            let class_def = DexClassDef::new(self, index)?;
            self.classes.insert(index, Rc::new(class_def));
        }
        Ok(self.classes[&index].clone())
    }
}
