use memmap2::Mmap;
use plain::Plain;

pub mod structs;
pub use structs::*;
pub mod header;
pub use header::*;
pub mod class_accessor;
pub mod verifier;
pub use class_accessor::*;
pub mod modifiers;
pub use modifiers::*;
pub mod instruction;
pub use instruction::*;
pub mod code_item_accessors;
pub use code_item_accessors::*;
pub mod container;
pub mod dump;
pub use container::*;

use crate::{dex_err, error::DexError, leb128::decode_leb128, utf, Result};

pub const DEX_MAGIC: &[u8] = b"dex\n";
pub const DEX_MAGIC_VERSIONS: &[&[u8]] = &[
    b"035\0", b"037\0", // Dex version 038: Android "O" and beyond.
    b"038\0", // Dex version 039: Android "P" and beyond.
    b"039\0", // Dex version 040: Android "Q" and beyond (aka Android 10).
    b"040\0", // Dex version 041: Android "V" and beyond (aka Android 15).
    b"041\0",
];

pub const DEX_ENDIAN_CONSTANT: u32 = 0x12345678;

#[derive(Debug)]
pub enum DexLocation {
    InMemory,
    Path(String),
}

impl From<&'static str> for DexLocation {
    fn from(s: &'static str) -> Self {
        DexLocation::Path(s.to_string())
    }
}

impl ToString for DexLocation {
    fn to_string(&self) -> String {
        match self {
            DexLocation::InMemory => "[in-memory]".to_string(),
            DexLocation::Path(path) => path.to_string(),
        }
    }
}

pub type InMemoryDexFile<'a> = DexFile<'a, InMemoryDexContainer<'a>>;
pub type MmapDexFile<'a> = DexFile<'a, Mmap>;

pub struct DexFile<'a, T: DexContainer<'a> = Mmap> {
    mmap: &'a T,
    header: &'a Header,

    string_ids: &'a [StringId],
    type_ids: &'a [TypeId],
    field_ids: &'a [FieldId],
    proto_ids: &'a [ProtoId],
    method_ids: &'a [MethodId],
    class_defs: &'a [ClassDef],
    method_handles: &'a [MethodHandleItem],
    call_site_ids: &'a [CallSiteIdItem],

    hiddenapi_data: Option<&'a HiddenapiClassData<'a>>,

    location: DexLocation,
}

macro_rules! check_lt_result {
    ($idx:expr, $count:expr, $item_ty:tt) => {
        if ($idx as usize) >= ($count as usize) {
            return dex_err!(DexIndexError {
                index: $idx as u32,
                item_ty: stringify!($item_ty),
                max: $count as usize,
            });
        }
    };
}

// writer
impl<'a, C: DexContainerMut<'a>> DexFile<'a, C> {
    //TODO
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    #[inline]
    fn header_available(base: &'a C) -> bool {
        let size = base.len();
        size >= std::mem::size_of::<Header>() && plain::is_aligned::<Header>(base)
    }

    pub fn get_section<T: Plain>(base: &'a C, offset: u32, len: u32) -> &'a [T] {
        if len == 0 {
            return &[];
        }
        // sanity checks so that this funtion will always return a valid slice
        let size = base.len();
        let section_size = len as usize * std::mem::size_of::<T>();
        if (offset as usize + section_size) >= size || offset as usize >= size {
            return &[];
        }

        let data = &base[offset as usize..];
        match T::slice_from_bytes_len(data, len as usize) {
            Ok(slice) => slice,
            Err(_) => &[],
        }
    }

    pub fn from_raw_parts(base: &'a C, location: DexLocation) -> Result<DexFile<'a, C>> {
        if !DexFile::header_available(base) {
            return dex_err!(TruncatedFile);
        }

        let header = match Header::from_bytes(&base) {
            Ok(header) => header,
            // REVISIT: we already checked the header
            Err(_) => return dex_err!(TruncatedFile),
        };
        let mut dex = Self {
            mmap: base,
            header,
            string_ids: DexFile::get_section(base, header.string_ids_off, header.string_ids_size),
            type_ids: DexFile::get_section(base, header.type_ids_off, header.type_ids_size),
            field_ids: DexFile::get_section(base, header.field_ids_off, header.field_ids_size),
            proto_ids: DexFile::get_section(base, header.proto_ids_off, header.proto_ids_size),
            method_ids: DexFile::get_section(base, header.method_ids_off, header.method_ids_size),
            class_defs: DexFile::get_section(base, header.class_defs_off, header.class_defs_size),
            method_handles: &[],
            call_site_ids: &[],
            hiddenapi_data: None,
            location,
        };

        dex.init_sections_from_maplist();
        Ok(dex)
    }

    pub fn open(container: &DexFileContainer) -> Result<MmapDexFile<'_>> {
        let loc = container.get_location();
        let size = container.data().len();
        if size < std::mem::size_of::<Header>() {
            return dex_err!(DexFileError, "Invalid or truncated file {:?}", loc);
        }

        let dex = DexFile::from_raw_parts(container.data(), DexLocation::Path(loc.to_string()))?;
        dex.init()?;
        if container.verify {
            DexFile::verify(&dex, container.verify_checksum)?;
        }
        Ok(dex)
    }

    pub fn expected_header_size(&self) -> u32 {
        let version = self.header.get_version();
        if version != 0 {
            if version < 41 {
                std::mem::size_of::<Header>() as u32
            } else {
                std::mem::size_of::<HeaderV41>() as u32
            }
        } else {
            0
        }
    }

    pub fn get_location(&self) -> &DexLocation {
        &self.location
    }

    #[inline(always)]
    pub fn file_size(&self) -> usize {
        self.mmap.len()
    }

    // -- strings
    #[inline(always)]
    pub fn get_string_id(&self, idx: u32) -> Result<&'a StringId> {
        check_lt_result!(idx, self.num_string_ids(), StringId);
        Ok(&self.string_ids[idx as usize])
    }

    #[inline(always)]
    pub fn string_ids(&self) -> &'a [StringId] {
        self.string_ids
    }

    #[inline(always)]
    pub fn num_string_ids(&self) -> u32 {
        self.header.string_ids_size
    }

    #[inline]
    pub fn get_string_data(&self, string_id: &StringId) -> Result<(u32, &'a [u8])> {
        check_lt_result!(string_id.offset(), self.file_size(), "string-id");
        let (utf16_len, size) = match decode_leb128(&self.mmap[string_id.offset()..]) {
            Ok((utf16_len, size)) => (utf16_len, size),
            Err(DexError::VarIntError(e)) => {
                return dex_err!(BadStringData {
                    offset: string_id.offset(),
                    kind: e
                });
            }
            _ => unreachable!(),
        };

        let start = string_id.offset() + size;
        check_lt_result!(start, self.file_size(), "string-data");
        match &self.mmap[start..].iter().position(|x| *x == 0) {
            Some(pos) => Ok((utf16_len, &self.mmap[start..start + pos + 1])),
            None => dex_err!(BadStringDataMissingNullByte, start),
        }
    }

    #[inline(always)]
    pub fn get_utf16_str_lossy(&self, string_id: &StringId) -> Result<String> {
        let (_, data) = self.get_string_data(string_id)?;
        Ok(utf::mutf8_to_str_lossy(data))
    }

    #[inline(always)]
    pub fn get_utf16_str_lossy_at(&self, idx: u32) -> Result<String> {
        let string_id = self.get_string_id(idx)?;
        self.get_utf16_str_lossy(string_id)
    }

    #[inline(always)]
    pub fn get_utf16_str(&self, string_id: &StringId) -> Result<String> {
        let (_, data) = self.get_string_data(string_id)?;
        crate::utf::mutf8_to_str(data)
    }

    #[inline(always)]
    pub fn get_utf16_str_at(&self, idx: u32) -> Result<String> {
        let string_id = self.get_string_id(idx)?;
        self.get_utf16_str(string_id)
    }

    #[inline(always)]
    pub fn get_type_id(&self, idx: TypeIndex) -> Result<&'a TypeId> {
        check_lt_result!(idx as u32, self.num_type_ids(), TypeId);
        Ok(&self.type_ids[idx as usize])
    }

    #[inline(always)]
    pub fn num_type_ids(&self) -> u32 {
        self.header.type_ids_size
    }

    #[inline(always)]
    pub fn get_type_ids(&self) -> &'a [TypeId] {
        self.type_ids
    }

    #[inline(always)]
    pub fn get_type_desc(&self, type_id: &TypeId) -> Result<String> {
        self.get_utf16_str_lossy_at(type_id.descriptor_idx)
    }

    #[inline(always)]
    pub fn get_type_desc_at(&self, idx: TypeIndex) -> Result<String> {
        self.get_type_desc(self.get_type_id(idx)?)
    }

    pub fn get_type_desc_utf16_lossy_at(&self, idx: TypeIndex) -> Result<String> {
        let type_id = self.get_type_id(idx)?;
        self.get_utf16_str_lossy_at(type_id.descriptor_idx)
    }

    pub fn get_type_desc_utf16_lossy(&self, type_id: &TypeId) -> Result<String> {
        self.get_utf16_str_lossy_at(type_id.descriptor_idx)
    }

    pub fn get_type_desc_utf16(&self, type_id: &TypeId) -> Result<String> {
        self.get_utf16_str_at(type_id.descriptor_idx)
    }

    pub fn get_type_desc_utf16_at(&self, idx: TypeIndex) -> Result<String> {
        let type_id = self.get_type_id(idx)?;
        self.get_utf16_str_at(type_id.descriptor_idx)
    }

    // -- code item
    #[inline(always)]
    pub fn get_code_item(&self, offset: u32) -> Result<Option<&'a CodeItem>> {
        check_lt_result!(offset, self.file_size(), "code item offset");
        self.data_ptr(offset)
    }

    #[inline(always)]
    pub fn get_code_item_accessor(&'a self, offset: u32) -> Result<CodeItemAccessor<'a>> {
        check_lt_result!(offset, self.file_size(), "code item offset");
        let code_item = self.non_null_data_ptr(offset)?;
        CodeItemAccessor::from_code_item(
            self,
            code_item,
            offset + std::mem::size_of::<CodeItem>() as u32,
        )
    }

    #[inline(always)]
    pub fn get_insns_raw(&self, code_off: u32, size_in_code_units: u32) -> Result<&'a [u16]> {
        check_lt_result!(code_off, self.file_size(), "code stream offset");
        self.non_null_array_data_ptr(code_off, size_in_code_units as usize)
    }

    // -- fields
    #[inline]
    pub fn get_field_id(&self, idx: u32) -> Result<&'a FieldId> {
        check_lt_result!(idx, self.header.field_ids_size, FieldId);
        Ok(&self.field_ids[idx as usize])
    }

    #[inline(always)]
    pub fn get_field_ids(&self) -> &'a [FieldId] {
        self.field_ids
    }

    pub fn get_field_name(&self, field_id: &FieldId) -> Result<String> {
        self.get_utf16_str_lossy_at(field_id.name_idx)
    }

    // Proto related methods
    pub fn get_proto_id(&self, idx: ProtoIndex) -> Result<&'a ProtoId> {
        check_lt_result!(idx, self.header.proto_ids_size, ProtoId);
        Ok(&self.proto_ids[idx as usize])
    }

    pub fn num_proto_ids(&self) -> u32 {
        self.header.proto_ids_size
    }

    pub fn get_proto_ids(&self) -> &'a [ProtoId] {
        self.proto_ids
    }

    pub fn get_shorty_at(&self, idx: ProtoIndex) -> Result<String> {
        let proto_id = self.get_proto_id(idx)?;
        self.get_shorty(proto_id)
    }

    pub fn get_shorty_lossy_at(&self, idx: ProtoIndex) -> Result<String> {
        let proto_id = self.get_proto_id(idx)?;
        self.get_shorty_lossy(proto_id)
    }

    pub fn get_shorty(&self, proto_id: &ProtoId) -> Result<String> {
        self.get_utf16_str_at(proto_id.shorty_idx)
    }

    pub fn get_shorty_lossy(&self, proto_id: &ProtoId) -> Result<String> {
        self.get_utf16_str_lossy_at(proto_id.shorty_idx)
    }

    // method ids related methods
    //------------------------------------------------------------------------------
    // Method Ids
    //------------------------------------------------------------------------------
    #[inline(always)]
    pub fn get_method_id(&self, idx: u32) -> Result<&'a MethodId> {
        check_lt_result!(idx, self.header.method_ids_size, MethodId);
        Ok(&self.method_ids[idx as usize])
    }

    #[inline(always)]
    pub fn num_method_ids(&self) -> u32 {
        self.header.method_ids_size
    }

    #[inline(always)]
    pub fn get_method_ids(&self) -> &'a [MethodId] {
        self.method_ids
    }

    // classdef related methods
    #[inline(always)]
    pub fn get_class_def(&self, idx: u32) -> Result<&'a ClassDef> {
        check_lt_result!(idx, self.class_defs.len(), ClassDef);
        Ok(&self.class_defs[idx as usize])
    }

    //------------------------------------------------------------------------------
    // Method Handles
    //------------------------------------------------------------------------------
    #[inline(always)]
    pub fn get_method_handle(&self, idx: u32) -> Result<&'a MethodHandleItem> {
        check_lt_result!(idx, self.method_handles.len(), MethodHandleItem);
        Ok(&self.method_handles[idx as usize])
    }

    #[inline(always)]
    pub fn num_method_handles(&self) -> u32 {
        self.method_handles.len() as u32
    }

    #[inline(always)]
    pub fn get_method_handles(&self) -> &'a [MethodHandleItem] {
        self.method_handles
    }

    //------------------------------------------------------------------------------
    // CallSites
    //------------------------------------------------------------------------------
    #[inline(always)]
    pub fn get_call_site_id(&self, idx: u32) -> Result<&'a CallSiteIdItem> {
        check_lt_result!(idx, self.call_site_ids.len(), CallSiteIdItem);
        Ok(&self.call_site_ids[idx as usize])
    }

    #[inline(always)]
    pub fn num_call_site_ids(&self) -> u32 {
        self.call_site_ids.len() as u32
    }

    #[inline(always)]
    pub fn get_call_site_ids(&self) -> &'a [CallSiteIdItem] {
        self.call_site_ids
    }

    //------------------------------------------------------------------------------
    // TryItem
    //------------------------------------------------------------------------------
    pub fn get_try_item(&'a self, ca: &CodeItemAccessor<'_>) -> Result<&'a [TryItem]> {
        let offset = (ca.code_off() as usize)
            + std::mem::size_of::<CodeItem>()
            + ca.insns_size_in_code_units() as usize;
        // must be 4-byte aligned
        let offset = (offset + 3) & !3;
        self.get_try_items_raw(offset as u32, ca.tries_size() as u16)
    }

    #[inline]
    pub fn get_try_items_raw(&'a self, tries_off: u32, tries_size: u16) -> Result<&'a [TryItem]> {
        check_lt_result!(tries_off, self.file_size(), TryItem);
        self.non_null_array_data_ptr(tries_off, tries_size as usize)
    }

    //------------------------------------------------------------------------------
    // ClassDefs
    //------------------------------------------------------------------------------
    #[inline(always)]
    pub fn num_class_defs(&self) -> u32 {
        self.header.class_defs_size
    }

    #[inline(always)]
    pub fn get_class_defs(&self) -> &'a [ClassDef] {
        self.class_defs
    }

    #[inline]
    pub fn get_class_desc_utf16_lossy(&self, class_def: &ClassDef) -> Result<String> {
        self.get_type_desc_utf16_lossy_at(class_def.class_idx)
    }

    #[inline]
    pub fn get_class_desc_utf16(&self, class_def: &ClassDef) -> Result<String> {
        self.get_type_desc_utf16_at(class_def.class_idx)
    }

    #[inline]
    pub fn get_interfaces_list(&self, class_def: &ClassDef) -> Result<Option<TypeList<'a>>> {
        self.get_type_list(class_def.interfaces_off)
    }

    // type list related methods
    #[inline(always)]
    pub fn get_type_list(&self, offset: u32) -> Result<Option<TypeList<'a>>> {
        if offset == 0 {
            return Ok(None);
        }

        check_lt_result!(offset, self.file_size(), TypeList);
        let length = u32::from_bytes(&self.mmap[offset as usize..]).unwrap();
        let data_off = offset + std::mem::size_of::<u32>() as u32;

        self.array_data_ptr(data_off, *length as usize)
    }

    // private methods
    #[inline]
    fn data_ptr<T: Plain>(&self, offset: u32) -> Result<Option<&'a T>> {
        match offset {
            0 => Ok(None),
            _ => Ok(Some(self.non_null_data_ptr(offset)?)),
        }
    }

    #[inline]
    fn non_null_data_ptr<T: Plain>(&self, offset: u32) -> Result<&'a T> {
        if offset == 0 {
            panic!(
                "Attempted to read a null pointer for data type {:?}.",
                std::any::type_name::<T>()
            );
        }
        match T::from_bytes(&self.mmap[offset as usize..]) {
            Ok(v) => Ok(&v),
            Err(plain::Error::TooShort) => {
                dex_err!(DexLayoutError, self, offset, std::any::type_name::<T>(), 0)
            }
            Err(err) => panic!(
                "Error decoding data type {:?}: {:?}",
                std::any::type_name::<T>(),
                err
            ),
        }
    }

    #[inline]
    fn array_data_ptr<T: Plain>(&self, offset: u32, len: usize) -> Result<Option<&'a [T]>> {
        match offset {
            0 => Ok(None),
            _ => Ok(Some(self.non_null_array_data_ptr(offset, len)?)),
        }
    }

    #[inline]
    fn non_null_array_data_ptr<T: Plain>(&self, offset: u32, len: usize) -> Result<&'a [T]> {
        if offset == 0 {
            panic!(
                "Attempted to read a null pointer for data type {:?}.",
                std::any::type_name::<T>()
            );
        }
        match T::slice_from_bytes_len(&self.mmap[offset as usize..], len) {
            Ok(v) => Ok(&v),
            Err(plain::Error::TooShort) => dex_err!(
                DexLayoutError,
                self,
                offset,
                std::any::type_name::<T>(),
                len
            ),
            Err(plain::Error::BadAlignment) => todo!(),
        }
    }

    fn init(&self) -> Result<()> {
        let container_size = self.file_size();
        if container_size < std::mem::size_of::<Header>() {
            return dex_err!(
                DexFileError,
                "Unable to open {:?}: File size is too small to fit dex header",
                self.location
            );
        }

        self.check_magic_and_version()?;

        let expected_header_size = self.expected_header_size();
        if expected_header_size < self.header.header_size {
            return dex_err!(
                DexFileError,
                "Unable to open {:?}: Header size is {} but {} was expected",
                self.location,
                expected_header_size,
                self.header.header_size
            );
        }

        if container_size < self.header.file_size as usize {
            return dex_err!(
                DexFileError,
                "Unable to open {:?}: File size is {} but the header expects {}",
                self.location,
                container_size,
                self.header.file_size
            );
        }
        Ok(())
    }

    fn check_magic_and_version(&self) -> Result<()> {
        if !self.is_magic_valid() {
            return dex_err!(
                DexFileError,
                "Unrecognized magic number in {:?}: {:?}",
                self.location,
                &self.header.get_magic()[..4]
            );
        }

        if !self.is_version_valid() {
            return dex_err!(
                DexFileError,
                "Unrecognized dex version in {:?}: {:?}",
                self.location,
                &self.header.get_magic()[4..]
            );
        }
        Ok(())
    }

    #[inline]
    fn maplist_available(&self) -> bool {
        if self.header.map_off == 0x00 {
            return false;
        }

        let size = self.file_size();
        let end = (self.header.map_off as usize) + std::mem::size_of::<u32>();
        end as usize > size || !plain::is_aligned::<u32>(&self.mmap[0..end as usize])
    }

    fn init_sections_from_maplist(&mut self) {
        if !self.maplist_available() {
            // bad offset
            return;
        }

        let map_list_size_off = self.header.map_off;
        let map_list_off = (self.header.map_off as usize) + std::mem::size_of::<u32>();
        if map_list_off >= self.file_size() as usize {
            // bad offset
            return;
        }

        let count: &u32 = match self.non_null_data_ptr(map_list_size_off) {
            Ok(v) => v,
            Err(_) => {
                // bad file will be reported through verifier
                return;
            }
        };
        let map_limit =
            (self.file_size() - std::mem::size_of::<u32>() - map_list_size_off as usize)
                / std::mem::size_of::<MapItem>();

        if *count as usize > map_limit {
            // bad file
            return;
        }

        // we should unwrap this here
        let items =
            match self.non_null_array_data_ptr::<MapItem>(map_list_off as u32, *count as usize) {
                Ok(v) => v,
                Err(_) => {
                    // bad file will be reported through verifier
                    return;
                }
            };
        for map_item in items {
            match map_item.type_ {
                MapItemType::MethodHandleItem => {
                    self.method_handles =
                        DexFile::get_section(self.mmap, map_item.off, map_item.size)
                }
                MapItemType::CallSiteIdItem => {
                    self.call_site_ids =
                        DexFile::get_section(self.mmap, map_item.off, map_item.size)
                }
                MapItemType::HiddenapiClassData => {
                    let item_off = map_item.off as usize;
                    self.hiddenapi_data = Some(
                        HiddenapiClassData::from_bytes(
                            &self.mmap[item_off..item_off + map_item.size as usize],
                        )
                        .unwrap(),
                    );
                }
                _ => {}
            }
        }
    }
}
