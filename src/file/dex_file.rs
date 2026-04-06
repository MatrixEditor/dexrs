use plain::Plain;

use crate::{dex_err, error::DexError, leb128::decode_leb128, utf, Result};

// All sibling module types are available via the file module's re-exports.
#[allow(unused_imports)]
use super::*;

pub struct DexFile<'a, T: DexContainer<'a> = Mmap> {
    pub(super) mmap: &'a T,
    /// Owned copy of the DEX header, read via `plain::copy_from_bytes` so that
    /// the backing container does not need to be aligned to `Header`'s
    /// alignment (4 bytes).  This allows callers to pass arbitrary byte slices
    /// such as those produced by `include_bytes!`.
    pub(super) header: Header,

    string_ids: &'a [StringId],
    type_ids: &'a [TypeId],
    field_ids: &'a [FieldId],
    proto_ids: &'a [ProtoId],
    method_ids: &'a [MethodId],
    class_defs: &'a [ClassDef],
    method_handles: &'a [MethodHandleItem],
    call_site_ids: &'a [CallSiteIdItem],

    hiddenapi_data: Option<&'a HiddenapiClassData<'a>>,

    pub(super) location: DexLocation,
    format: DexFormat,
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

macro_rules! fn_id {
    ($name:ident, $attr:ident, $ret_ty:ty, $idx_ty:ty, $(#[$meta:meta])* ) => {
        $(#[$meta])*
        #[inline(always)]
        pub fn $name(&self, idx: $idx_ty) -> Result<&'a $ret_ty> {
            check_lt_result!(idx, self.$attr.len(), $ret_ty);
            Ok(&self.$attr[idx as usize])
        }
    };
    ($name:ident, $attr:ident, Option: $ret_ty:ty, $fallback:ident, $idx_ty:ident, $(#[$meta:meta])*) => {
        $(#[$meta])*
        #[inline(always)]
        pub fn $name(&'a self, idx: $idx_ty) -> Result<Option<&'a $ret_ty>> {
            match idx {
                $idx_ty::MAX => Ok(None),
                _=> Ok(Some(self.$fallback(idx)?)),
            }
        }
    };
    ($name:ident, $attr:ident, $ret_ty:ty[], $(#[$meta:meta])* ) => {
        $(#[$meta])*
        #[inline(always)]
        pub fn $name(&'a self) -> &'a [$ret_ty] {
            &self.$attr
        }
    };
    ($name:ident, $attr:ident, Idx: $ref_ty:ty, $(#[$meta:meta])* ) => {
        $(#[$meta])*
        #[inline(always)]
        pub fn $name(&'a self, item: &'a $ref_ty) -> Result<u32> {
            self.offset_of(self.$attr, item)
        }
    }
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn get_section<T: Plain>(base: &'a C, offset: u32, len: u32) -> &'a [T] {
        if len == 0 {
            return &[];
        }
        let size = base.len();
        let section_size = len as usize * std::mem::size_of::<T>();
        if offset as usize + section_size > size {
            return &[];
        }
        let data = &base[offset as usize..];
        T::slice_from_bytes_len(data, len as usize).unwrap_or_default()
    }

    pub fn from_raw_parts(base: &'a C, location: DexLocation) -> Result<DexFile<'a, C>> {
        if base.len() < std::mem::size_of::<Header>() {
            return dex_err!(TruncatedFile);
        }

        // Copy the header bytes into an owned, properly-aligned value.  This
        // allows callers to pass byte slices with any alignment (e.g. data
        // produced by `include_bytes!` or sub-slices of a VDEX container).
        let mut header = unsafe { std::mem::zeroed::<Header>() };
        plain::copy_from_bytes(&mut header, base).map_err(|_| DexError::TruncatedFile)?;

        // Pre-compute section slices *before* moving `header` into the struct
        // so we can read its offset/size fields without a self-referential borrow.
        let string_ids = DexFile::get_section(base, header.string_ids_off, header.string_ids_size);
        let type_ids = DexFile::get_section(base, header.type_ids_off, header.type_ids_size);
        let field_ids = DexFile::get_section(base, header.field_ids_off, header.field_ids_size);
        let proto_ids = DexFile::get_section(base, header.proto_ids_off, header.proto_ids_size);
        let method_ids = DexFile::get_section(base, header.method_ids_off, header.method_ids_size);
        let class_defs = DexFile::get_section(base, header.class_defs_off, header.class_defs_size);
        let format = if base.len() >= 4 && &base[..4] == CDEX_MAGIC {
            DexFormat::Compact
        } else {
            DexFormat::Standard
        };

        let mut dex = Self {
            mmap: base,
            header,
            string_ids,
            type_ids,
            field_ids,
            proto_ids,
            method_ids,
            class_defs,
            method_handles: &[],
            call_site_ids: &[],
            hiddenapi_data: None,
            location,
            format,
        };

        dex.init_sections_from_maplist();
        Ok(dex)
    }

    pub fn open_file(container: &'a DexFileContainer) -> Result<MmapDexFile<'a>> {
        let loc = container.get_location();
        let size = container.data().len();
        if size < std::mem::size_of::<Header>() {
            return dex_err!(DexFileError, "Invalid or truncated file {:?}", loc);
        }

        DexFile::open(
            container.data(),
            DexLocation::Path(loc.to_string()),
            if container.verify_checksum {
                // currenlty supports only checksum
                verifier::VerifyPreset::ChecksumOnly
            } else {
                verifier::VerifyPreset::None
            },
        )
    }

    pub fn open(
        container: &'a C,
        location: DexLocation,
        verify_preset: verifier::VerifyPreset,
    ) -> Result<DexFile<'a, C>> {
        let dex = DexFile::from_raw_parts(container, location)?;
        dex.init()?;
        if verify_preset != verifier::VerifyPreset::None {
            DexFile::verify(&dex, verify_preset)?;
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

    #[inline(always)]
    pub fn get_header(&self) -> &Header {
        &self.header
    }

    // ------------------------------------------------------------------------------
    // strings
    // ------------------------------------------------------------------------------

    // TODO: add docs
    fn_id!(get_string_id, string_ids, StringId, u32,);
    fn_id!(get_string_ids, string_ids, StringId[],);
    fn_id! {get_string_id_opt, string_ids, Option: StringId, get_string_id, u32,}
    fn_id! {string_id_idx, string_ids, Idx: StringId, }

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

    #[inline]
    /// # Safety
    ///
    /// Caller must ensure the string data at `string_id` is valid UTF-8. No null-terminator or
    /// encoding validation is performed; invalid bytes will produce undefined behaviour.
    pub unsafe fn fast_get_utf8_str(&self, string_id: &StringId) -> Result<String> {
        let (size, data) = self.get_string_data(string_id)?;
        Ok(String::from_utf8_unchecked(data[0..size as usize].to_vec()))
    }

    #[inline]
    /// # Safety
    ///
    /// Caller must ensure the string data at index `idx` is valid UTF-8. No null-terminator or
    /// encoding validation is performed; invalid bytes will produce undefined behaviour.
    pub unsafe fn fast_get_utf8_str_at(&self, idx: u32) -> Result<String> {
        let string_id = self.get_string_id(idx)?;
        self.fast_get_utf8_str(string_id)
    }

    #[inline(always)]
    pub fn get_str_lossy(&self, string_id: &StringId) -> Result<String> {
        let (_, data) = self.get_string_data(string_id)?;
        utf::mutf8_to_str_lossy(data)
    }

    #[inline(always)]
    pub fn get_str_lossy_at(&self, idx: u32) -> Result<String> {
        let string_id = self.get_string_id(idx)?;
        self.get_str_lossy(string_id)
    }

    #[inline(always)]
    pub fn get_str(&self, string_id: &StringId) -> Result<String> {
        let (_, data) = self.get_string_data(string_id)?;
        crate::utf::mutf8_to_str(data)
    }

    #[inline(always)]
    pub fn get_str_at(&self, idx: StringIndex) -> Result<String> {
        let string_id = self.get_string_id(idx)?;
        self.get_str(string_id)
    }

    #[inline(always)]
    pub fn get_str_opt_at(&self, idx: StringIndex) -> Result<Option<String>> {
        match idx {
            StringIndex::MAX => Ok(None),
            _ => Ok(Some(self.get_str_at(idx)?)),
        }
    }

    // ------------------------------------------------------------------------------
    // types
    // ------------------------------------------------------------------------------
    fn_id!(get_type_id, type_ids, TypeId, TypeIndex,);
    fn_id!(get_type_ids, type_ids, TypeId[],);
    fn_id! {type_id_idx, type_ids, Idx: TypeId, }
    fn_id! {get_type_id_opt, type_ids, Option: TypeId, get_type_id, TypeIndex,}

    #[inline(always)]
    pub fn num_type_ids(&self) -> u32 {
        self.header.type_ids_size
    }

    #[inline(always)]
    pub fn get_type_desc_utf16_lossy_at(&self, idx: TypeIndex) -> Result<String> {
        let type_id = self.get_type_id(idx)?;
        self.get_str_lossy_at(type_id.descriptor_idx)
    }

    #[inline(always)]
    pub fn get_type_desc_utf16_lossy(&self, type_id: &TypeId) -> Result<String> {
        self.get_str_lossy_at(type_id.descriptor_idx)
    }

    #[inline(always)]
    pub fn get_type_desc_utf16(&self, type_id: &TypeId) -> Result<String> {
        self.get_str_at(type_id.descriptor_idx)
    }

    #[inline(always)]
    pub fn get_type_desc_utf16_at(&self, idx: TypeIndex) -> Result<String> {
        let type_id = self.get_type_id(idx)?;
        self.get_str_at(type_id.descriptor_idx)
    }

    // -- code item
    #[inline(always)]
    pub fn get_code_item(&self, offset: u32) -> Result<Option<&'a CodeItem>> {
        check_lt_result!(offset, self.file_size(), "code item offset");
        self.data_ptr(offset)
    }

    /// Returns `true` if this is a CompactDex file (`cdex` magic).
    #[inline]
    pub fn is_compact_dex(&self) -> bool {
        self.format == DexFormat::Compact
    }

    /// Returns `true` if this is a standard DEX file (`dex\n` magic).
    #[inline]
    pub fn is_standard_dex(&self) -> bool {
        self.format == DexFormat::Standard
    }

    /// Builds a [`CodeItemAccessor`] for the code item at `offset`.
    ///
    /// For standard DEX, `offset` points to the [`CodeItem`] struct.
    /// For compact DEX, `offset` points to the compact two-field header
    /// (`fields_` + `insns_count_and_flags_`).
    #[inline(always)]
    pub fn get_code_item_accessor(&self, offset: u32) -> Result<CodeItemAccessor<'a>> {
        if offset == 0 {
            return CodeItemAccessor::empty();
        }
        check_lt_result!(offset, self.file_size(), "code item offset");
        match self.format {
            DexFormat::Standard => {
                let code_item = self.non_null_data_ptr(offset)?;
                let insns_off = offset + std::mem::size_of::<CodeItem>() as u32;
                CodeItemAccessor::from_code_item(self, code_item, insns_off)
            }
            DexFormat::Compact => {
                let decoded = compact_dex::decode_compact_code_item(
                    self.mmap.as_ref(),
                    offset as usize,
                )
                .ok_or_else(|| crate::error::DexError::BadOffsetTooLarge {
                    offset,
                    size: self.file_size(),
                    section: "compact code item",
                })?;
                CodeItemAccessor::from_fields(
                    self,
                    decoded.registers_size,
                    decoded.ins_size,
                    decoded.outs_size,
                    decoded.tries_size,
                    0, // debug_info_off is in CompactOffsetTable, not the code item
                    decoded.insns_size,
                    decoded.insns_off,
                )
            }
        }
    }

    #[inline(always)]
    pub fn get_insns_raw(&self, code_off: u32, size_in_code_units: u32) -> Result<&'a [u16]> {
        check_lt_result!(code_off, self.file_size(), "code stream offset");
        self.non_null_array_data_ptr(code_off, size_in_code_units as usize)
    }

    // ------------------------------------------------------------------------------
    // Debug Info
    // ------------------------------------------------------------------------------
    #[inline(always)]
    pub fn get_debug_info_accessor(&'a self, offset: u32) -> Result<CodeItemDebugInfoAccessor<'a>> {
        check_lt_result!(offset, self.file_size(), "debug info offset");
        Ok(CodeItemDebugInfoAccessor::new(
            &self.mmap[offset as usize..],
        ))
    }

    #[inline(always)]
    pub fn get_debug_info_accessor_opt(
        &'a self,
        offset: u32,
    ) -> Result<Option<CodeItemDebugInfoAccessor<'a>>> {
        match offset {
            // WHY?: It seems that some applications incorrectly set the debug info offset to 0
            0 | u32::MAX => Ok(None),
            _ => Ok(Some(self.get_debug_info_accessor(offset)?)),
        }
    }

    // ------------------------------------------------------------------------------
    // field ids
    // ------------------------------------------------------------------------------
    fn_id!(get_field_id, field_ids, FieldId, FieldIndex,);
    fn_id!(get_field_ids, field_ids, FieldId[],);
    fn_id! {field_id_idx, field_ids, Idx: FieldId, }
    fn_id! {get_field_id_opt, field_ids, Option: FieldId, get_field_id, FieldIndex,}

    #[inline(always)]
    pub fn num_field_ids(&self) -> u32 {
        self.header.field_ids_size
    }

    #[inline(always)]
    pub fn get_field_name(&self, field_id: &FieldId) -> Result<String> {
        self.get_str_lossy_at(field_id.name_idx)
    }

    #[inline(always)]
    pub fn get_field_name_at(&self, idx: FieldIndex) -> Result<String> {
        let field_id = self.get_field_id(idx)?;
        self.get_str_lossy_at(field_id.name_idx)
    }

    // ------------------------------------------------------------------------------
    // proto ids
    // ------------------------------------------------------------------------------
    fn_id!(get_proto_id, proto_ids, ProtoId, ProtoIndex,);
    fn_id!(get_proto_ids, proto_ids, ProtoId[],);
    fn_id! {proto_id_idx, proto_ids, Idx: ProtoId, }
    fn_id! {get_proto_id_opt, proto_ids, Option: ProtoId, get_proto_id, ProtoIndex,}

    pub fn num_proto_ids(&self) -> u32 {
        self.header.proto_ids_size
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
        self.get_str_at(proto_id.shorty_idx)
    }

    pub fn get_shorty_lossy(&self, proto_id: &ProtoId) -> Result<String> {
        self.get_str_lossy_at(proto_id.shorty_idx)
    }

    //------------------------------------------------------------------------------
    // EncodedValue
    //------------------------------------------------------------------------------
    pub fn get_encoded_value(&self, off: u32) -> Result<EncodedValue> {
        check_lt_result!(off, self.file_size(), EncodedValue);
        EncodedValue::new(&self.mmap[off as usize..])
    }

    //------------------------------------------------------------------------------
    // Method Ids
    //------------------------------------------------------------------------------
    fn_id!(get_method_id, method_ids, MethodId, u32,);
    fn_id!(get_method_ids, method_ids, MethodId[],);
    fn_id! {method_id_idx, method_ids, Idx: MethodId, }
    fn_id! {get_method_id_opt, method_ids, Option: MethodId, get_method_id, u32,}

    #[inline(always)]
    pub fn num_method_ids(&self) -> u32 {
        self.header.method_ids_size
    }

    // classdef related methods
    //------------------------------------------------------------------------------
    // ClassDefs
    //------------------------------------------------------------------------------
    fn_id!(get_class_def, class_defs, ClassDef, u32,);
    fn_id!(get_class_defs, class_defs, ClassDef[],);
    fn_id! {class_def_idx, class_defs, Idx: ClassDef, }
    fn_id! {get_class_def_opt, class_defs, Option: ClassDef, get_class_def, u32,}

    #[inline(always)]
    pub fn num_class_defs(&self) -> u32 {
        self.header.class_defs_size
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

    //------------------------------------------------------------------------------
    // ClassDef convenience helpers
    //------------------------------------------------------------------------------

    /// Returns the Java-visible access flags for a class definition (lower 16 bits only).
    ///
    /// Matches ART's `ClassDef::GetJavaAccessFlags()`.
    #[inline]
    pub fn get_java_access_flags(class_def: &ClassDef) -> u32 {
        class_def.access_flags & 0xFFFF
    }

    //------------------------------------------------------------------------------
    // Proto helpers
    //------------------------------------------------------------------------------

    /// Returns the parameter `TypeList` for a `ProtoId`, or `None` if the proto has no parameters.
    ///
    /// Matches ART's `DexFile::GetProtoParameters()`.
    #[inline]
    pub fn get_proto_parameters(&'a self, proto_id: &ProtoId) -> Result<Option<TypeList<'a>>> {
        self.get_type_list(proto_id.parameters_off)
    }

    /// Builds and returns the method signature string for the given method index
    /// in DEX format: `"(param1param2...)return_type"`.
    ///
    /// Matches ART's `DexFile::GetMethodSignature()`.
    pub fn get_method_signature(&'a self, method_idx: u32) -> Result<Signature> {
        let method_id = self.get_method_id(method_idx)?;
        let proto_id = self.get_proto_id(method_id.proto_idx)?;

        let mut buf = String::from("(");
        if let Some(params) = self.get_proto_parameters(proto_id)? {
            for item in params {
                let desc = self.get_type_desc_utf16_at(item.type_idx)?;
                buf.push_str(&desc);
            }
        }
        buf.push(')');
        let ret_desc = self.get_type_desc_utf16_at(proto_id.return_type_idx)?;
        let is_void = ret_desc == "V";
        let num_params = self
            .get_proto_parameters(proto_id)?
            .map(|p| p.len() as u32)
            .unwrap_or(0);
        buf.push_str(&ret_desc);
        Ok(Signature::new(buf, num_params, is_void))
    }

    //------------------------------------------------------------------------------
    // TypeLookupTable
    //------------------------------------------------------------------------------

    /// Builds a [`TypeLookupTable`] for fast O(1) class lookup by descriptor.
    pub fn build_type_lookup_table(&'a self) -> TypeLookupTable {
        TypeLookupTable::new(self)
    }

    //------------------------------------------------------------------------------
    // HiddenapiClassData helpers
    //------------------------------------------------------------------------------

    /// Decodes the ULEB128 hidden-API flags stream for a given class.
    ///
    /// Returns `None` if no hidden-API data is present for this class.
    /// The returned `Vec` contains `count` flags in class_data_item order:
    /// static fields, instance fields, direct methods, virtual methods.
    pub fn get_hiddenapi_class_flags(&'a self, class_def_idx: u32, count: usize) -> Option<Vec<u32>> {
        let hiddenapi = self.hiddenapi_data?;
        let slice = hiddenapi.get_flags_slice(class_def_idx)?;
        let mut flags = Vec::with_capacity(count);
        let mut offset = 0;
        for _ in 0..count {
            match crate::leb128::decode_leb128_off::<u32>(slice, &mut offset) {
                Ok(v) => flags.push(v),
                Err(_) => break,
            }
        }
        Some(flags)
    }

    //------------------------------------------------------------------------------
    // Map List
    //------------------------------------------------------------------------------

    /// Returns the raw DEX section map, or `None` if the map list is unavailable.
    pub fn get_map_list(&'a self) -> Option<MapList<'a>> {
        if !self.maplist_available() {
            return None;
        }
        let map_list_size_off = self.header.map_off;
        let map_list_off = (self.header.map_off as usize) + std::mem::size_of::<u32>();
        if map_list_off >= self.file_size() {
            return None;
        }
        let count: &u32 = self.non_null_data_ptr(map_list_size_off).ok()?;
        let map_limit = (self.file_size()
            - std::mem::size_of::<u32>()
            - map_list_size_off as usize)
            / std::mem::size_of::<MapItem>();
        if *count as usize > map_limit {
            return None;
        }
        self.non_null_array_data_ptr::<MapItem>(map_list_off as u32, *count as usize)
            .ok()
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
    pub fn get_try_items(&'a self, ca: &CodeItemAccessor<'_>) -> Result<&'a [TryItem]> {
        // skip heavy work if there are no try items
        match ca.get_tries_abs_off() {
            None => Ok(&[]),
            Some(tries_off) => self.get_try_items_raw(tries_off, ca.tries_size()),
        }
    }

    #[inline]
    pub fn get_try_items_raw(&'a self, tries_off: u32, tries_size: u16) -> Result<&'a [TryItem]> {
        check_lt_result!(tries_off, self.file_size(), TryItem);
        self.non_null_array_data_ptr(tries_off, tries_size as usize)
    }

    //------------------------------------------------------------------------------
    // EncodedCatchHandler
    //------------------------------------------------------------------------------
    #[inline]
    pub fn get_catch_handler_data(
        &self,
        ca: &CodeItemAccessor<'_>,
        offset: usize,
    ) -> Result<Option<&'a [u8]>> {
        match ca.get_catch_handler_data_abs_off() {
            None => Ok(None),
            Some(data_offset) => {
                let offset = data_offset as usize + offset;
                check_lt_result!(offset, self.file_size(), CatchHandlerData);

                // TODO: handle values greater than u16 since u16::MAX is maximum offset
                Ok(Some(&self.mmap[offset..]))
            }
        }
    }

    #[inline]
    pub fn iter_catch_handlers_at(
        &self,
        ca: &CodeItemAccessor<'_>,
        offset: usize,
    ) -> Result<Option<EncodedCatchHandlerIterator<'_>>> {
        match self.get_catch_handler_data(ca, offset)? {
            None => Ok(None),
            Some(data) => Ok(Some(EncodedCatchHandlerIterator::new(data)?)),
        }
    }

    #[inline]
    pub fn iter_catch_handlers(
        &self,
        ca: &CodeItemAccessor<'_>,
        try_item: &TryItem,
    ) -> Result<Option<EncodedCatchHandlerIterator<'_>>> {
        self.iter_catch_handlers_at(ca, try_item.handler_off as usize)
    }

    //------------------------------------------------------------------------------
    // Annotations
    //------------------------------------------------------------------------------
    // see implementation in annotations.rs for accessor
    pub fn get_annotation_set(&self, off: u32) -> Result<AnnotationSetItem<'a>> {
        // this will not panic if offset is zero
        match self.data_ptr::<u32>(off)? {
            None => Ok(&[]),
            Some(size) => {
                let off = off as usize + std::mem::size_of::<u32>();
                check_lt_result!(off, self.file_size(), AnnotationSetItem);
                self.non_null_array_data_ptr(off as u32, *size as usize)
            }
        }
    }

    #[inline(always)]
    pub fn get_field_annotation_set(
        &'a self,
        anno_item: &FieldAnnotationsItem,
    ) -> Result<AnnotationSetItem<'a>> {
        self.get_annotation_set(anno_item.annotations_off)
    }

    #[inline(always)]
    pub fn get_method_annotation_set(
        &'a self,
        anno_item: &MethodAnnotationsItem,
    ) -> Result<AnnotationSetItem<'a>> {
        self.get_annotation_set(anno_item.annotations_off)
    }

    #[inline(always)]
    pub fn get_parameter_annotation_set(
        &'a self,
        anno_item: &ParameterAnnotationsItem,
    ) -> Result<AnnotationSetItem<'a>> {
        self.get_annotation_set(anno_item.annotations_off)
    }

    #[inline]
    pub fn get_annotation(&self, annotation_off: u32) -> Result<AnnotationItem> {
        check_lt_result!(annotation_off, self.file_size(), Annotation);
        AnnotationItem::from_raw_parts(&self.mmap[annotation_off as usize..])
    }

    //------------------------------------------------------------------------------
    // internal helpers
    //------------------------------------------------------------------------------
    #[inline]
    fn offset_of<T: Sized, U>(&self, buf: &[U], o: &T) -> Result<u32> {
        let start = buf.as_ptr() as usize;
        let target = o as *const _ as usize;
        let end = buf.as_ptr() as usize + self.file_size();

        if target < start || target > end {
            return dex_err!(UnknownObjectRef {
                offset: target,
                start,
                end
            });
        }

        Ok(((target - start) / std::mem::size_of::<T>()) as u32)
    }

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
    pub fn data_ptr<T: Plain>(&self, offset: u32) -> Result<Option<&'a T>> {
        match offset {
            0 => Ok(None),
            _ => Ok(Some(self.non_null_data_ptr(offset)?)),
        }
    }

    pub fn non_null_data_ptr<T: Plain>(&self, offset: u32) -> Result<&'a T> {
        if offset == 0 {
            return dex_err!(NullOffset {
                item_ty: std::any::type_name::<T>()
            });
        }
        match T::from_bytes(&self.mmap[offset as usize..]) {
            Ok(v) => Ok(v),
            Err(plain::Error::TooShort) => {
                dex_err!(DexLayoutError, self, offset, std::any::type_name::<T>(), 0)
            }
            Err(plain::Error::BadAlignment) => dex_err!(UnalignedRead {
                offset,
                item_ty: std::any::type_name::<T>()
            }),
        }
    }

    #[inline]
    pub fn array_data_ptr<T: Plain>(&self, offset: u32, len: usize) -> Result<Option<&'a [T]>> {
        match offset {
            0 => Ok(None),
            _ => Ok(Some(self.non_null_array_data_ptr(offset, len)?)),
        }
    }

    pub fn non_null_array_data_ptr<T: Plain>(&self, offset: u32, len: usize) -> Result<&'a [T]> {
        if offset == 0 {
            return dex_err!(NullOffset {
                item_ty: std::any::type_name::<T>()
            });
        }
        match T::slice_from_bytes_len(&self.mmap[offset as usize..], len) {
            Ok(v) => Ok(v),
            Err(plain::Error::TooShort) => dex_err!(
                DexLayoutError,
                self,
                offset,
                std::any::type_name::<T>(),
                len
            ),
            Err(plain::Error::BadAlignment) => dex_err!(UnalignedRead {
                offset,
                item_ty: std::any::type_name::<T>()
            }),
        }
    }

    //------------------------------------------------------------------------------
    // Initialization
    //------------------------------------------------------------------------------
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
        end <= size && plain::is_aligned::<u32>(&self.mmap[0..end])
    }

    fn init_sections_from_maplist(&mut self) {
        if !self.maplist_available() {
            // bad offset
            return;
        }

        let map_list_size_off = self.header.map_off;
        let map_list_off = (self.header.map_off as usize) + std::mem::size_of::<u32>();
        if map_list_off >= self.file_size() {
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
