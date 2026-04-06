use std::{fs, mem, path::Path};

use crate::{
    error::DexError,
    file::{
        patch::{encode_uleb128, read_header, skip_uleb128, update_checksum},
        MapItem, MapItemType,
    },
    utf::{mutf8_len, str_to_mutf8},
    Result,
};

// -- byte helpers --------------------------------------------------------------

#[inline]
fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

#[inline]
fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn write_u32(data: &mut [u8], off: usize, v: u32) {
    data[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// -- cached header fields ------------------------------------------------------

#[derive(Clone, Copy)]
struct CachedHeader {
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    map_off: u32,
    #[allow(dead_code)]
    data_off: u32,
}

impl CachedHeader {
    fn from_data(data: &[u8]) -> Result<Self> {
        let h = read_header(data)
            .ok_or_else(|| DexError::DexFileError("cannot read DEX header".into()))?;
        Ok(CachedHeader {
            string_ids_size: h.string_ids_size,
            string_ids_off: h.string_ids_off,
            type_ids_size: h.type_ids_size,
            type_ids_off: h.type_ids_off,
            proto_ids_size: h.proto_ids_size,
            proto_ids_off: h.proto_ids_off,
            field_ids_size: h.field_ids_size,
            field_ids_off: h.field_ids_off,
            method_ids_size: h.method_ids_size,
            method_ids_off: h.method_ids_off,
            class_defs_size: h.class_defs_size,
            class_defs_off: h.class_defs_off,
            map_off: h.map_off,
            data_off: h.data_off,
        })
    }
}

// -- public struct -------------------------------------------------------------

/// An owned DEX file with mutation methods.
///
/// Call [`build`](Self::build) or [`write_to`](Self::write_to) to finalise the
/// result (recalculates the Adler32 checksum).
pub struct DexEditor {
    data: Vec<u8>,
}

impl DexEditor {
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = fs::read(path)
            .map_err(|e| DexError::DexFileError(format!("read {}: {e}", path.display())))?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < 0x70 {
            return Err(DexError::TruncatedFile);
        }
        if &data[0..4] != b"dex\n" {
            return Err(DexError::BadFileMagic);
        }
        Ok(Self { data })
    }

    /// Patch `ClassDef.access_flags` for the class identified by its descriptor.
    ///
    /// Accepts dotted names (`com.example.Foo`), slash form (`com/example/Foo`),
    /// or full descriptor form (`Lcom/example/Foo;`).
    pub fn set_class_access_flags(&mut self, class_desc: &str, flags: u32) -> Result<()> {
        let h = CachedHeader::from_data(&self.data)?;
        let cd_off = resolve_class_def_off(&self.data, &h, class_desc)?;
        // access_flags is at offset 4: class_idx(2) + pad(2)
        write_u32(&mut self.data, cd_off + 4, flags);
        Ok(())
    }

    /// Re-encode `access_flags` for the named method inside `class_desc`.
    ///
    /// Handles LEB128 width changes by splicing bytes in the `class_data_item`.
    pub fn set_method_access_flags(
        &mut self,
        class_desc: &str,
        method_name: &str,
        flags: u32,
    ) -> Result<()> {
        let h = CachedHeader::from_data(&self.data)?;
        let cd_off = resolve_class_def_off(&self.data, &h, class_desc)?;

        // class_data_off at offset 24: class_idx(2)+pad(2)+flags(4)+super(2)+pad(2)+ifaces(4)+src(4)+ann(4)
        let class_data_off = read_u32(&self.data, cd_off + 24) as usize;
        if class_data_off == 0 {
            return Err(DexError::DexFileError(format!(
                "class {class_desc} has no class_data_item"
            )));
        }

        let target_mutf8 = str_to_mutf8(method_name); // includes null terminator

        let mut pos = class_data_off;
        let static_fields = skip_uleb128(&self.data, &mut pos)?;
        let instance_fields = skip_uleb128(&self.data, &mut pos)?;
        let direct_methods = skip_uleb128(&self.data, &mut pos)?;
        let virtual_methods = skip_uleb128(&self.data, &mut pos)?;

        for _ in 0..static_fields + instance_fields {
            skip_uleb128(&self.data, &mut pos)?; // field_idx_diff
            skip_uleb128(&self.data, &mut pos)?; // access_flags
        }

        let total_methods = direct_methods + virtual_methods;
        let mut method_idx: u32 = 0;

        for _ in 0..total_methods {
            let diff = skip_uleb128(&self.data, &mut pos)?;
            method_idx = method_idx
                .checked_add(diff)
                .ok_or_else(|| DexError::DexFileError("method index overflow".into()))?;

            let flags_start = pos;
            skip_uleb128(&self.data, &mut pos)?; // old access_flags
            let flags_end = pos;
            skip_uleb128(&self.data, &mut pos)?; // code_off

            if method_name_matches_mutf8(&self.data, &h, method_idx, &target_mutf8)? {
                let new_encoded = encode_uleb128(flags);
                self.data.splice(flags_start..flags_end, new_encoded);
                return Ok(());
            }
        }

        Err(DexError::DexFileError(format!(
            "method '{method_name}' not found in {class_desc}"
        )))
    }

    /// Zero out the `HiddenapiClassData` section (if present) and remove its map entry.
    pub fn clear_hiddenapi_flags(&mut self) -> Result<()> {
        let map_off = CachedHeader::from_data(&self.data)?.map_off as usize;
        if map_off + 4 > self.data.len() {
            return Err(DexError::TruncatedFile);
        }

        let count = read_u32(&self.data, map_off) as usize;
        let items_start = map_off + 4;
        const MAP_ITEM_SIZE: usize = mem::size_of::<MapItem>(); // 12 bytes

        let hiddenapi_pos = (0..count).find(|&i| {
            let type_val = read_u16(&self.data, items_start + i * MAP_ITEM_SIZE);
            type_val == MapItemType::HiddenapiClassData as u16
        });

        let pos = match hiddenapi_pos {
            Some(p) => p,
            None => return Ok(()), // section not present
        };

        let item_off = items_start + pos * MAP_ITEM_SIZE;
        // MapItem: type_(2) + unused_(2) + size(4) + off(4); off is at byte 8
        let section_off = read_u32(&self.data, item_off + 8) as usize;

        // The first u32 of the section is its total byte size
        let section_bytes = if section_off + 4 <= self.data.len() {
            read_u32(&self.data, section_off) as usize
        } else {
            0
        };
        let section_end = section_off.saturating_add(section_bytes).min(self.data.len());
        self.data[section_off..section_end].fill(0);

        // Remove map item by shifting subsequent items left
        let tail_start = item_off + MAP_ITEM_SIZE;
        let tail_end = items_start + count * MAP_ITEM_SIZE;
        if tail_start < tail_end {
            self.data.copy_within(tail_start..tail_end, item_off);
        }
        // Zero the now-unused last slot
        let last_slot = items_start + (count - 1) * MAP_ITEM_SIZE;
        if last_slot + MAP_ITEM_SIZE <= self.data.len() {
            self.data[last_slot..last_slot + MAP_ITEM_SIZE].fill(0);
        }
        // Decrement map list count
        write_u32(&mut self.data, map_off, (count - 1) as u32);

        Ok(())
    }

    /// Rename a class: replaces `old_desc` with `new_desc` in the string pool and
    /// updates all cross-references.
    ///
    /// Performs a full string-pool rebuild when the MUTF-8 byte lengths differ.
    pub fn rename_class(&mut self, old_desc: &str, new_desc: &str) -> Result<()> {
        let old_mutf8 = descriptor_mutf8(old_desc);
        let new_mutf8 = descriptor_mutf8(new_desc);

        // str_to_mutf8 includes a null terminator; strip it for content comparisons
        let old_bytes = &old_mutf8[..old_mutf8.len() - 1];
        let new_bytes = &new_mutf8[..new_mutf8.len() - 1];

        if old_bytes == new_bytes {
            return Ok(());
        }

        if old_bytes.len() == new_bytes.len() {
            self.rename_inplace(old_bytes, new_bytes)
        } else {
            self.rename_rebuild(old_bytes, new_bytes)
        }
    }

    /// Recalculate the Adler32 checksum and return the finalised bytes.
    pub fn build(mut self) -> Result<Vec<u8>> {
        update_checksum(&mut self.data);
        Ok(self.data)
    }

    /// Finalise and write to `path`.
    pub fn write_to(self, path: &Path) -> Result<()> {
        let data = self.build()?;
        fs::write(path, &data)
            .map_err(|e| DexError::DexFileError(format!("write {}: {e}", path.display())))
    }

    // -- private methods -------------------------------------------------------

    /// Same MUTF-8 byte length: patch in place, re-sort string_ids if needed.
    fn rename_inplace(&mut self, old_bytes: &[u8], new_bytes: &[u8]) -> Result<()> {
        let h = CachedHeader::from_data(&self.data)?;

        let string_idx = find_string_idx(&self.data, &h, old_bytes)
            .ok_or_else(|| DexError::DexFileError("class descriptor not in string pool".into()))?;

        let id_off = h.string_ids_off as usize + string_idx as usize * 4;
        let str_data_off = read_u32(&self.data, id_off) as usize;

        let mut pos = str_data_off;
        let old_utf16_len = skip_uleb128(&self.data, &mut pos)?;
        let leb_size = pos - str_data_off;
        let content_start = pos;

        // Recompute utf16_len for the new string (may differ for non-ASCII)
        let new_utf16_len = mutf8_len(new_bytes, new_bytes.len())? as u32;
        let new_leb = encode_uleb128(new_utf16_len);

        if new_leb.len() != leb_size {
            // ULEB128 header size changed; fall back to full rebuild
            return self.rename_rebuild(old_bytes, new_bytes);
        }

        if new_utf16_len != old_utf16_len {
            self.data[str_data_off..str_data_off + leb_size].copy_from_slice(&new_leb);
        }
        self.data[content_start..content_start + new_bytes.len()].copy_from_slice(new_bytes);
        // null terminator already in place (lengths are equal)

        // Re-sort string_ids if the new content is out of lexicographic order
        if string_out_of_order(&self.data, &h, string_idx, new_bytes)? {
            resort_and_remap(&mut self.data, &h)?;
        }

        Ok(())
    }

    /// Different MUTF-8 byte length: full string-pool rebuild.
    fn rename_rebuild(&mut self, old_bytes: &[u8], new_bytes: &[u8]) -> Result<()> {
        let h = CachedHeader::from_data(&self.data)?;
        let count = h.string_ids_size as usize;

        // Collect all strings (indexed by current string_ids position = sorted order)
        let mut strings: Vec<Vec<u8>> = collect_strings(&self.data, &h)?;

        let old_string_idx = strings
            .iter()
            .position(|s| s.as_slice() == old_bytes)
            .ok_or_else(|| {
                DexError::DexFileError("class descriptor not in string pool".into())
            })?;
        strings[old_string_idx] = new_bytes.to_vec();

        // Compute new sorted order
        let mut sorted_indices: Vec<usize> = (0..count).collect();
        sorted_indices.sort_by(|&a, &b| strings[a].cmp(&strings[b]));
        // sorted_indices[new_pos] = orig_pos

        // old_to_new[orig_pos] = new_pos
        let mut old_to_new = vec![0u32; count];
        for (new_pos, &orig_pos) in sorted_indices.iter().enumerate() {
            old_to_new[orig_pos] = new_pos as u32;
        }

        // Find the string_data section bounds
        let (old_section_start, old_section_end) =
            find_string_data_section_bounds(&self.data, &h)?;

        // Build the new string_data section; new_offsets[new_pos] = file offset
        let mut new_section: Vec<u8> = Vec::new();
        let mut new_offsets = vec![0u32; count];

        for (new_pos, &orig_pos) in sorted_indices.iter().enumerate() {
            new_offsets[new_pos] = (old_section_start + new_section.len()) as u32;
            let bytes = &strings[orig_pos];
            let utf16_len = mutf8_len(bytes, bytes.len())? as u32;
            new_section.extend_from_slice(&encode_uleb128(utf16_len));
            new_section.extend_from_slice(bytes);
            new_section.push(0);
        }

        let delta = new_section.len() as i64 - (old_section_end - old_section_start) as i64;

        // Splice in the new string_data bytes
        self.data
            .splice(old_section_start..old_section_end, new_section);

        // Shift all file offsets that were past the old section end
        adjust_offsets(&mut self.data, old_section_end, delta);

        // Rewrite string_ids with new file offsets
        let ids_off = CachedHeader::from_data(&self.data)?.string_ids_off as usize;
        for (new_pos, &file_off) in new_offsets.iter().enumerate() {
            write_u32(&mut self.data, ids_off + new_pos * 4, file_off);
        }

        // Remap all string_idx cross-references
        let h2 = CachedHeader::from_data(&self.data)?;
        remap_string_refs(&mut self.data, &h2, &old_to_new);

        // Update file_size and data_size in the header
        let new_file_size = self.data.len() as u32;
        write_u32(&mut self.data, 32, new_file_size); // header offset 32 = file_size
        let data_off = read_u32(&self.data, 108); // header offset 108 = data_off
        if data_off != 0 && new_file_size >= data_off {
            write_u32(&mut self.data, 104, new_file_size - data_off); // offset 104 = data_size
        }

        Ok(())
    }
}

// -- free helpers --------------------------------------------------------------

/// Normalise a class name to its full DEX descriptor form (`Lcom/example/Foo;`).
fn to_descriptor(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') {
        name.to_string()
    } else {
        format!("L{};", name.replace('.', "/"))
    }
}

/// Return the MUTF-8 encoding (with null terminator) of a class descriptor.
fn descriptor_mutf8(name: &str) -> Vec<u8> {
    str_to_mutf8(&to_descriptor(name))
}

/// Find the position in `string_ids` whose string content equals `target` (without null).
fn find_string_idx(data: &[u8], h: &CachedHeader, target: &[u8]) -> Option<u32> {
    let ids_off = h.string_ids_off as usize;
    (0..h.string_ids_size).find(|&i| {
        let data_off = read_u32(data, ids_off + i as usize * 4) as usize;
        read_string_bytes(data, data_off).as_deref() == Some(target)
    })
}

/// Read the MUTF-8 bytes (without null) for the string_data_item at `data_off`.
fn read_string_bytes(data: &[u8], data_off: usize) -> Option<Vec<u8>> {
    let mut pos = data_off;
    skip_uleb128(data, &mut pos).ok()?;
    let start = pos;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    Some(data[start..pos].to_vec())
}

/// Find the type_ids index whose `descriptor_idx` equals `string_idx`.
fn find_type_idx(data: &[u8], h: &CachedHeader, string_idx: u32) -> Option<u16> {
    let ids_off = h.type_ids_off as usize;
    (0..h.type_ids_size as usize).find_map(|i| {
        let sidx = read_u32(data, ids_off + i * 4);
        (sidx == string_idx).then_some(i as u16)
    })
}

/// Return the byte offset of the `ClassDef` for `type_idx`, or `None`.
fn find_class_def_off(data: &[u8], h: &CachedHeader, type_idx: u16) -> Option<usize> {
    const CLASS_DEF_SIZE: usize = 32;
    let defs_off = h.class_defs_off as usize;
    (0..h.class_defs_size as usize).find_map(|i| {
        let off = defs_off + i * CLASS_DEF_SIZE;
        (read_u16(data, off) == type_idx).then_some(off)
    })
}

/// Resolve a class descriptor -> byte offset of its `ClassDef`.
fn resolve_class_def_off(data: &[u8], h: &CachedHeader, class_desc: &str) -> Result<usize> {
    let mutf8 = descriptor_mutf8(class_desc);
    let content = &mutf8[..mutf8.len() - 1]; // strip null for comparison

    let string_idx = find_string_idx(data, h, content)
        .ok_or_else(|| DexError::DexFileError(format!("string not found: {class_desc}")))?;
    let type_idx = find_type_idx(data, h, string_idx)
        .ok_or_else(|| DexError::DexFileError(format!("type not found: {class_desc}")))?;
    find_class_def_off(data, h, type_idx)
        .ok_or_else(|| DexError::DexFileError(format!("class not found: {class_desc}")))
}

/// Return `true` if method `method_idx` has the MUTF-8 name `target_mutf8` (with null).
fn method_name_matches_mutf8(
    data: &[u8],
    h: &CachedHeader,
    method_idx: u32,
    target_mutf8: &[u8],
) -> Result<bool> {
    if method_idx >= h.method_ids_size {
        return Ok(false);
    }
    // MethodId layout: class_idx(2) + proto_idx(2) + name_idx(4); name_idx at offset 4
    let mid_off = h.method_ids_off as usize + method_idx as usize * 8;
    let name_idx = read_u32(data, mid_off + 4);
    if name_idx >= h.string_ids_size {
        return Ok(false);
    }
    let str_data_off = read_u32(data, h.string_ids_off as usize + name_idx as usize * 4) as usize;
    let mut pos = str_data_off;
    skip_uleb128(data, &mut pos)?;
    Ok(data.get(pos..pos + target_mutf8.len()) == Some(target_mutf8))
}

/// Collect all string content bytes (no null) indexed by `string_ids` position.
fn collect_strings(data: &[u8], h: &CachedHeader) -> Result<Vec<Vec<u8>>> {
    (0..h.string_ids_size as usize)
        .map(|i| {
            let id_off = h.string_ids_off as usize + i * 4;
            let str_data_off = read_u32(data, id_off) as usize;
            read_string_bytes(data, str_data_off)
                .ok_or_else(|| DexError::DexFileError("truncated string data".into()))
        })
        .collect()
}

/// Find the [start, end) byte range of the string_data section.
fn find_string_data_section_bounds(data: &[u8], h: &CachedHeader) -> Result<(usize, usize)> {
    if h.string_ids_size == 0 {
        return Err(DexError::DexFileError("DEX has no strings".into()));
    }
    let mut min_off = usize::MAX;
    let mut max_off: usize = 0;
    for i in 0..h.string_ids_size as usize {
        let id_off = h.string_ids_off as usize + i * 4;
        let off = read_u32(data, id_off) as usize;
        min_off = min_off.min(off);
        max_off = max_off.max(off);
    }
    // Compute the end of the last string_data_item
    let end = {
        let mut pos = max_off;
        skip_uleb128(data, &mut pos)
            .map_err(|_| DexError::DexFileError("truncated string data".into()))?;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return Err(DexError::DexFileError("unterminated string".into()));
        }
        pos + 1 // include null terminator
    };
    Ok((min_off, end))
}

/// Check whether `string_idx`'s new content is out of lexicographic order.
fn string_out_of_order(
    data: &[u8],
    h: &CachedHeader,
    string_idx: u32,
    new_bytes: &[u8],
) -> Result<bool> {
    let idx = string_idx as usize;
    let n = h.string_ids_size as usize;
    let ids_off = h.string_ids_off as usize;

    if idx > 0 {
        let prev_off = read_u32(data, ids_off + (idx - 1) * 4) as usize;
        let prev = read_string_bytes(data, prev_off)
            .ok_or_else(|| DexError::DexFileError("bad string data".into()))?;
        if new_bytes < prev.as_slice() {
            return Ok(true);
        }
    }
    if idx + 1 < n {
        let next_off = read_u32(data, ids_off + (idx + 1) * 4) as usize;
        let next = read_string_bytes(data, next_off)
            .ok_or_else(|| DexError::DexFileError("bad string data".into()))?;
        if new_bytes > next.as_slice() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Re-sort the `string_ids` array by string content and remap all cross-references.
fn resort_and_remap(data: &mut [u8], h: &CachedHeader) -> Result<()> {
    let n = h.string_ids_size as usize;
    let ids_off = h.string_ids_off as usize;

    // Collect (original_pos, file_off, content_bytes)
    let mut entries: Vec<(usize, u32, Vec<u8>)> = (0..n)
        .map(|i| {
            let file_off = read_u32(data, ids_off + i * 4);
            let bytes = read_string_bytes(data, file_off as usize).unwrap_or_default();
            (i, file_off, bytes)
        })
        .collect();

    entries.sort_by(|(_, _, a), (_, _, b)| a.cmp(b));
    // entries[new_pos] = (orig_pos, file_off, bytes)

    let mut old_to_new = vec![0u32; n];
    for (new_pos, (orig_pos, _, _)) in entries.iter().enumerate() {
        old_to_new[*orig_pos] = new_pos as u32;
    }

    for (new_pos, (_, file_off, _)) in entries.iter().enumerate() {
        write_u32(data, ids_off + new_pos * 4, *file_off);
    }

    remap_string_refs(data, h, &old_to_new);
    Ok(())
}

/// Update all u32 string_idx references using `old_to_new[old_idx] = new_idx`.
///
/// Tables: type_ids (descriptor_idx), proto_ids (shorty_idx),
/// method_ids (name_idx), field_ids (name_idx), class_defs (source_file_idx).
fn remap_string_refs(data: &mut [u8], h: &CachedHeader, old_to_new: &[u32]) {
    let remap = |v: u32| old_to_new.get(v as usize).copied().unwrap_or(v);

    // type_ids: descriptor_idx (u32) at offset 0, 4 bytes per entry
    for i in 0..h.type_ids_size as usize {
        let off = h.type_ids_off as usize + i * 4;
        let v = read_u32(data, off);
        write_u32(data, off, remap(v));
    }
    // proto_ids: shorty_idx (u32) at offset 0, 12 bytes per entry
    for i in 0..h.proto_ids_size as usize {
        let off = h.proto_ids_off as usize + i * 12;
        let v = read_u32(data, off);
        write_u32(data, off, remap(v));
    }
    // method_ids: name_idx (u32) at offset 4, 8 bytes per entry
    for i in 0..h.method_ids_size as usize {
        let off = h.method_ids_off as usize + i * 8 + 4;
        let v = read_u32(data, off);
        write_u32(data, off, remap(v));
    }
    // field_ids: name_idx (u32) at offset 4, 8 bytes per entry
    for i in 0..h.field_ids_size as usize {
        let off = h.field_ids_off as usize + i * 8 + 4;
        let v = read_u32(data, off);
        write_u32(data, off, remap(v));
    }
    // class_defs: source_file_idx (u32) at offset 16, 32 bytes per entry
    for i in 0..h.class_defs_size as usize {
        let off = h.class_defs_off as usize + i * 32 + 16;
        let v = read_u32(data, off);
        if v != u32::MAX {
            write_u32(data, off, remap(v));
        }
    }
}

/// Shift all stored file offsets >= `threshold` by `delta`.
///
/// Adjusts: header offset fields, map list entries, ClassDef offset fields,
/// and CodeItem debug_info_off fields. Call after splicing bytes so that the
/// threshold equals the byte position after the last unchanged byte.
fn adjust_offsets(data: &mut [u8], threshold: usize, delta: i64) {
    if delta == 0 {
        return;
    }
    let threshold = threshold as u32;
    let adjust = |v: u32| -> u32 {
        if v != 0 && v >= threshold {
            (v as i64 + delta) as u32
        } else {
            v
        }
    };

    // Header offset fields (byte offset -> field):
    //   48=link_off, 52=map_off, 60=string_ids_off, 68=type_ids_off,
    //   76=proto_ids_off, 84=field_ids_off, 92=method_ids_off, 100=class_defs_off, 108=data_off
    const OFFSET_FIELDS: &[usize] = &[48, 52, 60, 68, 76, 84, 92, 100, 108];
    for &byte_off in OFFSET_FIELDS {
        if byte_off + 4 <= data.len() {
            let v = read_u32(data, byte_off);
            write_u32(data, byte_off, adjust(v));
        }
    }

    // Fix file_size at byte 32
    write_u32(data, 32, data.len() as u32);

    // Adjust map list entries (read map_off after the header adjustment above)
    let map_off = read_u32(data, 52) as usize;
    if map_off + 4 > data.len() {
        return;
    }
    let count = read_u32(data, map_off) as usize;
    const MAP_ITEM_SIZE: usize = mem::size_of::<MapItem>(); // 12
    for i in 0..count {
        // MapItem: type_(2) + unused_(2) + size(4) + off(4); off field at byte 8 within item
        let off_field = map_off + 4 + i * MAP_ITEM_SIZE + 8;
        if off_field + 4 <= data.len() {
            let v = read_u32(data, off_field);
            write_u32(data, off_field, adjust(v));
        }
    }

    // Adjust ClassDef offset fields within each ClassDef (32 bytes each):
    //   interfaces_off @ +12, annotations_off @ +20, class_data_off @ +24, static_values_off @ +28
    let class_defs_off = read_u32(data, 100) as usize;
    let class_defs_size = read_u32(data, 96) as usize;
    const CLASS_DEF_SIZE: usize = 32;
    const CLASS_DEF_OFFSET_FIELDS: &[usize] = &[12, 20, 24, 28];
    for i in 0..class_defs_size {
        let def_base = class_defs_off + i * CLASS_DEF_SIZE;
        for &rel_off in CLASS_DEF_OFFSET_FIELDS {
            let abs_off = def_base + rel_off;
            if abs_off + 4 <= data.len() {
                let v = read_u32(data, abs_off);
                write_u32(data, abs_off, adjust(v));
            }
        }
    }

    // Adjust debug_info_off in CodeItems (variable-size, located via map list).
    // CodeItem layout: registers(2)+ins(2)+outs(2)+tries(2)+debug_info_off(4)+insns_size(4)+insns[...]
    // We need to find code items via the map list entry (type 0x2001 = CODE_ITEM).
    const CODE_ITEM_TYPE: u16 = 0x2001;
    // Re-read map after adjustments above
    if map_off + 4 > data.len() {
        return;
    }
    let map_count = read_u32(data, map_off) as usize;
    for i in 0..map_count {
        let item_off = map_off + 4 + i * MAP_ITEM_SIZE;
        if item_off + MAP_ITEM_SIZE > data.len() {
            break;
        }
        let item_type = u16::from_le_bytes([data[item_off], data[item_off + 1]]);
        if item_type != CODE_ITEM_TYPE {
            continue;
        }
        let code_items_count = read_u32(data, item_off + 4) as usize;
        let mut code_item_off = read_u32(data, item_off + 8) as usize;
        for _ in 0..code_items_count {
            if code_item_off + 16 > data.len() {
                break;
            }
            // debug_info_off at byte 8 within CodeItem
            let dbg_field = code_item_off + 8;
            let v = read_u32(data, dbg_field);
            write_u32(data, dbg_field, adjust(v));

            // Advance to next CodeItem: header(16) + insns_size*2 bytes, aligned to 4
            let insns_size = read_u32(data, code_item_off + 12) as usize;
            let raw_next = code_item_off + 16 + insns_size * 2;
            // align up to 4
            code_item_off = (raw_next + 3) & !3;
        }
        break; // only one CODE_ITEM map entry
    }
}

// --- Tests -------------------------------------------------------------------

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{verifier::VerifyPreset, DexFile, DexLocation};

    const PRIME: &[u8] = include_bytes!("../../tests/prime/prime.dex");
    const FIB:   &[u8] = include_bytes!("../../tests/fibonacci/fib.dex");

    fn prime() -> DexEditor { DexEditor::from_bytes(PRIME.to_vec()).unwrap() }

    // -- from_bytes -----------------------------------------------------------

    #[test]
    fn from_bytes_valid() { let _ = prime(); }

    #[test]
    fn from_bytes_invalid_magic_errors() {
        assert!(DexEditor::from_bytes(b"not a dex file".to_vec()).is_err());
    }

    #[test]
    fn from_bytes_too_short_errors() {
        assert!(DexEditor::from_bytes(vec![0u8; 10]).is_err());
    }

    // -- set_class_access_flags -----------------------------------------------

    #[test]
    fn set_class_flags_roundtrip() {
        let mut ed = prime();
        ed.set_class_access_flags("Lprime/prime;", 0x0011).unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        assert_eq!(dex.get_class_def(0).unwrap().access_flags, 0x0011);
    }

    #[test]
    fn set_class_flags_dotted_name() {
        let mut ed = prime();
        ed.set_class_access_flags("prime.prime", 0x0001).unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        assert_eq!(dex.get_class_def(0).unwrap().access_flags, 0x0001);
    }

    #[test]
    fn set_class_flags_unknown_class_errors() {
        let mut ed = prime();
        assert!(ed.set_class_access_flags("Lno/such/Class;", 0x0001).is_err());
    }

    // -- set_method_access_flags ----------------------------------------------

    #[test]
    fn set_method_flags_main() {
        let mut ed = prime();
        ed.set_method_access_flags("Lprime/prime;", "main", 0x0009).unwrap();
        let bytes = ed.build().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn set_method_flags_unknown_method_errors() {
        let mut ed = prime();
        assert!(ed.set_method_access_flags("Lprime/prime;", "noSuch", 0x0001).is_err());
    }

    // -- rename_class ---------------------------------------------------------

    #[test]
    fn rename_same_length_roundtrip() {
        let mut ed = prime();
        ed.rename_class("Lprime/prime;", "Lprime/other;").unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        let desc = dex.get_type_desc_utf16_at(dex.get_class_def(0).unwrap().class_idx).unwrap();
        assert_eq!(desc, "Lprime/other;");
    }

    #[test]
    fn rename_different_length_roundtrip() {
        let mut ed = prime();
        ed.rename_class("Lprime/prime;", "Lprime/renamed;").unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        let desc = dex.get_type_desc_utf16_at(dex.get_class_def(0).unwrap().class_idx).unwrap();
        assert_eq!(desc, "Lprime/renamed;");
    }

    #[test]
    fn rename_verifies_checksum() {
        let mut ed = prime();
        ed.rename_class("Lprime/prime;", "Lprime/renamed;").unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        DexFile::verify(&dex, VerifyPreset::ChecksumOnly).unwrap();
    }

    #[test]
    fn rename_unknown_class_errors() {
        let mut ed = prime();
        assert!(ed.rename_class("Lno/such/Class;", "Lnew/name;").is_err());
    }

    // -- clear_hiddenapi ------------------------------------------------------

    #[test]
    fn clear_hiddenapi_noop_on_plain_dex() {
        let mut ed = prime();
        let _ = ed.clear_hiddenapi_flags();
        ed.build().unwrap();
    }

    // -- build ----------------------------------------------------------------

    #[test]
    fn build_preserves_size_for_no_op() {
        let bytes = prime().build().unwrap();
        assert_eq!(bytes.len(), PRIME.len());
    }

    #[test]
    fn multiple_mutations_chained() {
        let mut ed = prime();
        ed.set_class_access_flags("Lprime/prime;", 0x0011).unwrap();
        ed.set_method_access_flags("Lprime/prime;", "main", 0x0009).unwrap();
        ed.rename_class("Lprime/prime;", "Lprime/renamed;").unwrap();
        let bytes = ed.build().unwrap();
        let dex = DexFile::from_raw_parts(&bytes, DexLocation::InMemory).unwrap();
        let cd = dex.get_class_def(0).unwrap();
        assert_eq!(cd.access_flags, 0x0011);
        assert_eq!(dex.get_type_desc_utf16_at(cd.class_idx).unwrap(), "Lprime/renamed;");
    }

    #[test]
    fn fib_roundtrip() {
        let mut ed = DexEditor::from_bytes(FIB.to_vec()).unwrap();
        ed.set_class_access_flags("Lfibonacci/fib;", 0x0001).unwrap();
        DexFile::from_raw_parts(&ed.build().unwrap(), DexLocation::InMemory).unwrap();
    }
}
