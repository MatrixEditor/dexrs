#[repr(C)]
#[derive(Debug, Clone)]
pub struct Header {
    /// magic value
    magic: [u8; 8],

    /// Taken from Android docs:
    ///
    /// Adler32 checksum of the rest of the file (everything but `magic` and this
    /// field); used to detect file corruption.
    pub checksum: u32,

    /// Android docs:
    ///
    /// SHA-1 signature (hash) of the rest of the file (everything but `magic`,
    /// `checksum`, and this field); used to uniquely identify files.
    signature: [u8; 20],

    /// Size of the entire file including the header.
    pub file_size: u32,

    /// Size of the header (this struct), in bytes. It is always 0x70.
    pub header_size: u32,

    /// Endian contant - ART source code only supports one byte order
    pub endian_tag: u32,

    // unused {
    /// size of the link section, or 0 if this file isn't statically linked
    pub link_size: u32,

    /// offset from the start of the file to the link section, or `0` if
    /// `link_size == 0`. The offset, if non-zero, should be to an offset
    /// into the `link_data` section.
    pub link_off: u32,
    // } unused
    /// offset from the start of the file to the map item. The offset, which
    /// must be non-zero, should be to an offset into the `data` section.
    pub map_off: u32,

    /// count of strings in the string identifiers list
    pub string_ids_size: u32,

    /// offset from the start of the file to the string identifiers list, or
    /// `0` if `string_ids_size == 0`.
    pub string_ids_off: u32,

    /// count of elements in the type identifiers list, at most `65535`
    pub type_ids_size: u32,

    /// offset from the start of the file to the type identifiers list, or
    /// `0` if `type_ids_size == 0`.
    pub type_ids_off: u32,

    /// count of elements in the proto identifiers list, at most `65535`
    pub proto_ids_size: u32,

    /// offset from the start of the file to the proto identifiers list, or
    /// `0` if `proto_ids_size == 0`.
    pub proto_ids_off: u32,

    /// count of elements in the field identifiers list
    pub field_ids_size: u32,

    /// offset from the start of the file to the field identifiers list, or
    /// `0` if `field_ids_size == 0`.
    pub field_ids_off: u32,

    /// count of elements in the method identifiers list
    pub method_ids_size: u32,

    /// offset from the start of the file to the method identifiers list, or
    /// `0` if `method_ids_size == 0`.
    pub method_ids_off: u32,

    /// count of elements in the class definitions list
    pub class_defs_size: u32,

    /// offset from the start of the file to the class definitions list, or
    /// `0` if `class_defs_size == 0`.
    pub class_defs_off: u32,

    /// size of the data section (in bytes)
    pub data_size: u32,

    /// offset from the start of the file to the data section
    pub data_off: u32,
}

unsafe impl plain::Plain for Header {}

impl Header {
    pub fn get_magic(&self) -> &[u8; 8] {
        &self.magic
    }

    pub fn get_signature(&self) -> &[u8; 20] {
        &self.signature
    }

    pub fn get_version(&self) -> u32 {
        let version_raw = &self.magic[4..7];
        String::from_utf8_lossy(version_raw)
            .parse()
            .unwrap_or_default() // will lead to invalid dex file
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct HeaderV41 {
    pub inner: Header,
    pub container_size: u32, // total size of all dex files in the container.
    pub header_off: u32,     // offset of this dex's header in the container.
}
