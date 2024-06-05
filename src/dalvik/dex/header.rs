use binrw::binrw;
use openssl::sha;
use std::{
    io::{self},
    result,
};

use super::types::*;
use crate::dalvik::error::ConstraintError;

/// The magic number for a DEX file represented as a byte array. It translates
/// to b'dex\n'.
pub const DEX_FILE_MAGIC: [UByte; 4] = [0x64, 0x65, 0x78, 0x0a];

/// Contains the structure of DEX_FILE_MAGIC. It must appear at the beginning
/// of a DEX file. Splitting the bytes in this way allows us to use the version
/// number as a u32.
#[binrw]
#[brw(little, magic = b"dex\n")]
#[derive(Debug)]
pub struct Magic {
    /// The version of the DEX file. Use .version_num() to get the version
    /// as a u32.
    version: [UByte; 4],
}

impl Magic {
    /// Returns the version as a u32
    pub fn version_num(&self) -> result::Result<UInt, std::num::ParseIntError> {
        // We assume the version is always 3 bytes and ends with a '\0'
        let raw_version = &self.version[..3];
        return String::from_utf8_lossy(raw_version).parse();
    }
}

/// Default endianness constant indicator
pub const ENDIAN_CONSTANT: UInt = 0x12345678;

/// Reverse endianness constant indicator
///
/// Files with this constant have performed byte-swapping.
pub const REVERSE_ENDIAN_CONSTANT: UInt = 0x78563421;

/// The constant `NO_INDEX` is used to indicate that an index value is absent.
///
/// Its value will be encoded as -1 using the ULeb128p1 encoding.
pub const NO_INDEX: UInt = 0xFFFFFFFF;

/// SHA-1 signature size
pub const SIGNATURE_SIZE: usize = 20;

/// Header item size
pub const HEADER_SIZE: usize = 0x70;



/// Header item data structure
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct HeaderItem {
    /// magic value
    pub magic: Magic,

    /// Taken from Android docs:
    ///
    /// Adler32 checksum of the rest of the file (everything but `magic` and this
    /// field); used to detect file corruption.
    pub checksum: UInt,

    /// Android docs:
    ///
    /// SHA-1 signature (hash) of the rest of the file (everything but `magic`,
    /// `checksum`, and this field); used to uniquely identify files.
    pub signature: [UByte; 20],

    /// Size of the entire file including the header.
    pub file_size: UInt,

    /// Size of the header (this struct), in bytes. It is always 0x70.
    pub header_size: UInt,

    /// Endianness specification.
    pub endian_tag: UInt,

    /// size of the link section, or 0 if this file isn't statically linked
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub link_size: UInt,

    /// offset from the start of the file to the link section, or `0` if
    /// `link_size == 0`. The offset, if non-zero, should be to an offset
    /// into the `link_data` section.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub link_off: UInt,

    /// offset from the start of the file to the map item. The offset, which
    /// must be non-zero, should be to an offset into the `data` section.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub map_off: UInt,

    /// count of strings in the string identifiers list
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub string_ids_size: UInt,

    /// offset from the start of the file to the string identifiers list, or
    /// `0` if `string_ids_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub string_ids_off: UInt,

    /// count of elements in the type identifiers list, at most `65535`
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub type_ids_size: UInt,

    /// offset from the start of the file to the type identifiers list, or
    /// `0` if `type_ids_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub type_ids_off: UInt,

    /// count of elements in the proto identifiers list, at most `65535`
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub proto_ids_size: UInt,

    /// offset from the start of the file to the proto identifiers list, or
    /// `0` if `proto_ids_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub proto_ids_off: UInt,

    /// count of elements in the field identifiers list
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub field_ids_size: UInt,

    /// offset from the start of the file to the field identifiers list, or
    /// `0` if `field_ids_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub field_ids_off: UInt,

    /// count of elements in the method identifiers list
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub method_ids_size: UInt,

    /// offset from the start of the file to the method identifiers list, or
    /// `0` if `method_ids_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub method_ids_off: UInt,

    /// count of elements in the class definitions list
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub class_defs_size: UInt,

    /// offset from the start of the file to the class definitions list, or
    /// `0` if `class_defs_size == 0`.
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub class_defs_off: UInt,

    /// size of the data section (in bytes)
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub data_size: UInt,

    /// offset from the start of the file to the data section
    #[br(is_big = endian_tag == REVERSE_ENDIAN_CONSTANT)]
    pub data_off: UInt,
}

impl HeaderItem {
    pub fn verify<R>(&self, mut reader: R, offset: UInt) -> result::Result<(), ConstraintError>
    where
        R: io::Read + io::Seek,
    {
        if let Err(e) = reader.seek(io::SeekFrom::Start((offset + 12) as u64)) {
            return Err(ConstraintError {
                identifier: "io",
                description: e.to_string(),
            });
        }

        // Verification of the first contraints from the Android docs:
        //
        // G2: The checksum must be an Adler-32 checksum of the whole file contents
        //     except magic and checksum field.
        let checksum = match adler32::adler32(&mut reader) {
            Ok(x) => x,
            Err(e) => {
                return Err(ConstraintError {
                    identifier: "io",
                    description: e.to_string(),
                })
            }
        };

        if checksum != self.checksum {
            return Err(ConstraintError {
                identifier: "G2",
                description: format!("expected {}, got {}", self.checksum, checksum),
            });
        }

        // G3: The signature must be a SHA-1 hash of the whole file contents except
        //     magic, checksum, and signature.
        if let Err(e) = reader.seek(io::SeekFrom::Start((offset + 32) as u64)) {
            return Err(ConstraintError {
                identifier: "io",
                description: e.to_string(),
            });
        }

        let digest = {
            let mut hasher = sha::Sha1::new();
            let mut buffer = [0u8; 1024];

            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            hasher.finish()
        };

        if digest != self.signature {
            return Err(ConstraintError {
                identifier: "G3",
                description: format!("expected {:?}, got {:?}", self.signature, digest),
            });
        }

        // G5: The header_size must be 0x70.
        if self.header_size != 0x70 {
            return Err(ConstraintError {
                identifier: "G5",
                description: format!("expected 0x70, got {}", self.header_size),
            });
        }

        // G6: The endian_tag must have either the value: ENDIAN_CONSTANT or
        //     REVERSE_ENDIAN_CONSTANT
        if self.endian_tag != 0x12345678 && self.endian_tag != 0x78563412 {
            return Err(ConstraintError {
                identifier: "G6",
                description: format!(
                    "expected 0x12345678 or 0x78563412, got {:#x}",
                    self.endian_tag
                ),
            });
        }

        let values = vec![
            (self.link_size, self.link_off, "link"),
            (self.string_ids_size, self.string_ids_off, "string_ids"),
            (self.type_ids_size, self.type_ids_off, "type_ids"),
            (self.proto_ids_size, self.proto_ids_off, "proto_ids"),
            (self.field_ids_size, self.field_ids_off, "field_ids"),
            (self.method_ids_size, self.method_ids_off, "method_ids"),
            (self.class_defs_size, self.class_defs_off, "class_defs"),
            (self.data_size, self.data_off, "data"),
        ];
        for (v1, v2, name) in values {
            if v1 != 0 && v2 == 0 {
                return Err(ConstraintError {
                    identifier: "G7",
                    description: format!(
                        "expected non-zero offset for size {}, got 0 (sec: {})",
                        v1, name
                    ),
                });
            } else if v1 == 0 && v2 != 0 {
                return Err(ConstraintError {
                    identifier: "G7",
                    description: format!(
                        "expected 0 for offset, got non-zero offset {} (sec: {})",
                        v2, name
                    ),
                });
            }
        }

        return Ok(());
    }
}
