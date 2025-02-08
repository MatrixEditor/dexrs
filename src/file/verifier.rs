use adler32;

use crate::{dex_err, error::DexError, Result};

use super::{
    DexContainer, DexFile, Header, HeaderV41, DEX_ENDIAN_CONSTANT, DEX_MAGIC, DEX_MAGIC_VERSIONS,
};

pub enum VerifyPreset {
    None,
    All,
    ChecksumOnly,
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn is_magic_valid(&self) -> bool {
        &self.header.get_magic()[..4] == DEX_MAGIC
    }

    pub fn is_version_valid(&self) -> bool {
        let version_raw = &self.header.get_magic()[4..];
        DEX_MAGIC_VERSIONS.contains(&version_raw)
    }

    // TODO: can be changed into enum
    pub fn verify(dex: &DexFile<'a, C>, preset: VerifyPreset) -> Result<()> {
        check_header(dex, preset)?;
        //  REVISIT: maybe validate map list items
        Ok(())
    }

    pub fn calculate_checksum(&self) -> u32 {
        let size = self.file_size();
        let data = &self.mmap[12..size];
        adler32::adler32(data).unwrap()
    }
}

fn check_header<'a, C>(dex: &DexFile<'a, C>, preset: VerifyPreset) -> Result<()>
where
    C: DexContainer<'a>,
{
    let size = dex.file_size();
    if size < std::mem::size_of::<Header>() {
        return dex_err!(TruncatedFile);
    }

    if !dex.is_magic_valid() {
        return dex_err!(BadFileMagic);
    }

    if !dex.is_version_valid() {
        return dex_err!(UnknownDexVersion {
            version: dex.header.get_version()
        });
    }

    // check file size from header
    let version = dex.header.get_version();
    let file_size = dex.header.file_size as usize;
    let header_size = if version >= 41 {
        std::mem::size_of::<HeaderV41>()
    } else {
        std::mem::size_of::<Header>()
    };

    if file_size < header_size {
        return dex_err!(FileSizeAtLeast {
            actual: file_size,
            expected: header_size
        });
    }
    if file_size > size {
        return dex_err!(FileSizeAtMost {
            actual: file_size,
            expected: size
        });
    }

    // check header size
    if dex.header.header_size as usize != header_size {
        return dex_err!(BadHeaderSize {
            size: dex.header.header_size,
            expected: header_size as u32
        });
    }

    // check endian
    if dex.header.endian_tag != DEX_ENDIAN_CONSTANT {
        return dex_err!(UnexpectedEndianess, dex.header.endian_tag);
    }

    match &preset {
        VerifyPreset::All | VerifyPreset::ChecksumOnly => {
            let checksum = dex.calculate_checksum();
            if checksum != dex.header.checksum {
                return dex_err!(BadChecksum {
                    actual: checksum,
                    expected: dex.header.checksum
                });
            }
        }
        _ => {}
    };

    let header = dex.header;
    check_valid_offset_and_size(dex, header.link_off, header.link_size, "link")?;
    check_valid_offset_and_size(
        dex,
        header.map_off,
        std::mem::size_of::<u32>() as u32,
        "map",
    )?;
    check_valid_offset_and_size(
        dex,
        header.string_ids_off,
        header.string_ids_size,
        "string-ids",
    )?;
    check_valid_offset_and_size(dex, header.type_ids_off, header.type_ids_size, "type-ids")?;
    check_valid_offset_and_size(
        dex,
        header.proto_ids_off,
        header.proto_ids_size,
        "proto-ids",
    )?;
    check_valid_offset_and_size(
        dex,
        header.field_ids_off,
        header.field_ids_size,
        "field-ids",
    )?;
    check_valid_offset_and_size(
        dex,
        header.method_ids_off,
        header.method_ids_size,
        "method-ids",
    )?;
    check_valid_offset_and_size(
        dex,
        header.class_defs_off,
        header.class_defs_size,
        "class-defs",
    )?;
    check_valid_offset_and_size(dex, header.data_off, header.data_size, "data")?;
    Ok(())
}

fn check_valid_offset_and_size<'a, C>(
    dex: &DexFile<'a, C>,
    offset: u32,
    size: u32,
    label: &'static str,
) -> Result<()>
where
    C: DexContainer<'a>,
{
    if size == 0 {
        if offset != 0 {
            return dex_err!(BadOffsetNoSize {
                offset,
                section: label
            });
        }

        return Ok(());
    }

    let file_size = dex.file_size();
    let header_offset = std::mem::size_of::<Header>() as u32;
    if offset < header_offset {
        return dex_err!(BadOffsetInHeader {
            offset,
            header_size: header_offset as usize,
            section: label
        });
    }
    if offset as usize > file_size {
        return dex_err!(BadOffsetTooLarge {
            offset,
            size: dex.file_size(),
            section: label
        });
    }

    if (file_size - offset as usize) < size as usize {
        return dex_err!(BadSection {
            offset: offset + size,
            size: file_size as usize,
            section: label
        });
    }

    // TODO alignment checks
    Ok(())
}
