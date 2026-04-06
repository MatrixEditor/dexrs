use adler32;

use crate::{dex_err, error::DexError, Result};

use super::{
    DexContainer, DexFile, Header, CDEX_MAGIC, CDEX_MAGIC_VERSIONS, DEX_ENDIAN_CONSTANT,
    DEX_MAGIC, DEX_MAGIC_VERSIONS,
};

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyPreset {
    None,
    All,
    ChecksumOnly,
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn is_magic_valid(&self) -> bool {
        let magic4 = &self.header.get_magic()[..4];
        magic4 == DEX_MAGIC || magic4 == CDEX_MAGIC
    }

    pub fn is_version_valid(&self) -> bool {
        let version_raw = &self.header.get_magic()[4..];
        DEX_MAGIC_VERSIONS.contains(&version_raw) || CDEX_MAGIC_VERSIONS.contains(&version_raw)
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
    // Structural checks (truncation, magic, version, file/header size) are
    // already enforced by DexFile::init(), which runs before verify(). Here
    // we only handle the checks that init() intentionally defers.

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

    let header = &dex.header;
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
            size: file_size,
            section: label
        });
    }

    // TODO alignment checks
    Ok(())
}
