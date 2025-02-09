#![allow(unused)]

use dexrs::file::{verifier::VerifyPreset, DexFile, DexFileContainer, DexLocation};

fn parse_dex_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // external files should be opened through a DexFileContainer
    let file = std::fs::File::open(path)?;
    // you can configure whether to verify the dex file
    let container = DexFileContainer::new(&file)
        .verify(true)
        .verify_checksum(true);

    let dex = container.open()?;
    // ...
    Ok(())
}

fn parse_in_memory_file(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // everything that implements a DexContainer can be used
    let file = DexFile::open(&data, DexLocation::InMemory, VerifyPreset::None)?;

    Ok(())
}

fn open_mutable_memory(data: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    // mutable files are still WIP, but their interface will
    // be the same. However, this file will return a valid DexFile
    // only if the given data already contains a valid header definition.
    let mut file = DexFile::open(&data, DexLocation::InMemory, VerifyPreset::None)?;

    Ok(())
}

fn open_mutable_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // The interface for opening files that should be manipulated should
    // be the same as parse_dex_file but with open_mut at the end
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
    // will be updated
    let mut file = DexFile::open(
        &mmap,
        DexLocation::Path(path.to_string()),
        VerifyPreset::None,
    )?;

    Ok(())
}

fn parse_dex_file_unchecked(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // files can be created without further initialization and checks. NOTE:
    // This operation will still try to iterate over the MapList and collect
    // additional items.
    let file = DexFile::from_raw_parts(&data, DexLocation::InMemory)?;

    // verification can be done now
    DexFile::verify(&file, VerifyPreset::All)?;
    Ok(())
}

fn main() {
    // ...
}
