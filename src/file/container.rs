use std::ops::Deref;

use memmap2::MmapAsRawDesc;

use crate::Result;

use super::MmapDexFile;

pub trait DexContainer<'a>: AsRef<[u8]> + Deref<Target = [u8]> + 'a {
    fn data(&'a self) -> &'a [u8] {
        self.as_ref()
    }

    fn file_size(&'a self) -> usize {
        self.data().len()
    }
}

impl<'a> DexContainer<'a> for memmap2::Mmap {}

pub struct InMemoryDexContainer<'a>(&'a [u8]);

impl<'a> InMemoryDexContainer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> Deref for InMemoryDexContainer<'a> {
    type Target = [u8];
    fn deref(&self) -> &'a Self::Target {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for InMemoryDexContainer<'a> {
    fn as_ref(&self) -> &'a [u8] {
        &self.0
    }
}

impl<'a> DexContainer<'a> for InMemoryDexContainer<'a> {}

impl<'a> DexContainer<'a> for &'a [u8] {}

pub struct DexFileContainer {
    mmap: memmap2::Mmap,
    location: String,
    pub verify: bool,
    pub verify_checksum: bool,
}

impl DexFileContainer {
    pub fn new<T>(file: T) -> Self
    where
        T: MmapAsRawDesc,
    {
        Self {
            mmap: unsafe { memmap2::Mmap::map(file).unwrap() },
            verify: false,
            verify_checksum: false,
            location: "[anonymous]".to_string(),
        }
    }

    pub fn location(&mut self, location: String) -> &mut Self {
        self.location = location;
        self
    }

    pub fn verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    pub fn verify_checksum(mut self, verify_checksum: bool) -> Self {
        self.verify_checksum = verify_checksum;
        self
    }

    pub fn open<'a>(&'a self) -> Result<MmapDexFile<'a>> {
        MmapDexFile::open(self)
    }

    pub fn get_location(&self) -> &str {
        &self.location
    }

    pub fn data(&self) -> &memmap2::Mmap {
        &self.mmap
    }
}
