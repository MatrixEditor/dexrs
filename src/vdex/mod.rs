//! VDEX file parsing.
//!
//! VDEX files are produced by dex2oat and contain:
//! - Checksums of the embedded DEX files for integrity verification.
//! - Optionally, the raw DEX files themselves (kDexFileSection).
//! - Verifier dependency data (kVerifierDepsSection).
//! - Type lookup tables (kTypeLookupTableSection).
//!
//! This module closely follows the layout defined in
//! `art/runtime/vdex_file.h` from the Android Open Source Project.
//!
//! # Container pattern
//!
//! [`VdexFile`] is generic over `C: DexContainer<'a>`, mirroring [`DexFile`].
//! Common aliases:
//! ```ignore
//! type InMemoryVdexFile<'a> = VdexFile<'a, &'a [u8]>;
//! type MmapVdexFile<'a>     = VdexFile<'a, Mmap>;
//! ```

use memmap2::MmapAsRawDesc;
use plain::Plain;

use crate::{
    error::DexError,
    file::{DexContainer, Header},
    Result,
};

// -- Constants -----------------------------------------------------------------

/// Magic bytes at the start of every VDEX file.
pub const VDEX_MAGIC: &[u8; 4] = b"vdex";

/// The only VDEX format version currently supported.
///
/// Matches `kVdexVersion` in `art/runtime/vdex_file.h`.
pub const VDEX_VERSION: &[u8; 4] = b"027\0";

/// Total number of sections in a VDEX file.
pub const VDEX_NUM_SECTIONS: usize = 4;

// -- Section kind --------------------------------------------------------------

/// Identifies a section within the VDEX file.
///
/// The numeric values must match the `VdexSection` enum in ART.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VdexSection {
    /// Adler-32 checksums of the embedded DEX files (one `u32` per file).
    Checksum = 0,
    /// Concatenated DEX file bytes (optional; absent in metadata-only VDEXes).
    DexFile = 1,
    /// Encoded verifier-dependency data.
    VerifierDeps = 2,
    /// Type lookup tables for fast class resolution.
    TypeLookupTable = 3,
}

impl VdexSection {
    fn name(self) -> &'static str {
        match self {
            VdexSection::Checksum => "checksum",
            VdexSection::DexFile => "dex_file",
            VdexSection::VerifierDeps => "verifier_deps",
            VdexSection::TypeLookupTable => "type_lookup_table",
        }
    }
}

// -- On-disk structures --------------------------------------------------------

/// Fixed-size file header at offset 0.
///
/// Layout (12 bytes):
/// ```text
/// magic_[4]            = b"vdex"
/// vdex_version_[4]     = b"027\0"
/// number_of_sections_  = 4  (u32 LE)
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VdexFileHeader {
    pub magic: [u8; 4],
    pub vdex_version: [u8; 4],
    pub number_of_sections: u32,
}

// SAFETY: VdexFileHeader is a flat C struct with no padding or interior
// mutability, and can be safely reinterpreted from aligned byte sequences.
unsafe impl Plain for VdexFileHeader {}

impl VdexFileHeader {
    /// Returns `true` when the magic bytes are `"vdex"`.
    #[inline]
    pub fn is_magic_valid(&self) -> bool {
        &self.magic == VDEX_MAGIC
    }

    /// Returns `true` when the version string matches the supported version.
    #[inline]
    pub fn is_version_valid(&self) -> bool {
        &self.vdex_version == VDEX_VERSION
    }
}

/// Per-section descriptor stored immediately after [`VdexFileHeader`].
///
/// Layout (12 bytes):
/// ```text
/// section_kind    u32 LE - VdexSection discriminant
/// section_offset  u32 LE - byte offset from start of file
/// section_size    u32 LE - byte length of section (0 = absent)
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VdexSectionHeader {
    pub section_kind: u32,
    pub section_offset: u32,
    pub section_size: u32,
}

// SAFETY: Same reasoning as VdexFileHeader.
unsafe impl Plain for VdexSectionHeader {}

// -- VdexFile ------------------------------------------------------------------

// -- Type aliases --------------------------------------------------------------

pub type InMemoryVdexFile<'a> = VdexFile<'a, &'a [u8]>;
pub type MmapVdexFile<'a> = VdexFile<'a, memmap2::Mmap>;

// -- VdexFile ------------------------------------------------------------------

/// Parsed view of a VDEX file backed by a [`DexContainer`].
///
/// The type parameter `C` is the backing store (mmap, `&[u8]`, `Vec<u8]`, …),
/// exactly mirroring the [`DexFile<'a, C>`][crate::file::DexFile] design.
/// The lifetime `'a` ties all data references to the container.
///
/// # Construction
///
/// ```ignore
/// // From an in-memory byte slice:
/// let vdex = VdexFile::from_raw_parts(&data, ())?;
///
/// // From a memory-mapped file:
/// let mmap = unsafe { Mmap::map(&file)? };
/// let vdex = VdexFile::from_raw_parts(&mmap, ())?;
/// ```
pub struct VdexFile<'a, C: DexContainer<'a> = memmap2::Mmap> {
    /// Reference to the backing container - same field name and semantics as
    /// `DexFile::mmap`.
    pub(crate) mmap: &'a C,
    /// Owned copy of the file-level header, read via `plain::copy_from_bytes`
    /// so that the container does not need to be aligned.
    header: VdexFileHeader,
    /// Section descriptors in VDEX order (Checksum … TypeLookupTable).
    sections: Vec<VdexSectionHeader>,
}

impl<'a, C: DexContainer<'a>> VdexFile<'a, C> {
    // -- Helper: raw slice from container --------------------------------------

    /// Returns `&'a [u8]` for `container[start..end]`, propagating the
    /// container's lifetime - the same pattern used by `DexFile::get_section`.
    #[inline]
    fn raw_slice(base: &'a C, start: usize, end: usize) -> &'a [u8] {
        &base[start..end]
    }

    // -- Construction ----------------------------------------------------------

    /// Parse and validate a VDEX file from a container.
    ///
    /// Mirrors `DexFile::from_raw_parts(base, location)`.
    ///
    /// Returns an error when:
    /// - The buffer is too short to hold the file header + section headers.
    /// - The magic bytes are not `"vdex"`.
    /// - The version string is not the supported version.
    /// - Any section descriptor places data outside the container.
    pub fn from_raw_parts(base: &'a C) -> Result<Self> {
        let data_len = base.len();
        let header_size = std::mem::size_of::<VdexFileHeader>();

        if data_len < header_size {
            return Err(DexError::TruncatedVdexFile { size: data_len });
        }

        // Read the file header into an owned value (alignment-independent).
        let mut header = unsafe { std::mem::zeroed::<VdexFileHeader>() };
        plain::copy_from_bytes(&mut header, base).map_err(|_| DexError::TruncatedVdexFile {
            size: data_len,
        })?;

        if !header.is_magic_valid() {
            return Err(DexError::BadVdexMagic);
        }
        if !header.is_version_valid() {
            return Err(DexError::UnknownVdexVersion {
                version: header.vdex_version,
            });
        }

        let n = header.number_of_sections as usize;
        let sections_start = header_size;
        let section_hdr_size = std::mem::size_of::<VdexSectionHeader>();
        let sections_end = sections_start
            .checked_add(n * section_hdr_size)
            .ok_or(DexError::TruncatedVdexFile { size: data_len })?;

        if data_len < sections_end {
            return Err(DexError::TruncatedVdexFile { size: data_len });
        }

        // Read section headers into an owned Vec (alignment-independent).
        let mut sections = Vec::with_capacity(n);
        for i in 0..n {
            let off = sections_start + i * section_hdr_size;
            let mut sec = unsafe { std::mem::zeroed::<VdexSectionHeader>() };
            plain::copy_from_bytes(&mut sec, &base[off..])
                .map_err(|_| DexError::TruncatedVdexFile { size: data_len })?;
            sections.push(sec);
        }

        let vdex = VdexFile { mmap: base, header, sections };
        vdex.validate_sections()?;
        Ok(vdex)
    }

    // -- Header accessors ------------------------------------------------------

    /// Raw file header.
    #[inline]
    pub fn file_header(&self) -> &VdexFileHeader {
        &self.header
    }

    /// Number of sections declared in the header.
    #[inline]
    pub fn num_sections(&self) -> u32 {
        self.header.number_of_sections
    }

    /// Total byte length of the underlying container.
    #[inline]
    pub fn size(&self) -> usize {
        self.mmap.len()
    }

    // -- Section accessors -----------------------------------------------------

    /// Returns the [`VdexSectionHeader`] for `kind`, or `None` if the file
    /// does not have that many sections.
    #[inline]
    pub fn get_section_header(&self, kind: VdexSection) -> Option<&VdexSectionHeader> {
        self.sections.get(kind as usize)
    }

    /// Returns a raw `&'a [u8]` for the given section (empty when absent).
    ///
    /// The returned slice borrows directly from the container - no copying.
    pub fn get_section_data(&self, kind: VdexSection) -> &'a [u8] {
        let Some(hdr) = self.get_section_header(kind) else {
            return &[];
        };
        if hdr.section_size == 0 {
            return &[];
        }
        let start = hdr.section_offset as usize;
        let end = start + hdr.section_size as usize;
        Self::raw_slice(self.mmap, start, end)
    }

    // -- Checksum section ------------------------------------------------------

    /// Number of DEX files whose checksums are stored in the checksum section.
    #[inline]
    pub fn num_dex_files(&self) -> u32 {
        match self.get_section_header(VdexSection::Checksum) {
            Some(hdr) => hdr.section_size / std::mem::size_of::<u32>() as u32,
            None => 0,
        }
    }

    /// Returns the full slice of DEX-file checksums (borrows from container).
    pub fn dex_checksums(&self) -> &'a [u32] {
        let data = self.get_section_data(VdexSection::Checksum);
        u32::slice_from_bytes(data).unwrap_or(&[])
    }

    /// Returns the Adler-32 checksum of the DEX file at `index`.
    pub fn dex_checksum_at(&self, index: u32) -> Result<u32> {
        let n = self.num_dex_files();
        if index >= n {
            return Err(DexError::VdexDexIndexOutOfRange {
                index,
                num_dex_files: n,
            });
        }
        Ok(self.dex_checksums()[index as usize])
    }

    // -- DEX file section ------------------------------------------------------

    /// Returns `true` when the VDEX contains embedded DEX file bytes.
    #[inline]
    pub fn has_dex_section(&self) -> bool {
        self.get_section_header(VdexSection::DexFile)
            .is_some_and(|h| h.section_size != 0)
    }

    /// Returns the raw bytes of the DEX file at `index` as a `&'a [u8]` slice
    /// that borrows directly from the container - no copying.
    ///
    /// DEX files inside the section are stored back-to-back with 4-byte
    /// alignment (matching `OatWriter::SeekToDexFiles`).
    pub fn get_dex_file_data(&self, index: u32) -> Result<&'a [u8]> {
        let n = self.num_dex_files();
        if index >= n {
            return Err(DexError::VdexDexIndexOutOfRange {
                index,
                num_dex_files: n,
            });
        }
        if !self.has_dex_section() {
            return Err(DexError::BadVdexSection {
                section: "dex_file",
                msg: "VDEX does not contain a DEX file section".to_string(),
            });
        }

        let sec_hdr = self.get_section_header(VdexSection::DexFile).unwrap();
        let sec_start = sec_hdr.section_offset as usize;
        let sec_end = sec_start + sec_hdr.section_size as usize;

        let mut offset = sec_start;
        for i in 0..=index {
            let dex_header_end = offset + std::mem::size_of::<Header>();
            if dex_header_end > sec_end {
                return Err(DexError::BadVdexSection {
                    section: "dex_file",
                    msg: format!("DEX header for index {i} extends beyond section bounds"),
                });
            }

            let mut dex_hdr = unsafe { std::mem::zeroed::<Header>() };
            plain::copy_from_bytes(&mut dex_hdr, &self.mmap[offset..])
                .map_err(|_| DexError::BadVdexSection {
                    section: "dex_file",
                    msg: format!("Cannot read DEX header at offset {offset} for index {i}"),
                })?;

            let file_size = dex_hdr.file_size as usize;
            let dex_end = offset + file_size;
            if dex_end > sec_end {
                return Err(DexError::BadVdexSection {
                    section: "dex_file",
                    msg: format!(
                        "DEX file {i} at offset {offset} with size {file_size} overflows section"
                    ),
                });
            }

            if i == index {
                return Ok(Self::raw_slice(self.mmap, offset, dex_end));
            }

            offset = align_up(dex_end, 4);
        }

        Err(DexError::VdexDexIndexOutOfRange {
            index,
            num_dex_files: n,
        })
    }

    /// Returns an iterator over the raw byte slices of each embedded DEX file.
    ///
    /// Each item is `Result<&'a [u8]>`.  To parse a DEX file call
    /// [`DexFile::from_raw_parts`][crate::file::DexFile::from_raw_parts] on
    /// the slice:
    ///
    /// ```ignore
    /// for raw in vdex.iter_dex_files() {
    ///     let dex = raw.and_then(|b| DexFile::from_raw_parts(b, DexLocation::InMemory));
    /// }
    /// ```
    pub fn iter_dex_files(&self) -> impl Iterator<Item = Result<&'a [u8]>> + '_ {
        (0..self.num_dex_files()).map(|i| self.get_dex_file_data(i))
    }

    // -- Verifier deps section -------------------------------------------------

    /// Raw bytes of the verifier-dependency section (empty when absent).
    #[inline]
    pub fn verifier_deps_data(&self) -> &'a [u8] {
        self.get_section_data(VdexSection::VerifierDeps)
    }

    // -- Type lookup table section ---------------------------------------------

    /// Returns `true` when the VDEX includes a type-lookup-table section.
    #[inline]
    pub fn has_type_lookup_table_section(&self) -> bool {
        self.num_sections() as usize > VdexSection::TypeLookupTable as usize
    }

    /// Raw bytes of the type-lookup-table section (empty when absent).
    #[inline]
    pub fn type_lookup_table_data(&self) -> &'a [u8] {
        self.get_section_data(VdexSection::TypeLookupTable)
    }

    // -- Checksum matching -----------------------------------------------------

    /// Returns `true` when the checksums stored in the VDEX match those in
    /// `dex_headers` (count and order must both match).
    pub fn matches_dex_checksums(&self, dex_headers: &[&Header]) -> bool {
        if dex_headers.len() as u32 != self.num_dex_files() {
            return false;
        }
        self.dex_checksums()
            .iter()
            .zip(dex_headers)
            .all(|(stored, hdr)| *stored == hdr.checksum)
    }

    // -- Private helpers -------------------------------------------------------

    fn validate_sections(&self) -> Result<()> {
        let data_len = self.mmap.len();
        for sec in &self.sections {
            if sec.section_size == 0 {
                continue;
            }
            let end = (sec.section_offset as usize)
                .checked_add(sec.section_size as usize)
                .ok_or_else(|| DexError::BadVdexSection {
                    section: section_name_from_kind(sec.section_kind),
                    msg: "offset+size overflows usize".to_string(),
                })?;
            if end > data_len {
                return Err(DexError::BadVdexSection {
                    section: section_name_from_kind(sec.section_kind),
                    msg: format!("section end ({end}) exceeds file size ({data_len})"),
                });
            }
        }
        Ok(())
    }
}

// -- VdexFileContainer ---------------------------------------------------------

/// Owning builder for a memory-mapped VDEX file.
///
/// Mirrors [`DexFileContainer`][crate::file::DexFileContainer]: keeps the
/// `Mmap` alive and exposes an [`open`][VdexFileContainer::open] method that
/// returns a [`MmapVdexFile`] borrowing from it.
pub struct VdexFileContainer {
    mmap: memmap2::Mmap,
}

impl VdexFileContainer {
    /// Memory-map `file` and return a container ready for parsing.
    ///
    /// # Panics
    /// Panics if the OS `mmap` call fails (mirrors `DexFileContainer::new`).
    pub fn new<T: MmapAsRawDesc>(file: T) -> Self {
        // SAFETY: read-only mmap of a file descriptor supplied by the caller.
        Self { mmap: unsafe { memmap2::Mmap::map(file).unwrap() } }
    }

    /// Parse the memory-mapped bytes as a VDEX file.
    pub fn open(&self) -> Result<MmapVdexFile<'_>> {
        VdexFile::from_raw_parts(&self.mmap)
    }

    /// Raw bytes of the mapped file.
    pub fn data(&self) -> &memmap2::Mmap {
        &self.mmap
    }
}

// -- Free helpers --------------------------------------------------------------

/// Round `value` up to the next multiple of `align` (which must be a power of
/// two).
#[inline]
fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

/// Map a raw section-kind `u32` to a human-readable name for error messages.
fn section_name_from_kind(kind: u32) -> &'static str {
    match kind {
        0 => VdexSection::Checksum.name(),
        1 => VdexSection::DexFile.name(),
        2 => VdexSection::VerifierDeps.name(),
        3 => VdexSection::TypeLookupTable.name(),
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers ---------------------------------------------------------------

    /// Build a minimal VDEX file that has no DEX section but carries
    /// `checksums` in the checksum section.
    fn build_vdex(checksums: &[u32]) -> Vec<u8> {
        // Compute section offsets.
        let header_size = std::mem::size_of::<VdexFileHeader>();
        let section_headers_size =
            VDEX_NUM_SECTIONS * std::mem::size_of::<VdexSectionHeader>();
        let checksum_section_offset = header_size + section_headers_size;
        let checksum_section_size = checksums.len() * std::mem::size_of::<u32>();

        // Total file size (no verifier deps, no type lookup table, no dex).
        let file_size = checksum_section_offset + checksum_section_size;

        let mut out = vec![0u8; file_size];

        // Write VdexFileHeader.
        out[0..4].copy_from_slice(VDEX_MAGIC);
        out[4..8].copy_from_slice(VDEX_VERSION);
        out[8..12].copy_from_slice(&(VDEX_NUM_SECTIONS as u32).to_le_bytes());

        // Write section headers.
        let write_section = |buf: &mut Vec<u8>, idx: usize, kind: u32, offset: u32, size: u32| {
            let base = header_size + idx * std::mem::size_of::<VdexSectionHeader>();
            buf[base..base + 4].copy_from_slice(&kind.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&offset.to_le_bytes());
            buf[base + 8..base + 12].copy_from_slice(&size.to_le_bytes());
        };

        // kChecksumSection
        write_section(
            &mut out,
            0,
            VdexSection::Checksum as u32,
            checksum_section_offset as u32,
            checksum_section_size as u32,
        );
        // kDexFileSection - absent
        write_section(&mut out, 1, VdexSection::DexFile as u32, 0, 0);
        // kVerifierDepsSection - absent
        write_section(&mut out, 2, VdexSection::VerifierDeps as u32, 0, 0);
        // kTypeLookupTableSection - absent
        write_section(&mut out, 3, VdexSection::TypeLookupTable as u32, 0, 0);

        // Write checksums.
        for (i, c) in checksums.iter().enumerate() {
            let base = checksum_section_offset + i * 4;
            out[base..base + 4].copy_from_slice(&c.to_le_bytes());
        }

        out
    }

    // -- Tests -----------------------------------------------------------------

    #[test]
    fn valid_header_magic_and_version() {
        let data = build_vdex(&[]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert!(vdex.file_header().is_magic_valid());
        assert!(vdex.file_header().is_version_valid());
    }

    #[test]
    fn num_sections_matches_constant() {
        let data = build_vdex(&[]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert_eq!(vdex.num_sections() as usize, VDEX_NUM_SECTIONS);
    }

    #[test]
    fn num_dex_files_zero_when_no_checksums() {
        let data = build_vdex(&[]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert_eq!(vdex.num_dex_files(), 0);
    }

    #[test]
    fn num_dex_files_matches_checksum_count() {
        let data = build_vdex(&[0xdeadbeef, 0xcafef00d]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert_eq!(vdex.num_dex_files(), 2);
    }

    #[test]
    fn dex_checksum_at_returns_correct_values() {
        let checksums = [0x11111111u32, 0x22222222, 0x33333333];
        let data = build_vdex(&checksums);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        for (i, expected) in checksums.iter().enumerate() {
            assert_eq!(vdex.dex_checksum_at(i as u32).unwrap(), *expected);
        }
    }

    #[test]
    fn dex_checksum_out_of_range_returns_error() {
        let data = build_vdex(&[0xdeadbeef]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert!(matches!(
            vdex.dex_checksum_at(1),
            Err(DexError::VdexDexIndexOutOfRange { index: 1, .. })
        ));
    }

    #[test]
    fn bad_magic_returns_error() {
        let mut data = build_vdex(&[]);
        data[0] = b'w'; // corrupt magic
        assert!(matches!(
            VdexFile::from_raw_parts(&data),
            Err(DexError::BadVdexMagic)
        ));
    }

    #[test]
    fn bad_version_returns_error() {
        let mut data = build_vdex(&[]);
        data[4] = b'0';
        data[5] = b'0';
        data[6] = b'1'; // version "001\0" - not supported
        assert!(matches!(
            VdexFile::from_raw_parts(&data),
            Err(DexError::UnknownVdexVersion { .. })
        ));
    }

    #[test]
    fn truncated_data_returns_error() {
        let data = build_vdex(&[0x12345678]);
        // Too short to hold even the header.  Use a &[u8] container.
        let truncated: &[u8] = &data[..4];
        assert!(matches!(
            VdexFile::from_raw_parts(&truncated),
            Err(DexError::TruncatedVdexFile { .. })
        ));
    }

    #[test]
    fn has_dex_section_false_for_metadata_only_vdex() {
        let data = build_vdex(&[0xdeadbeef]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert!(!vdex.has_dex_section());
    }

    #[test]
    fn verifier_deps_data_empty_when_absent() {
        let data = build_vdex(&[]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert!(vdex.verifier_deps_data().is_empty());
    }

    #[test]
    fn matches_dex_checksums_empty_succeeds() {
        let data = build_vdex(&[]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();
        assert!(vdex.matches_dex_checksums(&[]));
    }

    #[test]
    fn matches_dex_checksums_mismatch_fails() {
        use crate::file::Header;
        let data = build_vdex(&[0xdeadbeef]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();

        // Build a fake Header with a different checksum.
        let mut fake_header = unsafe { std::mem::zeroed::<Header>() };
        // Set the checksum field (offset 8 within Header).
        fake_header.checksum = 0x12345678;
        assert!(!vdex.matches_dex_checksums(&[&fake_header]));
    }

    #[test]
    fn matches_dex_checksums_correct_checksum_succeeds() {
        use crate::file::Header;
        let data = build_vdex(&[0xdeadbeef]);
        let vdex = VdexFile::from_raw_parts(&data).unwrap();

        let mut fake_header = unsafe { std::mem::zeroed::<Header>() };
        fake_header.checksum = 0xdeadbeef;
        assert!(vdex.matches_dex_checksums(&[&fake_header]));
    }
}
