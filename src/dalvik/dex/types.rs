use binrw::meta::ReadEndian;
use binrw::{BinRead, BinWrite, Endian};
use bitflags::bitflags;
use leb128;
use std::{io, result};

/// 8bit signed int
pub type Byte = i8;

/// 8bit unsigned int
pub type UByte = u8;

/// 16bit signed int
pub type Short = i16;

/// 16bit unsigned int
pub type UShort = u16;

/// 32bit signed int
pub type Int = i32;

/// 32bit unsigned int
pub type UInt = u32;

/// 64bit signed int
pub type Long = i64;

/// 64bit unsigned int
pub type ULong = u64;

/// SHA-1 signature type alias
pub type SHA1Signature = [UByte; 20];

bitflags! {
    #[derive(Debug)]
    pub struct AccessFlags: UInt {
        const PUBLIC = 0x0001;
        const PRIVATE = 0x0002;
        const PROTECTED = 0x0004;
        const STATIC = 0x0008;
        const FINAL = 0x0010;

        /// associated lock automatically acquired around call
        /// to this method.
        ///
        /// @note Only valid for methods.
        const SYNCHRONIZED = 0x0020;

        /// special access rules to help with thread safety
        ///
        /// @note Only valid for fields.
        const VOLATILE = 0x0040;

        /// bridge method, added automatically by compiler as a
        /// type-safe bridge
        ///
        /// @note Only valid for methods.
        const BRIDGE = 0x0040;

        /// not to be saved by default serialization
        ///
        /// @note Only valid for fields.
        const TRANSIENT = 0x0080;

        /// last argument should be treated as a "rest" argument by compiler
        ///
        /// @note Only valid for methods.
        const VARARGS = 0x0080;

        /// native method
        ///
        /// @note Only valid for methods.
        const NATIVE = 0x0100;

        /// multiply-implementable abstract class
        ///
        /// @note Only valid for classes.
        const INTERFACE = 0x0200;

        /// @note Only valid for classes and methods.
        const ABSTRACT = 0x0400;

        /// @note Only valid for fields.
        const STRICT = 0x0800;
        const SYNTHETIC = 0x1000;

        /// @note Only valid for classes.
        const ANNOTATION = 0x2000;

        /// @note Only valid for classes and fields.
        const ENUM = 0x4000;

        /// mandated, the parameter is synthetic but also implied by the language specification
        const MANDATED = 0x8000; // only fields

        /// @note Only valid for methods.
        const CONSTRUCTOR = 0x10000;

        /// @note Only valid for methods.
        const DECLARED_SYNCHRONIZED = 0x20000;
    }
}

/// signed LEB128, variable-length:
///
/// Borrowed from the DWARF3 specification, Section 7.6, "Variable Length Data",
/// Android only uses it to encode 32bit entities. Therefore, the type here will
/// be i32.
#[derive(Debug)]
pub struct SLeb128(pub i32);

impl BinRead for SLeb128 {
    type Args<'a> = ();

    /// Read signed LEB128, variable-length into an i32
    fn read_options<R: io::Read + io::Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<Self, binrw::Error> {
        // simply delegate to leb128
        return match leb128::read::signed(reader) {
            Ok(x) => Ok(Self(x as i32)),
            Err(e) => Err(binrw::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e,
            ))),
        };
    }
}

impl ReadEndian for SLeb128 {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::None;
}

impl BinWrite for SLeb128 {
    type Args<'a> = ();

    /// Write signed LEB128, variable-length into an i32
    fn write_options<W: io::Write>(
        &self,
        writer: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<(), binrw::Error> {
        // simply delegate to leb128
        return match leb128::write::signed(writer, self.0 as i64) {
            Ok(_) => Ok(()),
            Err(e) => Err(binrw::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e,
            ))),
        };
    }
}

/// unsigned LEB128, variable-length
#[derive(Debug)]
pub struct ULeb128(pub u32);

impl ReadEndian for ULeb128 {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::None;
}

impl BinRead for ULeb128 {
    type Args<'a> = ();

    /// Read unsigned LEB128, variable-length into an u32
    fn read_options<R: io::Read + io::Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<Self, binrw::Error> {
        // simply delegate to leb128
        return match leb128::read::unsigned(reader) {
            Ok(x) => Ok(Self(x as u32)),
            Err(e) => Err(binrw::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e,
            ))),
        };
    }
}

impl BinWrite for ULeb128 {
    type Args<'a> = ();

    /// Write unsigned LEB128, variable-length into an u32
    fn write_options<W: io::Write>(
        &self,
        writer: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<(), binrw::Error> {
        // simply delegate to leb128
        return match leb128::write::unsigned(writer, self.0 as u64) {
            Ok(_) => Ok(()),
            Err(e) => Err(binrw::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e,
            ))),
        };
    }
}

/// unsigned LEB128 plus 1, variable-length
///
/// This is used for LEB128p1 in Android, which is used to encode a number
/// using uleb128 + 1.
#[derive(Debug)]
pub enum ULeb128p1 {
    Pos(u32),
    Neg,
}

impl ReadEndian for ULeb128p1 {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::None;
}

impl BinRead for ULeb128p1 {
    type Args<'a> = ();

    /// Read unsigned LEB128p1, variable-length into an i32
    fn read_options<R: io::Read + io::Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<Self, binrw::Error> {
        // simply delegate to leb128
        return match leb128::read::unsigned(reader) {
            Ok(x) => match x {
                0 => Ok(Self::Neg),
                _ => Ok(Self::Pos((x - 1) as u32)),
            },
            Err(e) => Err(binrw::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e,
            ))),
        };
    }
}



impl BinWrite for ULeb128p1 {
    type Args<'a> = ();

    /// Write unsigned LEB128p1, variable-length into an i32
    fn write_options<W: io::Write>(
        &self,
        writer: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> result::Result<(), binrw::Error> {
        match self {
            ULeb128p1::Pos(x) => match leb128::write::unsigned(writer, *x as u64 + 1) {
                Ok(_) => Ok(()),
                Err(e) => Err(binrw::Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e,
                ))),
            },
            ULeb128p1::Neg => match leb128::write::unsigned(writer, 0) {
                Ok(_) => Ok(()),
                Err(e) => Err(binrw::Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e,
                ))),
            },
        }
    }
}



pub mod mutf8 {
    use std::io::{self, Read, Seek};


    /// # Modified UTF-8 encoding
    ///
    /// Taken from Android docs: As a concession to easier legacy support, the `.dex`
    /// format encodes its string data in a de facto standard modified UTF-8 form,
    /// hereafter referred to as MUTF-8. This form is identical to standard UTF-8
    /// with a few modifications:
    ///
    /// - Only the one-, two-, and three-byte encodings are used.
    /// - Code points in the range `U+10000 ... U+10ffff` are encoded as a surrogate
    ///   pair, each of which is represented as a three-byte encoded value.
    /// - The code point U+0000 is encoded in two-byte form.
    /// - A plain null byte (value 0) indicates the end of a string, as is the standard
    ///   C language interpretation.
    ///
    /// The first two items above can be summarized as: MUTF-8 is an encoding format for
    /// UTF-16, instead of being a more direct encoding format for Unicode characters.
    pub fn read<R>(reader: &mut R) -> io::Result<String>
    where
        R: Read + Seek,
    {
        let len = match leb128::read::unsigned(reader) {
            Ok(x) => x as usize,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        };
        let mut buf = [0];
        let mut out: Vec<u16> = Vec::with_capacity(len);
        let mut k: usize = len;
        while k > 0 {
            reader.read(&mut buf)?;
            let byte = buf[0];
            // (4) A plain null byte (value 0) indicates the end of a string, as is the
            // standard C language interpretation.
            if byte == 0 {
                break;
            }

            let out_val: u16 = match byte >> 4 {
                0x00..=0x07 => {
                    // 0xxx xxxx
                    byte as u16
                }
                0x0C | 0x0D => {
                    // 110x xxxx
                    reader.read(&mut buf)?;
                    let next = buf[0];
                    if (next & 0xC0) != 0x80 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Bad second character!",
                        ));
                    }
                    (((byte & 0x1F) << 6) | (next & 0x3F)) as u16
                }
                0x0E => {
                    // 1110 xxxx
                    reader.read(&mut buf)?;
                    let b = buf[0];
                    if (b & 0xC0) != 0x80 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Bad second character!",
                        ));
                    }
                    reader.read(&mut buf)?;
                    let c = buf[0];
                    if (c & 0xC0) != 0x80 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Bad third character!",
                        ));
                    }
                    // REVISIT: rust can't handle surrogates
                    (((byte as u16) & 0x0F) << 12) | (b as u16 & 0x3F) << 6 | (c as u16 & 0x3F)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bad character: {:#x}", byte),
                    ));
                }
            };
            out.push(out_val);
            k -= 1;
        }
        return Ok(String::from_utf16_lossy(out.as_ref()));
    }
}
