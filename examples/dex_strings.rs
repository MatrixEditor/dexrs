#![allow(unused)]

use dexrs::{file::DexFile, utf, Result};

fn dex_strings(dex: &DexFile<'_>) -> Result<()> {
    // strings can be retrieved in various ways
    let string_id = dex.get_string_id(0)?;
    assert!(dex.string_id_idx(string_id)? == 0);

    // name can be retrieved in various ways:
    //
    // 1. modified utf8 -> utf16 with checks
    let name = dex.get_utf16_str(string_id)?;
    //
    // 2. modified utf8 -> utf16 lossy
    let name = dex.get_utf16_str_lossy(string_id)?;
    //
    // 3. modified utf8 -> utf8 unsafe (but fast)
    let name = unsafe { dex.fast_get_utf8_str(string_id)? };

    // there's also a function to query the raw string
    // data without conversion
    let (utf16_len, data) = dex.get_string_data(string_id)?;

    // all of the operations above can be done with the
    // index directly
    let name = dex.get_utf16_str_lossy_at(0)?;

    Ok(())
}

pub fn mutf8_strings() -> Result<()> {
    // the conversion of MUTF8 strings is not stable yet (fails fuzzing)

    // The only contraint on input data is that it must be null-terminated
    let data = b"Hello, World!\0";
    // conversion from MUTF8 to UTF16 is provided in two ways:
    //
    // 1. modified utf8 -> utf16 with checks
    let name = utf::mutf8_to_str(data)?;
    //
    // 2. modified utf8 -> utf16 lossy
    let name = utf::mutf8_to_str_lossy(data);

    // conversion back is also supported
    let mutf8_data = utf::str_to_mutf8(&name);
    assert_eq!(data.to_vec(), mutf8_data);
    Ok(())
}

fn main() {
    // ...
}
