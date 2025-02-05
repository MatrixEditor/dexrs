use varint_simd;

#[inline(always)]
pub fn decode_leb128<T: varint_simd::VarIntTarget>(data_in: &[u8]) -> (T, usize) {
    // TODO: convert to result
    match varint_simd::decode::<T>(data_in) {
        Ok((value, size)) => (value, size),
        Err(err) => panic!(
            "Error decoding LEB128: {:?}. Data: {:?}",
            err,
            data_in.as_ptr()
        ),
    }
}

#[inline(always)]
pub fn decode_leb128p1<T: varint_simd::VarIntTarget>(data_in: &[u8]) -> (i32, usize) {
    let (result, size) = decode_leb128::<u32>(data_in);
    ((result - 1) as i32, size)
}

#[inline(always)]
pub fn decode_leb128_off<T: varint_simd::VarIntTarget>(data_in: &[u8], ptr_pos: &mut usize) -> T {
    let (value, size) = decode_leb128(data_in);
    *ptr_pos += size;
    value
}
