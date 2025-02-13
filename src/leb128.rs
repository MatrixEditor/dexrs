use varint_simd;

use crate::Result;

#[inline(always)]
pub fn decode_leb128<T: varint_simd::VarIntTarget>(data_in: &[u8]) -> Result<(T, usize)> {
    // TODO: convert to result
    Ok(varint_simd::decode::<T>(data_in)?)
}

#[inline(always)]
pub fn decode_leb128p1(data_in: &[u8]) -> Result<(i32, usize)> {
    let (result, size) = decode_leb128::<u32>(data_in)?;
    Ok((result as i32 - 1, size))
}

#[inline(always)]
pub fn decode_leb128_adv<T: varint_simd::VarIntTarget>(
    data_in: &[u8],
    ptr_pos: &mut usize,
) -> Result<T> {
    let (value, size) = decode_leb128(data_in)?;
    *ptr_pos += size;
    Ok(value)
}

#[inline(always)]
pub fn decode_leb128_off<T: varint_simd::VarIntTarget>(
    data_in: &[u8],
    ptr_pos: &mut usize,
) -> Result<T> {
    let (value, size) = decode_leb128(&data_in[*ptr_pos..])?;
    *ptr_pos += size;
    Ok(value)
}

#[inline(always)]
pub fn decode_leb128p1_off(data_in: &[u8], ptr_pos: &mut usize) -> Result<i32> {
    let (value, size) = decode_leb128p1(&data_in[*ptr_pos..])?;
    *ptr_pos += size;
    Ok(value)
}
