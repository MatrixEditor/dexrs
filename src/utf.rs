
// TODO: these functions are highly unsafe and does not stand any chance against fuzzing

pub fn mutf8_to_str(utf8_data_in: &[u8]) -> crate::Result<String> {
    let utf16_data = mutf8_to_utf16(utf8_data_in);
    Ok(String::from_utf16(&utf16_data)?)
}

pub fn mutf8_to_str_lossy(utf8_data_in: &[u8]) -> String {
    let utf16_data = mutf8_to_utf16(utf8_data_in);
    String::from_utf16_lossy(&utf16_data)
}

pub fn str_to_mutf8(str_data_in: &str) -> Vec<u8> {
    let utf16_data_in: Vec<u16> = str_data_in.encode_utf16().collect();
    utf16_to_mutf8(&utf16_data_in, &Options::new())
}

pub fn str_to_mutf8_lossy(str_data_in: &str) -> Vec<u8> {
    let utf16_data_in: Vec<u16> = str_data_in.encode_utf16().collect();
    let options = Options::new().replace_bad_surrogates(true);
    utf16_to_mutf8(&utf16_data_in, &options)
}

#[inline]
fn utf16_from_utf8(utf8_data_in: &[u8], offset: &mut usize) -> u32 {
    let one = utf8_data_in[*offset];
    *offset += 1;
    if one & 0x80 == 0 {
        return one as u32;
    }

    let two = utf8_data_in[*offset];
    *offset += 1;
    if one & 0x20 == 0 {
        return ((one & 0x1f) as u32) << 6 | (two & 0x3F) as u32;
    }

    let three = utf8_data_in[*offset];
    *offset += 1;
    if one & 0x10 == 0 {
        return ((one & 0x0f) as u32) << 12 | ((two & 0x3F) as u32) << 6 | (three & 0x3F) as u32;
    }

    let four = utf8_data_in[*offset];
    *offset += 1;
    let code_point = ((one & 0x0F) as u32) << 18
        | ((two & 0x3F) as u32) << 12
        | ((three & 0x3F) as u32) << 6
        | (four & 0x3F) as u32;

    let mut surrogate_pair: u32 = 0x00;
    surrogate_pair |= ((code_point >> 10) + 0xd7c0) & 0xFFFF;
    surrogate_pair |= ((code_point & 0x03FF) + 0xdc80) << 16;
    return surrogate_pair;
}

#[inline(always)]
fn trailing_utf16_char(maybe_pair: u32) -> u16 {
    (maybe_pair >> 16) as u16
}

#[inline(always)]
fn leading_utf16_char(maybe_pair: u32) -> u16 {
    (maybe_pair & 0x0000FFFFF) as u16
}

#[inline(always)]
fn is_lead(ch: u16) -> bool {
    ch & 0xFC00 == 0xd800
}

#[inline(always)]
fn is_trail(ch: u16) -> bool {
    ch & 0xFC00 == 0xDC00
}

#[inline(always)]
fn is_surrogate(ch: u16) -> bool {
    ch & 0xF800 == 0xD800
}

#[inline(always)]
fn is_surrogate_lead(ch: u16) -> bool {
    ch & 0x0400 == 0x00
}

#[inline(always)]
fn get_supplementary(lead: u16, trail: u16) -> u32 {
    const OFFSET: u32 = (0xd800 << 10) + 0xdc00 - 0x10000;
    ((lead as u32) << 10) + (trail as u32) - OFFSET
}

pub fn mutf8_len(utf8_data_in: &[u8], utf8_in_len: usize) -> usize {
    let mut len = 0;
    let mut in_idx = 0;
    while in_idx < utf8_in_len {
        let ic = utf8_data_in[in_idx];
        in_idx += 1;
        len += 1;
        if ic & 0x80 == 0 {
            continue; // one byze encoding
        }

        in_idx += 1;
        if ic & 0x20 == 0 {
            // two byze encoding
            continue;
        }

        in_idx += 1;
        if ic & 0x10 == 0 {
            continue;
        }

        // Four-byte encoding: needs to be converted into a surrogate
        // pair.
        in_idx += 1;
        len += 1;
    }
    len
}

fn mutf8_to_utf16(utf8_data_in: &[u8]) -> Vec<u16> {
    if utf8_data_in.is_empty() {
        return Vec::new();
    }

    let utf8_in_len = utf8_data_in.len() - 1;
    let out_chars = mutf8_len(utf8_data_in, utf8_in_len);
    convert_mutf8_to_utf16(utf8_data_in, utf8_in_len, out_chars)
}

fn convert_mutf8_to_utf16(
    utf8_data_in: &[u8],
    utf8_in_len: usize,
    out_chars: usize,
) -> Vec<u16> {
    if utf8_data_in.len() == out_chars {
        // common case where all chars are ASCII
        return utf8_data_in.iter().map(|i| *i as u16).collect();
    }

    let mut utf16_data_out: Vec<u16> = Vec::with_capacity(out_chars);
    let mut in_idx = 0x00;
    while in_idx < utf8_in_len {
        let ch = utf16_from_utf8(utf8_data_in, &mut in_idx);
        let leading = leading_utf16_char(ch);
        let trailing = trailing_utf16_char(ch);

        utf16_data_out.push(leading);
        if trailing != 0 {
            utf16_data_out.push(trailing);
        }
    }
    utf16_data_out
}

fn utf16_to_mutf8(utf16_in: &[u16], options: &Options) -> Vec<u8> {
    let mut mutf8_len = 0;
    convert_utf16_to_mutf8(utf16_in, options, |_| mutf8_len += 1);

    let mut mutf8_out;
    if mutf8_len == utf16_in.len() {
        // only ascii chars
        mutf8_out = utf16_in.iter().map(|ch| *ch as u8).collect();
    } else {
        mutf8_out = vec![0x00; mutf8_len + 1];
        convert_utf16_to_mutf8(utf16_in, options, |ch| mutf8_out.push(ch));
    }

    // append trailing null
    mutf8_out.push(0x00);
    mutf8_out

}

pub struct Options {
    pub short_zero: bool,
    pub replace_bad_surrogates: bool,
}

impl Options {
    pub fn new() -> Options {
        Options {
            short_zero: false,
            replace_bad_surrogates: false,
        }
    }

    pub fn use_short_zero(mut self, enable: bool) -> Self {
        self.short_zero = enable;
        self
    }

    pub fn replace_bad_surrogates(mut self, enable: bool) -> Self {
        self.replace_bad_surrogates = enable;
        self
    }
}

fn convert_utf16_to_mutf8<Append>(utf16_in: &[u16], options: &Options, mut append: Append)
where
    Append: FnMut(u8) -> (),
{
    let mut in_idx = 0;
    while in_idx < utf16_in.len() {
        let ch = utf16_in[in_idx];
        if ch < 0x80 && (options.short_zero || ch != 0) {
            append(ch as u8);
        } else if ch < 0x800 {
            append(((ch >> 6) | 0xC0) as u8);
            append(((ch & 0x3F) | 0x80) as u8);
        } else if is_surrogate(ch)
            || (is_lead(ch) && in_idx + 1 != utf16_in.len() && is_trail(utf16_in[in_idx + 1]))
        {
            if options.replace_bad_surrogates
                && (!is_surrogate_lead(ch)
                    && in_idx + 1 != utf16_in.len()
                    && !is_trail(utf16_in[in_idx + 1]))
            {
                append('?' as u8);
            } else {
                let code_point = get_supplementary(ch, utf16_in[in_idx + 1]);
                in_idx += 1;
                append(((code_point >> 18) | 0xf0) as u8);
                append((((code_point >> 12) & 0x3f) | 0x80) as u8);
                append((((code_point >> 6) & 0x3f) | 0x80) as u8);
                append(((code_point & 0x3f) | 0x80) as u8);
            }
        } else {
            append(((ch >> 12) | 0xE0) as u8);
            append((((ch >> 6) & 0x3F) | 0x80) as u8);
            append(((ch & 0x3F) | 0x80) as u8);
        }

        in_idx += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_to_mutf8() {
        let data = "foobar";
        assert_eq!(str_to_mutf8(data), b"foobar\0");
    }

    #[test]
    fn test_mutf8_to_str() {
        let data = &[102, 111, 111, 98, 97, 114, 0];
        assert_eq!(mutf8_to_str_lossy(data), "foobar".to_string());
    }
}
