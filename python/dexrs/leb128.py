from dexrs._internal import leb128 as rust_leb128


decode_uleb128 = rust_leb128.decode_uleb128
decode_sleb128 = rust_leb128.decode_sleb128
decode_leb128p1 = rust_leb128.decode_leb128p1

__all__ = [
    "decode_uleb128",
    "decode_sleb128",
    "decode_leb128p1",
]