"""Thin Python wrapper re-exporting LEB128 varint decoder functions.

`Little Endian Base 128 (LEB128)`_ is a variable-length integer encoding used
extensively in the DEX format for sizes, offsets, and access flags.

.. _Little Endian Base 128 (LEB128):
   https://source.android.com/docs/core/runtime/dex-format#leb128

Functions
---------
- :func:`decode_uleb128` - unsigned LEB128 -> non-negative :class:`int`.
- :func:`decode_sleb128` - signed LEB128 -> signed :class:`int`.
- :func:`decode_leb128p1` - ``ULEB128p1`` encoding (value stored as ``n+1``),
  where ``-1`` encodes the special *no-index* sentinel.

Example::

    from dexrs.leb128 import decode_uleb128, decode_sleb128, decode_leb128p1

    decode_uleb128(bytes([0x8E, 0x02]))  # 270
    decode_sleb128(bytes([0x9B, 0x7F]))  # -101
    decode_leb128p1(bytes([0x00]))       # -1  (no-index sentinel)
    decode_leb128p1(bytes([0x01]))       # 0
"""
from dexrs._internal import leb128 as rust_leb128


decode_uleb128 = rust_leb128.decode_uleb128
decode_sleb128 = rust_leb128.decode_sleb128
decode_leb128p1 = rust_leb128.decode_leb128p1

__all__ = [
    "decode_uleb128",
    "decode_sleb128",
    "decode_leb128p1",
]