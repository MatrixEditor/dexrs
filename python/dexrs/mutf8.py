"""Thin Python wrapper re-exporting MUTF-8 ↔ Python :class:`str` converters.

DEX files use a variant of UTF-8 called `Modified UTF-8 (MUTF-8)`_ which
differs from standard UTF-8 in two ways:

1. The null character ``U+0000`` is encoded as the two-byte sequence
   ``0xC0 0x80`` (overlong form) rather than a single ``0x00`` byte.
2. Supplementary characters (U+10000…U+10FFFF) are encoded as two surrogate
   pairs in CESU-8 style rather than a single 4-byte sequence.

.. _Modified UTF-8 (MUTF-8):
   https://source.android.com/docs/core/runtime/dex-format#mutf-8

Functions
---------
- :func:`mutf8_to_str` - strict MUTF-8 bytes -> Python :class:`str`.
- :func:`mutf8_to_str_lossy` - lenient variant; replaces invalid sequences
  with the Unicode replacement character ``U+FFFD``.
- :func:`str_to_mutf8` - Python :class:`str` -> MUTF-8 bytes (strict).
- :func:`str_to_mutf8_lossy` - lenient variant; skips unencodable code points.

Example::

    from dexrs.mutf8 import mutf8_to_str, str_to_mutf8

    raw = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])  # "Hello" in MUTF-8
    assert mutf8_to_str(raw) == "Hello"
    assert str_to_mutf8("Hello") == raw

    # Null character encoded as overlong 0xC0 0x80
    null_encoded = bytes([0xC0, 0x80])
    assert mutf8_to_str(null_encoded) == "\\x00"
"""
from dexrs._internal import mutf8 as rust_mutf8


mutf8_to_str = rust_mutf8.mutf8_to_str
mutf8_to_str_lossy = rust_mutf8.mutf8_to_str_lossy
str_to_mutf8 = rust_mutf8.str_to_mutf8
str_to_mutf8_lossy = rust_mutf8.str_to_mutf8_lossy