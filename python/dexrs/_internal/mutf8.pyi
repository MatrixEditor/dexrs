"""Type stubs for the ``dexrs._internal.mutf8`` native extension module.

DEX files use Modified UTF-8 (MUTF-8), which differs from standard UTF-8 in
two ways:

1. The null character U+0000 is encoded as the two-byte overlong sequence
   ``0xC0 0x80`` rather than a single ``0x00`` byte.
2. Supplementary code points (U+10000–U+10FFFF) are encoded as a pair of
   UTF-16 surrogates in CESU-8 style rather than a single 4-byte sequence.

See: https://source.android.com/docs/core/runtime/dex-format#mutf-8
"""


def mutf8_to_str(utf8_data_in: bytes) -> str:
    """Decode strict MUTF-8 bytes to a Python :class:`str`.

    :param utf8_data_in: Raw MUTF-8 encoded bytes.
    :returns: Decoded Python string.
    :raises PyDexError: If the byte sequence is not valid MUTF-8.

    Example::

        mutf8_to_str(bytes([0xC0, 0x80]))  # "\\x00"
    """
    ...

def str_to_mutf8(str_data_in: str) -> bytes:
    """Encode a Python :class:`str` to strict MUTF-8 bytes.

    :param str_data_in: Python string to encode.
    :returns: MUTF-8 encoded bytes.
    :raises PyDexError: If the string contains characters that cannot be encoded.

    Example::

        str_to_mutf8("Hello")  # b"Hello"
    """
    ...

def mutf8_to_str_lossy(utf8_data_in: bytes) -> str:
    """Decode MUTF-8 bytes to a Python :class:`str`, replacing invalid sequences with U+FFFD.

    :param utf8_data_in: Raw bytes, possibly containing invalid MUTF-8 sequences.
    :returns: Decoded Python string with replacement characters for bad bytes.
    """
    ...

def str_to_mutf8_lossy(str_data_in: str) -> bytes:
    """Encode a Python :class:`str` to MUTF-8 bytes, skipping unencodable code points.

    :param str_data_in: Python string to encode.
    :returns: MUTF-8 encoded bytes with unencodable characters silently dropped.
    """
    ...
