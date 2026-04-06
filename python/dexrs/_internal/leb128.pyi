"""Type stubs for the ``dexrs._internal.leb128`` native extension module.

LEB128 (Little Endian Base 128) is the variable-length integer encoding used
throughout the DEX format for sizes, offsets, and access flags.

See also: https://source.android.com/docs/core/runtime/dex-format#leb128
"""


def decode_uleb128(data: bytes) -> int:
    """Decode an unsigned LEB128 integer from the start of *data*.

    :param data: Bytes starting with a valid ULEB128-encoded integer.
    :returns: The decoded non-negative integer value.
    :raises PyDexError: If *data* is empty or the encoding is malformed.

    Example::

        decode_uleb128(bytes([0x8E, 0x02]))  # 270
    """
    ...

def decode_sleb128(data: bytes) -> int:
    """Decode a signed LEB128 integer from the start of *data*.

    :param data: Bytes starting with a valid SLEB128-encoded integer.
    :returns: The decoded signed integer value.
    :raises PyDexError: If *data* is empty or the encoding is malformed.

    Example::

        decode_sleb128(bytes([0x9B, 0x7F]))  # -101
    """
    ...

def decode_leb128p1(data: bytes) -> int:
    """Decode a ``ULEB128p1``-encoded integer from the start of *data*.

    The value is stored as ``n + 1``, so the encoded value ``0`` represents
    ``-1`` (the "no-index" sentinel used in DEX).

    :param data: Bytes starting with a valid ULEB128p1-encoded integer.
    :returns: The decoded value (may be ``-1`` for the no-index sentinel).
    :raises PyDexError: If *data* is empty or the encoding is malformed.

    Example::

        decode_leb128p1(bytes([0x00]))  # -1  (no-index sentinel)
        decode_leb128p1(bytes([0x01]))  # 0
    """
    ...
