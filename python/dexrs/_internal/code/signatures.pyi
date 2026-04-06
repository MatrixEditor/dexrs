"""Type stubs for the ``dexrs._internal.code.signatures`` sub-module.

Magic 16-bit values that identify pseudo-instruction payloads embedded in a
Dalvik method body.  These appear as the first code unit of a payload block
and are used to distinguish payload types during decoding.
"""

ArrayDataSignature: int
"""First code unit of a ``fill-array-data`` payload block (``0x0300``)."""
SparseSwitchSignature: int
"""First code unit of a ``sparse-switch`` payload block (``0x0200``)."""
PackedSwitchSignature: int
"""First code unit of a ``packed-switch`` payload block (``0x0100``)."""
