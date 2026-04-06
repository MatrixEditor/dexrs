"""Thin Python wrapper re-exporting :exc:`PyDexError`.

:exc:`PyDexError` is the exception type raised by all ``dexrs`` operations
that fail at the Rust level (e.g. malformed DEX, out-of-bounds index, I/O
errors that are not plain :exc:`IOError`).

Example::

    from dexrs import DexFile, InMemoryDexContainer
    from dexrs.error import PyDexError

    try:
        dex = DexFile.from_bytes(InMemoryDexContainer(b"not a dex"))
    except PyDexError as exc:
        print(f"Parse failed: {exc}")
"""
from dexrs._internal import error as rust_error

PyDexError = rust_error.PyDexError

__all__ = ["PyDexError"]
