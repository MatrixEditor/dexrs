"""Type stubs for the ``dexrs._internal.error`` native extension module."""


class PyDexError(Exception):
    """Exception raised by ``dexrs`` when a Rust-level operation fails.

    Covers malformed DEX images, out-of-bounds indices, checksum mismatches,
    I/O errors, and other parse failures that are not plain :exc:`IOError`.

    Example::

        from dexrs.error import PyDexError

        try:
            dex = DexFile.from_bytes(InMemoryDexContainer(b"bad"))
        except PyDexError as exc:
            print(f"DEX error: {exc}")
    """

    def __init__(self, message: str) -> None: ...
