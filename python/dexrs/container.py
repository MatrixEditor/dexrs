"""Thin Python wrapper re-exporting DEX container types.

A *container* is the backing store that holds the raw DEX bytes.  Pass one to
:meth:`~dexrs.DexFile.from_bytes` or :meth:`~dexrs.DexFile.from_file` when
opening a DEX file.

- :class:`InMemoryDexContainer` — wraps an in-memory ``bytes`` buffer.
- :class:`FileDexContainer` — memory-maps a file on disk (zero-copy reads).

Example::

    from dexrs.container import InMemoryDexContainer, FileDexContainer

    # from bytes already in memory
    container = InMemoryDexContainer(raw_bytes)

    # directly from a file path (uses mmap)
    container = FileDexContainer("classes.dex")
    print(container.location)   # "classes.dex"
    print(container.file_size)  # size in bytes
"""
from dexrs._internal import container as rust_container


InMemoryDexContainer = rust_container.InMemoryDexContainer
FileDexContainer = rust_container.FileDexContainer
