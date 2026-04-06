"""Thin Python wrapper re-exporting the Rust ``TypeLookupTable`` class.

:class:`TypeLookupTable` provides O(1) class-descriptor lookups over all
classes defined in a :class:`~dexrs.DexFile`.  Build one via
:meth:`~dexrs.DexFile.build_type_lookup_table`.

Example::

    from dexrs import DexFile, InMemoryDexContainer

    with open("classes.dex", "rb") as f:
        dex = DexFile.from_bytes(InMemoryDexContainer(f.read()))

    tlt = dex.build_type_lookup_table()
    idx = tlt.lookup("Ljava/lang/String;")
    if idx is not None:
        print(f"String class_def index: {idx}")
"""
from dexrs._internal import type_lookup_table as _rust_tlt

TypeLookupTable = _rust_tlt.TypeLookupTable

__all__ = ["TypeLookupTable"]
