"""Thin Python wrapper re-exporting :class:`DexFile` and :class:`VerifyPreset`.

:class:`DexFile` is the central type of the ``dexrs`` library.  It holds a
parsed DEX image and exposes read-only accessors for every section described
by the `AOSP DEX format specification`_.

.. _AOSP DEX format specification:
   https://source.android.com/docs/core/runtime/dex-format

Example::

    from dexrs import DexFile, FileDexContainer, VerifyPreset

    dex = DexFile.from_file(FileDexContainer("classes.dex"), VerifyPreset.ALL)
    header = dex.get_header()
    print(f"DEX version {header.version_int}, {dex.num_class_defs()} classes")

    for i in range(dex.num_class_defs()):
        cls = dex.get_class_def(i)
        print(dex.get_class_desc(cls))
"""
from dexrs._internal import file as rust_file


DexFile = rust_file.DexFile
VerifyPreset = rust_file.VerifyPreset

__all__ = ["DexFile", "VerifyPreset"]
