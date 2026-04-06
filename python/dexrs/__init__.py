"""dexrs - Python bindings for the Rust DEX file parsing library.

This package exposes the full public API of the ``dexrs`` Rust crate via
PyO3-generated native extensions, re-exported under clean Python names.

Quickstart::

    from dexrs import DexFile, InMemoryDexContainer, VerifyPreset

    with open("classes.dex", "rb") as f:
        container = InMemoryDexContainer(f.read())

    dex = DexFile.from_bytes(container, VerifyPreset.ALL)

    for i in range(dex.num_class_defs()):
        cls = dex.get_class_def(i)
        print(dex.get_class_desc(cls))

Submodules
----------
- :mod:`dexrs.file` - :class:`DexFile` and :class:`VerifyPreset`
- :mod:`dexrs.container` - :class:`InMemoryDexContainer`, :class:`FileDexContainer`
- :mod:`dexrs.editor` - :class:`DexEditor` for mutation
- :mod:`dexrs.code` - Instructions, opcodes, and operand helpers
- :mod:`dexrs.error` - :exc:`PyDexError`
- :mod:`dexrs.leb128` - LEB128 varint decoders
- :mod:`dexrs.mutf8` - MUTF-8 ↔ str conversion
- :mod:`dexrs.primitive` - :class:`PrimitiveType` enum
- :mod:`dexrs.type_lookup_table` - :class:`TypeLookupTable`
"""
# some shortcuts
from .file import DexFile, VerifyPreset
from .container import InMemoryDexContainer, FileDexContainer
from .error import PyDexError
from .editor import DexEditor
from .builder import DexIrBuilder, IrClassDef, IrMethodDef, CodeBuilder
from .type_lookup_table import TypeLookupTable
from .primitive import PrimitiveType

__all__ = [
    "DexFile",
    "VerifyPreset",
    "InMemoryDexContainer",
    "FileDexContainer",
    "PyDexError",
    "DexEditor",
    "DexIrBuilder",
    "IrClassDef",
    "IrMethodDef",
    "CodeBuilder",
    "TypeLookupTable",
    "PrimitiveType",
]