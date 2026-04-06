"""Thin Python wrapper re-exporting DEX instruction and code-item types.

This module re-exports the full ``code`` sub-package from the native
extension, which provides:

- :class:`CodeItemAccessor` - iterate over instructions in a method body.
- :class:`Instruction` - a single decoded Dalvik instruction.
- :class:`Code` - opcode enum (``NOP``, ``MOVE``, ``INVOKE_VIRTUAL``, …).
- :class:`Format` - instruction format enum (``k10x``, ``k35c``, …).
- :class:`IndexType` - index-operand type enum.
- :data:`code_flags`, :data:`verify_flags`, :data:`flags` - flag constant modules.
- :data:`signatures` - well-known pseudo-instruction signatures.
- :data:`vreg` - virtual-register operand accessor functions.

Example::

    from dexrs import DexFile, InMemoryDexContainer
    from dexrs.code import Code

    with open("classes.dex", "rb") as f:
        dex = DexFile.from_bytes(InMemoryDexContainer(f.read()))

    cls = dex.get_class_def(0)
    accessor = dex.get_class_accessor(cls)
    if accessor is not None:
        for method in accessor.get_direct_methods():
            ca = dex.get_code_item_accessor(method.code_offset)
            for inst in ca.insns():
                if inst.opcode == Code.RETURN_VOID:
                    print("Found RETURN_VOID at", inst)
"""
from dexrs._internal import code as rust_code

CodeItemAccessor = rust_code.CodeItemAccessor
Code = rust_code.Code
Instruction = rust_code.Instruction
Format = rust_code.Format
IndexType = rust_code.IndexType

# sub-modules will be represented as variables here
code_flags = rust_code.code_flags
verify_flags = rust_code.verify_flags
flags = rust_code.flags
signatures = rust_code.signatures
vreg = rust_code.vreg

__all__ = [
    "CodeItemAccessor",
    "Code",
    "Instruction",
    "Format",
    "IndexType",
    "code_flags",
    "verify_flags",
    "flags",
    "signatures",
]
