"""Type stubs for the ``dexrs._internal.code.vreg`` sub-module.

Virtual-register operand accessor functions for decoded Dalvik instructions.

The Dalvik instruction formats use lettered operand slots (``A``, ``B``, ``C``,
``H``).  These helpers extract the value of each slot from an
:class:`~dexrs._internal.code.Instruction` according to its format.

Example::

    from dexrs._internal.code import vreg

    # For an "iput v1, v2, field@0003" instruction (format k22c):
    if vreg.has_a(inst):
        dst = vreg.A(inst)   # destination register index
    if vreg.has_b(inst):
        src = vreg.B(inst)   # source register index
"""

from . import (
    Instruction,
    PackedSwitchPayload,
    FillArrayDataPayload,
    SparseSwitchPayload,
)

def has_a(inst: Instruction) -> bool:
    """Return ``True`` if *inst* has an ``A`` operand slot."""
    ...

def has_b(inst: Instruction) -> bool:
    """Return ``True`` if *inst* has a ``B`` operand slot."""
    ...

def has_c(inst: Instruction) -> bool:
    """Return ``True`` if *inst* has a ``C`` operand slot."""
    ...

def has_h(inst: Instruction) -> bool:
    """Return ``True`` if *inst* has an ``H`` (high-order) operand slot."""
    ...

def A(inst: Instruction) -> int:
    """Return the value of the ``A`` operand (typically the destination register).

    :raises ValueError: If *inst* has no ``A`` operand.
    """
    ...

def B(inst: Instruction) -> int:
    """Return the value of the ``B`` operand (typically the first source register or index).

    :raises ValueError: If *inst* has no ``B`` operand.
    """
    ...

def C(inst: Instruction) -> int:
    """Return the value of the ``C`` operand (typically the second source register).

    :raises ValueError: If *inst* has no ``C`` operand.
    """
    ...

def H(inst: Instruction) -> int:
    """Return the value of the ``H`` (high-order / prototype) operand.

    :raises ValueError: If *inst* has no ``H`` operand.
    """
    ...

def has_wide_b(inst: Instruction) -> bool:
    """Return ``True`` if *inst* has a wide (32-bit) ``B`` operand (e.g. format ``k22x``)."""
    ...

def wide_b(inst: Instruction) -> int:
    """Return the wide (32-bit) ``B`` operand value.

    :raises ValueError: If *inst* has no wide ``B`` operand.
    """
    ...

def array_data(inst: Instruction) -> FillArrayDataPayload:
    """Decode and return the ``fill-array-data`` payload referenced by *inst*.

    :raises PyDexError: If *inst* is not a ``fill-array-data`` instruction.
    """
    ...

def packed_switch(inst: Instruction) -> PackedSwitchPayload:
    """Decode and return the ``packed-switch`` payload referenced by *inst*.

    :raises PyDexError: If *inst* is not a ``packed-switch`` instruction.
    """
    ...

def sparse_switch(inst: Instruction) -> SparseSwitchPayload:
    """Decode and return the ``sparse-switch`` payload referenced by *inst*.

    :raises PyDexError: If *inst* is not a ``sparse-switch`` instruction.
    """
    ...
