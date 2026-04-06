"""Type stubs for the ``dexrs._internal.code.flags`` sub-module.

Control-flow flags for Dalvik instructions.  These bitmask constants are
returned by :meth:`~dexrs._internal.code.Instruction.get_flags_of` and can be
combined with bitwise OR.
"""

Branch: int
"""Instruction is a conditional or unconditional branch."""
Continue: int
"""Execution may fall through to the next instruction."""
Switch: int
"""Instruction is a switch (``packed-switch`` or ``sparse-switch``)."""
Throw: int
"""Instruction may throw an exception."""
Return: int
"""Instruction is a return (``return``, ``return-void``, etc.)."""
Invoke: int
"""Instruction is a method invocation."""
Unconditional: int
"""Branch is unconditional (no fall-through path)."""
Experimental: int
"""Instruction is experimental / not part of the stable ART bytecode set."""
