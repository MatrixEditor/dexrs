"""Type stubs for the ``dexrs._internal.code.verify_flags`` sub-module.

Per-instruction verification flags used by the ART bytecode verifier.
Each constant is a bit in the bitmask returned by
:meth:`~dexrs._internal.code.Instruction.get_verify_flags_of`.
"""

VerifyNothing: int
"""No verification required for any operand."""
VerifyRegA: int
"""Verify that register ``vA`` is valid."""
VerifyRegAWide: int
"""Verify that register ``vA`` is a valid wide (64-bit) register pair."""
VerifyRegB: int
"""Verify that register ``vB`` is valid."""
VerifyRegBField: int
"""Verify that ``vB`` is a valid field reference."""
VerifyRegBMethod: int
"""Verify that ``vB`` is a valid method reference."""
VerifyRegBNewInstance: int
"""Verify that ``vB`` is a valid new-instance type reference."""
VerifyRegBString: int
"""Verify that ``vB`` is a valid string reference."""
VerifyRegBType: int
"""Verify that ``vB`` is a valid type reference."""
VerifyRegBWide: int
"""Verify that ``vB`` is a valid wide register pair."""
VerifyRegC: int
"""Verify that register ``vC`` is valid."""
VerifyRegCField: int
"""Verify that ``vC`` is a valid field reference."""
VerifyRegCNewArray: int
"""Verify that ``vC`` is a valid new-array type reference."""
VerifyRegCType: int
"""Verify that ``vC`` is a valid type reference."""
VerifyRegCWide: int
"""Verify that ``vC`` is a valid wide register pair."""
VerifyArrayData: int
"""Verify the ``fill-array-data`` payload referenced by this instruction."""
VerifyBranchTarget: int
"""Verify that the branch target is within the method body."""
VerifySwitchTargets: int
"""Verify all targets of a ``packed-switch`` or ``sparse-switch`` instruction."""
VerifyVarArg: int
"""Verify the variable-length argument list (up to 5 registers)."""
VerifyVarArgNonZero: int
"""Verify the variable-length argument list is non-empty."""
VerifyVarArgRange: int
"""Verify the register-range argument list."""
VerifyVarArgRangeNonZero: int
"""Verify the register-range argument list is non-empty."""
VerifyError: int
"""Instruction always produces a verification error."""
VerifyRegHPrototype: int
"""Verify that ``vH`` is a valid prototype reference."""
VerifyRegBCallSite: int
"""Verify that ``vB`` is a valid call-site reference."""
VerifyRegBMethodHandle: int
"""Verify that ``vB`` is a valid method-handle reference."""
VerifyRegBPrototype: int
"""Verify that ``vB`` is a valid prototype (proto-ID) reference."""
