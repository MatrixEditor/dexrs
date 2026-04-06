"""Type stubs for the ``dexrs._internal.code.code_flags`` sub-module.

These flags describe additional per-instruction properties used by the
ART verifier and optimiser that are not captured by the basic control-flow
flags in :mod:`~dexrs._internal.code.flags`.
"""

Complex: int
"""Instruction has complex behaviour that requires special verifier treatment."""
Custom: int
"""Instruction is custom (``invoke-custom`` / ``invoke-custom/range``)."""
