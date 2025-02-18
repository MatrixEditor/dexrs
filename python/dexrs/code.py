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
