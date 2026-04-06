"""Type stubs for the ``dexrs._internal.code`` native extension module.

Provides types for iterating and inspecting Dalvik bytecode instructions.

- :class:`CodeItemAccessor` — iterate over instructions in a method body.
- :class:`Instruction` — a single decoded Dalvik instruction.
- :class:`Code` — opcode enum (``NOP``, ``MOVE``, ``INVOKE_VIRTUAL``, …).
- :class:`Format` — instruction format enum (``k10x``, ``k35c``, …).
- :class:`IndexType` — type of the index operand in an instruction.
- :class:`FillArrayDataPayload` — payload for ``fill-array-data``.
- :class:`SparseSwitchPayload` — payload for ``sparse-switch``.
- :class:`PackedSwitchPayload` — payload for ``packed-switch``.
"""

from typing import List, Optional

from ..structs import CodeItem
from ..file import DexFile

class CodeItemAccessor:
    """Accessor for the instructions and metadata of a single ``code_item``.

    Obtain one via :meth:`~dexrs._internal.file.DexFile.get_code_item_accessor`.
    """

    code_off: int
    """Byte offset of the ``code_item`` within the DEX file."""
    code_item: CodeItem
    """The parsed ``code_item`` header."""

    @property
    def registers_size(self) -> int:
        """Total number of virtual registers used by the method."""
        ...

    @property
    def ins_size(self) -> int:
        """Number of words of incoming arguments."""
        ...

    @property
    def outs_size(self) -> int:
        """Number of words of outgoing argument space required."""
        ...

    @property
    def tries_size(self) -> int:
        """Number of ``try_item`` entries in the method."""
        ...

    @property
    def debug_info_off(self) -> int:
        """Offset to the ``debug_info_item``, or 0 if absent."""
        ...

    @property
    def code_off(self) -> int:
        """Byte offset of the start of the instruction array."""
        ...

    @property
    def insns_size_in_code_units(self) -> int:
        """Length of the instruction array in 16-bit code units."""
        ...

    @property
    def insns_size_in_bytes(self) -> int:
        """Length of the instruction array in bytes."""
        ...

    def insns_raw(self) -> List[int]:
        """Return the raw instruction array as a list of 16-bit code units."""
        ...

    def insns(self) -> List["Instruction"]:
        """Decode and return all instructions in the method body."""
        ...

    def inst_at(self, pc: int) -> "Instruction":
        """Return the decoded instruction at program-counter offset *pc* (in code units).

        :raises PyDexError: If *pc* is out of range.
        """
        ...

class Instruction:
    """A single decoded Dalvik instruction.

    Provides access to opcode metadata and operand extraction via the
    :mod:`~dexrs._internal.code.vreg` helper functions.
    """

    @property
    def opcode(self) -> "Code":
        """The opcode enum value of this instruction."""
        ...

    @property
    def format(self) -> "Format":
        """The instruction format (determines operand layout)."""
        ...

    @property
    def name(self) -> str:
        """The mnemonic string for this opcode (e.g. ``"invoke-virtual"``)."""
        ...

    @property
    def verify_flags(self) -> int:
        """Verification flags bitmask for this instruction (see :mod:`~dexrs._internal.code.verify_flags`)."""
        ...

    def size_in_code_units(self) -> int:
        """Return the size of this instruction in 16-bit code units."""
        ...

    def next(self) -> Optional["Instruction"]:
        """Return the next instruction in the stream, or ``None`` at end-of-method."""
        ...

    @staticmethod
    def get_opcode_of(inst_data: int) -> "Code":
        """Decode the :class:`Code` opcode from the raw first code unit *inst_data*."""
        ...

    @staticmethod
    def get_name_of(opcode: "Code") -> str:
        """Return the mnemonic string for *opcode*."""
        ...

    @staticmethod
    def get_format_of(opcode: "Code") -> "Format":
        """Return the :class:`Format` for *opcode*."""
        ...

    @staticmethod
    def get_verify_flags_of(opcode: "Code") -> int:
        """Return the verify-flags bitmask for *opcode*."""
        ...

    @staticmethod
    def get_flags_of(inst_data: int) -> int:
        """Return the control-flow flags bitmask for the raw first code unit *inst_data*."""
        ...

    @staticmethod
    def get_index_type_of(inst_data: int) -> "IndexType":
        """Return the :class:`IndexType` for the raw first code unit *inst_data*."""
        ...

    def to_string(self, dex_file: Optional[DexFile] = ...) -> str:
        """Return a human-readable disassembly string for this instruction.

        When *dex_file* is provided, index operands are resolved to names.
        """
        ...

class FillArrayDataPayload:
    """Payload for a ``fill-array-data`` instruction."""

    data: bytes
    """The raw element bytes of the array initialiser."""
    element_count: int
    """Number of elements in the array."""
    element_size: int
    """Size of each element in bytes (1, 2, 4, or 8)."""

class SparseSwitchPayload:
    """Payload for a ``sparse-switch`` instruction."""

    keys: List[int]
    """Sorted list of case keys."""
    targets: List[int]
    """Branch targets (relative offsets) corresponding to each key."""
    case_count: int
    """Number of cases in the switch."""

class PackedSwitchPayload:
    """Payload for a ``packed-switch`` instruction."""

    first_key: List[int]
    """The first (lowest) key value of the packed range."""
    targets: List[int]
    """Branch targets (relative offsets) for each key starting at *first_key*."""
    case_count: int
    """Number of cases in the switch."""

class Format:
    """Dalvik instruction format enum.

    The format determines the number and layout of operands in an instruction.
    Use :attr:`Instruction.format` to obtain the format of a decoded instruction.
    """

    k10x: "Format"
    """No operands (e.g. ``nop``, ``return-void``)."""
    k12x: "Format"
    """Two 4-bit registers: ``vA``, ``vB``."""
    k11n: "Format"
    """One 4-bit register and a 4-bit literal: ``vA``, ``#+B``."""
    k11x: "Format"
    """One 8-bit register: ``vAA``."""
    k10t: "Format"
    """8-bit branch offset: ``+AA``."""
    k20t: "Format"
    """16-bit branch offset: ``+AAAA``."""
    k22x: "Format"
    """One 8-bit and one 16-bit register: ``vAA``, ``vBBBB``."""
    k21t: "Format"
    """One 8-bit register + 16-bit branch offset: ``vAA``, ``+BBBB``."""
    k21s: "Format"
    """One 8-bit register + 16-bit signed literal: ``vAA``, ``#+BBBB``."""
    k21h: "Format"
    """One 8-bit register + 16-bit high-order literal: ``vAA``, ``#+BBBB0000``."""
    k21c: "Format"
    """One 8-bit register + 16-bit index: ``vAA``, ``kind@BBBB``."""
    k23x: "Format"
    """Three 8-bit registers: ``vAA``, ``vBB``, ``vCC``."""
    k22b: "Format"
    """Two 8-bit registers + 8-bit signed literal: ``vAA``, ``vBB``, ``#+CC``."""
    k22t: "Format"
    """Two 4-bit registers + 16-bit branch offset: ``vA``, ``vB``, ``+CCCC``."""
    k22s: "Format"
    """Two 4-bit registers + 16-bit signed literal: ``vA``, ``vB``, ``#+CCCC``."""
    k22c: "Format"
    """Two 4-bit registers + 16-bit index: ``vA``, ``vB``, ``kind@CCCC``."""
    k32x: "Format"
    """Two 16-bit registers: ``vAAAA``, ``vBBBB``."""
    k30t: "Format"
    """32-bit branch offset: ``+AAAAAAAA``."""
    k31t: "Format"
    """One 8-bit register + 32-bit branch offset: ``vAA``, ``+BBBBBBBB``."""
    k31i: "Format"
    """One 8-bit register + 32-bit signed literal: ``vAA``, ``#+BBBBBBBB``."""
    k31c: "Format"
    """One 8-bit register + 32-bit index: ``vAA``, ``string@BBBBBBBB``."""
    k35c: "Format"
    """Up to 5 registers + 16-bit index (used for invoke): ``{vC,vD,vE,vF,vG}``, ``kind@BBBB``."""
    k3rc: "Format"
    """Register range + 16-bit index: ``{vCCCC .. vNNNN}``, ``kind@BBBB``."""
    k45cc: "Format"
    """5 registers + two 16-bit indices (invoke-polymorphic): ``{vC,..}``, ``meth@BBBB``, ``proto@HHHH``."""
    k4rcc: "Format"
    """Register range + two 16-bit indices (invoke-polymorphic/range)."""
    k51l: "Format"
    """One 8-bit register + 64-bit literal: ``vAA``, ``#+BBBBBBBBBBBBBBBB``."""
    kInvalidFormat: "Format"
    """Sentinel value for an unrecognised or invalid instruction format."""

    def __int__(self) -> int:
        """Return the integer discriminant of this format variant."""
        ...

class IndexType:
    """Describes the kind of pool index carried by an instruction operand."""

    Unknown: "IndexType"
    """Index type is not known."""
    NoIndex: "IndexType"
    """This instruction carries no index operand."""
    TypeRef: "IndexType"
    """Index into the type identifiers list."""
    StringRef: "IndexType"
    """Index into the string identifiers list."""
    MethodRef: "IndexType"
    """Index into the method identifiers list."""
    FieldRef: "IndexType"
    """Index into the field identifiers list."""
    MethodAndProtoRef: "IndexType"
    """Dual index: method and prototype (used by ``invoke-polymorphic``)."""
    CallSiteRef: "IndexType"
    """Index into the call-site items."""
    MethodHandleRef: "IndexType"
    """Index into the method handles list."""
    ProtoRef: "IndexType"
    """Index into the prototype identifiers list."""

    def __int__(self) -> int:
        """Return the integer discriminant of this index-type variant."""
        ...

class Code:
    """Dalvik opcode enum.

    Each class attribute is an instance of :class:`Code` representing one
    Dalvik opcode.  Use :attr:`Instruction.opcode` to obtain the opcode of a
    decoded instruction, or compare directly::

        if inst.opcode == Code.RETURN_VOID:
            ...
    """

    NOP: "Code"
    MOVE: "Code"
    MOVE_FROM16: "Code"
    MOVE_16: "Code"
    MOVE_WIDE: "Code"
    MOVE_WIDE_FROM16: "Code"
    MOVE_WIDE_16: "Code"
    MOVE_OBJECT: "Code"
    MOVE_OBJECT_FROM16: "Code"
    MOVE_OBJECT_16: "Code"
    MOVE_RESULT: "Code"
    MOVE_RESULT_WIDE: "Code"
    MOVE_RESULT_OBJECT: "Code"
    MOVE_EXCEPTION: "Code"
    RETURN_VOID: "Code"
    RETURN: "Code"
    RETURN_WIDE: "Code"
    RETURN_OBJECT: "Code"
    CONST_4: "Code"
    CONST_16: "Code"
    CONST: "Code"
    CONST_HIGH16: "Code"
    CONST_WIDE_16: "Code"
    CONST_WIDE_32: "Code"
    CONST_WIDE: "Code"
    CONST_WIDE_HIGH16: "Code"
    CONST_STRING: "Code"
    CONST_STRING_JUMBO: "Code"
    CONST_CLASS: "Code"
    MONITOR_ENTER: "Code"
    MONITOR_EXIT: "Code"
    CHECK_CAST: "Code"
    INSTANCE_OF: "Code"
    ARRAY_LENGTH: "Code"
    NEW_INSTANCE: "Code"
    NEW_ARRAY: "Code"
    FILLED_NEW_ARRAY: "Code"
    FILLED_NEW_ARRAY_RANGE: "Code"
    FILL_ARRAY_DATA: "Code"
    THROW: "Code"
    GOTO: "Code"
    GOTO_16: "Code"
    GOTO_32: "Code"
    PACKED_SWITCH: "Code"
    SPARSE_SWITCH: "Code"
    CMPL_FLOAT: "Code"
    CMPG_FLOAT: "Code"
    CMPL_DOUBLE: "Code"
    CMPG_DOUBLE: "Code"
    CMP_LONG: "Code"
    IF_EQ: "Code"
    IF_NE: "Code"
    IF_LT: "Code"
    IF_GE: "Code"
    IF_GT: "Code"
    IF_LE: "Code"
    IF_EQZ: "Code"
    IF_NEZ: "Code"
    IF_LTZ: "Code"
    IF_GEZ: "Code"
    IF_GTZ: "Code"
    IF_LEZ: "Code"
    UNUSED_3E: "Code"
    UNUSED_3F: "Code"
    UNUSED_40: "Code"
    UNUSED_41: "Code"
    UNUSED_42: "Code"
    UNUSED_43: "Code"
    AGET: "Code"
    AGET_WIDE: "Code"
    AGET_OBJECT: "Code"
    AGET_BOOLEAN: "Code"
    AGET_BYTE: "Code"
    AGET_CHAR: "Code"
    AGET_SHORT: "Code"
    APUT: "Code"
    APUT_WIDE: "Code"
    APUT_OBJECT: "Code"
    APUT_BOOLEAN: "Code"
    APUT_BYTE: "Code"
    APUT_CHAR: "Code"
    APUT_SHORT: "Code"
    IGET: "Code"
    IGET_WIDE: "Code"
    IGET_OBJECT: "Code"
    IGET_BOOLEAN: "Code"
    IGET_BYTE: "Code"
    IGET_CHAR: "Code"
    IGET_SHORT: "Code"
    IPUT: "Code"
    IPUT_WIDE: "Code"
    IPUT_OBJECT: "Code"
    IPUT_BOOLEAN: "Code"
    IPUT_BYTE: "Code"
    IPUT_CHAR: "Code"
    IPUT_SHORT: "Code"
    SGET: "Code"
    SGET_WIDE: "Code"
    SGET_OBJECT: "Code"
    SGET_BOOLEAN: "Code"
    SGET_BYTE: "Code"
    SGET_CHAR: "Code"
    SGET_SHORT: "Code"
    SPUT: "Code"
    SPUT_WIDE: "Code"
    SPUT_OBJECT: "Code"
    SPUT_BOOLEAN: "Code"
    SPUT_BYTE: "Code"
    SPUT_CHAR: "Code"
    SPUT_SHORT: "Code"
    INVOKE_VIRTUAL: "Code"
    INVOKE_SUPER: "Code"
    INVOKE_DIRECT: "Code"
    INVOKE_STATIC: "Code"
    INVOKE_INTERFACE: "Code"
    UNUSED_73: "Code"
    INVOKE_VIRTUAL_RANGE: "Code"
    INVOKE_SUPER_RANGE: "Code"
    INVOKE_DIRECT_RANGE: "Code"
    INVOKE_STATIC_RANGE: "Code"
    INVOKE_INTERFACE_RANGE: "Code"
    UNUSED_79: "Code"
    UNUSED_7A: "Code"
    NEG_INT: "Code"
    NOT_INT: "Code"
    NEG_LONG: "Code"
    NOT_LONG: "Code"
    NEG_FLOAT: "Code"
    NEG_DOUBLE: "Code"
    INT_TO_LONG: "Code"
    INT_TO_FLOAT: "Code"
    INT_TO_DOUBLE: "Code"
    LONG_TO_INT: "Code"
    LONG_TO_FLOAT: "Code"
    LONG_TO_DOUBLE: "Code"
    FLOAT_TO_INT: "Code"
    FLOAT_TO_LONG: "Code"
    FLOAT_TO_DOUBLE: "Code"
    DOUBLE_TO_INT: "Code"
    DOUBLE_TO_LONG: "Code"
    DOUBLE_TO_FLOAT: "Code"
    INT_TO_BYTE: "Code"
    INT_TO_CHAR: "Code"
    INT_TO_SHORT: "Code"
    ADD_INT: "Code"
    SUB_INT: "Code"
    MUL_INT: "Code"
    DIV_INT: "Code"
    REM_INT: "Code"
    AND_INT: "Code"
    OR_INT: "Code"
    XOR_INT: "Code"
    SHL_INT: "Code"
    SHR_INT: "Code"
    USHR_INT: "Code"
    ADD_LONG: "Code"
    SUB_LONG: "Code"
    MUL_LONG: "Code"
    DIV_LONG: "Code"
    REM_LONG: "Code"
    AND_LONG: "Code"
    OR_LONG: "Code"
    XOR_LONG: "Code"
    SHL_LONG: "Code"
    SHR_LONG: "Code"
    USHR_LONG: "Code"
    ADD_FLOAT: "Code"
    SUB_FLOAT: "Code"
    MUL_FLOAT: "Code"
    DIV_FLOAT: "Code"
    REM_FLOAT: "Code"
    ADD_DOUBLE: "Code"
    SUB_DOUBLE: "Code"
    MUL_DOUBLE: "Code"
    DIV_DOUBLE: "Code"
    REM_DOUBLE: "Code"
    ADD_INT_2ADDR: "Code"
    SUB_INT_2ADDR: "Code"
    MUL_INT_2ADDR: "Code"
    DIV_INT_2ADDR: "Code"
    REM_INT_2ADDR: "Code"
    AND_INT_2ADDR: "Code"
    OR_INT_2ADDR: "Code"
    XOR_INT_2ADDR: "Code"
    SHL_INT_2ADDR: "Code"
    SHR_INT_2ADDR: "Code"
    USHR_INT_2ADDR: "Code"
    ADD_LONG_2ADDR: "Code"
    SUB_LONG_2ADDR: "Code"
    MUL_LONG_2ADDR: "Code"
    DIV_LONG_2ADDR: "Code"
    REM_LONG_2ADDR: "Code"
    AND_LONG_2ADDR: "Code"
    OR_LONG_2ADDR: "Code"
    XOR_LONG_2ADDR: "Code"
    SHL_LONG_2ADDR: "Code"
    SHR_LONG_2ADDR: "Code"
    USHR_LONG_2ADDR: "Code"
    ADD_FLOAT_2ADDR: "Code"
    SUB_FLOAT_2ADDR: "Code"
    MUL_FLOAT_2ADDR: "Code"
    DIV_FLOAT_2ADDR: "Code"
    REM_FLOAT_2ADDR: "Code"
    ADD_DOUBLE_2ADDR: "Code"
    SUB_DOUBLE_2ADDR: "Code"
    MUL_DOUBLE_2ADDR: "Code"
    DIV_DOUBLE_2ADDR: "Code"
    REM_DOUBLE_2ADDR: "Code"
    ADD_INT_LIT16: "Code"
    RSUB_INT: "Code"
    MUL_INT_LIT16: "Code"
    DIV_INT_LIT16: "Code"
    REM_INT_LIT16: "Code"
    AND_INT_LIT16: "Code"
    OR_INT_LIT16: "Code"
    XOR_INT_LIT16: "Code"
    ADD_INT_LIT8: "Code"
    RSUB_INT_LIT8: "Code"
    MUL_INT_LIT8: "Code"
    DIV_INT_LIT8: "Code"
    REM_INT_LIT8: "Code"
    AND_INT_LIT8: "Code"
    OR_INT_LIT8: "Code"
    XOR_INT_LIT8: "Code"
    SHL_INT_LIT8: "Code"
    SHR_INT_LIT8: "Code"
    USHR_INT_LIT8: "Code"
    UNUSED_E3: "Code"
    UNUSED_E4: "Code"
    UNUSED_E5: "Code"
    UNUSED_E6: "Code"
    UNUSED_E7: "Code"
    UNUSED_E8: "Code"
    UNUSED_E9: "Code"
    UNUSED_EA: "Code"
    UNUSED_EB: "Code"
    UNUSED_EC: "Code"
    UNUSED_ED: "Code"
    UNUSED_EE: "Code"
    UNUSED_EF: "Code"
    UNUSED_F0: "Code"
    UNUSED_F1: "Code"
    UNUSED_F2: "Code"
    UNUSED_F3: "Code"
    UNUSED_F4: "Code"
    UNUSED_F5: "Code"
    UNUSED_F6: "Code"
    UNUSED_F7: "Code"
    UNUSED_F8: "Code"
    UNUSED_F9: "Code"
    INVOKE_POLYMORPHIC: "Code"
    INVOKE_POLYMORPHIC_RANGE: "Code"
    INVOKE_CUSTOM: "Code"
    INVOKE_CUSTOM_RANGE: "Code"
    CONST_METHOD_HANDLE: "Code"
    CONST_METHOD_TYPE: "Code"

    def __int__(self) -> int:
        """Return the integer opcode value."""
        ...
