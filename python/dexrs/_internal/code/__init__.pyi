from typing import List, Optional

from ..structs import CodeItem
from ..file import DexFile

class CodeItemAccessor:
    code_off: int
    code_item: CodeItem

    @property
    def registers_size(self) -> int: ...
    @property
    def ins_size(self) -> int: ...
    @property
    def outs_size(self) -> int: ...
    @property
    def tries_size(self) -> int: ...
    @property
    def debug_info_off(self) -> int: ...
    @property
    def code_off(self) -> int: ...
    @property
    def insns_size_in_code_units(self) -> int: ...
    @property
    def insns_size_in_bytes(self) -> int: ...
    def insns_raw(self) -> List[int]: ...
    def insns(self) -> List[Instruction]: ...
    def inst_at(self, pc: int) -> Instruction: ...

class Instruction:
    @property
    def opcode(self) -> Code: ...
    @property
    def format(self) -> Format: ...
    @property
    def name(self) -> str: ...
    @property
    def verify_flags(self) -> int: ...
    def size_in_code_units(self) -> int: ...
    def next(self) -> Instruction | None: ...
    @staticmethod
    def get_opcode_of(inst_data: int) -> Code: ...
    @staticmethod
    def get_name_of(opcode: Code) -> str: ...
    @staticmethod
    def get_format_of(opcode: Code) -> Format: ...
    @staticmethod
    def get_verify_flags_of(opcode: Code) -> int: ...
    @staticmethod
    def get_flags_of(inst_data: int) -> int: ...
    @staticmethod
    def get_index_type_of(inst_data: int) -> IndexType: ...
    def to_string(self, dex_file: Optional[DexFile] = ...) -> str: ...

class FillArrayDataPayload:
    data: bytes
    element_count: int
    element_size: int

class SparseSwitchPayload:
    keys: List[int]
    targets: List[int]
    case_count: int

class PackedSwitchPayload:
    first_key: List[int]
    targets: List[int]
    case_count: int

class Format:
    k10x: Format
    k12x: Format
    k11n: Format
    k11x: Format
    k10t: Format
    k20t: Format
    k22x: Format
    k21t: Format
    k21s: Format
    k21h: Format
    k21c: Format
    k23x: Format
    k22b: Format
    k22t: Format
    k22s: Format
    k22c: Format
    k32x: Format
    k30t: Format
    k31t: Format
    k31i: Format
    k31c: Format
    k35c: Format
    k3rc: Format
    k45cc: Format
    k4rcc: Format
    k51l: Format
    kInvalidFormat: Format

    def __int__(self) -> int: ...

class IndexType:
    Unknown: IndexType
    NoIndex: IndexType
    TypeRef: IndexType
    StringRef: IndexType
    MethodRef: IndexType
    FieldRef: IndexType
    MethodAndProtoRef: IndexType
    CallSiteRef: IndexType
    MethodHandleRef: IndexType
    ProtoRef: IndexType

    def __int__(self) -> int: ...

class Code:
    NOP: Code
    MOVE: Code
    MOVE_FROM16: Code
    MOVE_16: Code
    MOVE_WIDE: Code
    MOVE_WIDE_FROM16: Code
    MOVE_WIDE_16: Code
    MOVE_OBJECT: Code
    MOVE_OBJECT_FROM16: Code
    MOVE_OBJECT_16: Code
    MOVE_RESULT: Code
    MOVE_RESULT_WIDE: Code
    MOVE_RESULT_OBJECT: Code
    MOVE_EXCEPTION: Code
    RETURN_VOID: Code
    RETURN: Code
    RETURN_WIDE: Code
    RETURN_OBJECT: Code
    CONST_4: Code
    CONST_16: Code
    CONST: Code
    CONST_HIGH16: Code
    CONST_WIDE_16: Code
    CONST_WIDE_32: Code
    CONST_WIDE: Code
    CONST_WIDE_HIGH16: Code
    CONST_STRING: Code
    CONST_STRING_JUMBO: Code
    CONST_CLASS: Code
    MONITOR_ENTER: Code
    MONITOR_EXIT: Code
    CHECK_CAST: Code
    INSTANCE_OF: Code
    ARRAY_LENGTH: Code
    NEW_INSTANCE: Code
    NEW_ARRAY: Code
    FILLED_NEW_ARRAY: Code
    FILLED_NEW_ARRAY_RANGE: Code
    FILL_ARRAY_DATA: Code
    THROW: Code
    GOTO: Code
    GOTO_16: Code
    GOTO_32: Code
    PACKED_SWITCH: Code
    SPARSE_SWITCH: Code
    CMPL_FLOAT: Code
    CMPG_FLOAT: Code
    CMPL_DOUBLE: Code
    CMPG_DOUBLE: Code
    CMP_LONG: Code
    IF_EQ: Code
    IF_NE: Code
    IF_LT: Code
    IF_GE: Code
    IF_GT: Code
    IF_LE: Code
    IF_EQZ: Code
    IF_NEZ: Code
    IF_LTZ: Code
    IF_GEZ: Code
    IF_GTZ: Code
    IF_LEZ: Code
    UNUSED_3E: Code
    UNUSED_3F: Code
    UNUSED_40: Code
    UNUSED_41: Code
    UNUSED_42: Code
    UNUSED_43: Code
    AGET: Code
    AGET_WIDE: Code
    AGET_OBJECT: Code
    AGET_BOOLEAN: Code
    AGET_BYTE: Code
    AGET_CHAR: Code
    AGET_SHORT: Code
    APUT: Code
    APUT_WIDE: Code
    APUT_OBJECT: Code
    APUT_BOOLEAN: Code
    APUT_BYTE: Code
    APUT_CHAR: Code
    APUT_SHORT: Code
    IGET: Code
    IGET_WIDE: Code
    IGET_OBJECT: Code
    IGET_BOOLEAN: Code
    IGET_BYTE: Code
    IGET_CHAR: Code
    IGET_SHORT: Code
    IPUT: Code
    IPUT_WIDE: Code
    IPUT_OBJECT: Code
    IPUT_BOOLEAN: Code
    IPUT_BYTE: Code
    IPUT_CHAR: Code
    IPUT_SHORT: Code
    SGET: Code
    SGET_WIDE: Code
    SGET_OBJECT: Code
    SGET_BOOLEAN: Code
    SGET_BYTE: Code
    SGET_CHAR: Code
    SGET_SHORT: Code
    SPUT: Code
    SPUT_WIDE: Code
    SPUT_OBJECT: Code
    SPUT_BOOLEAN: Code
    SPUT_BYTE: Code
    SPUT_CHAR: Code
    SPUT_SHORT: Code
    INVOKE_VIRTUAL: Code
    INVOKE_SUPER: Code
    INVOKE_DIRECT: Code
    INVOKE_STATIC: Code
    INVOKE_INTERFACE: Code
    UNUSED_73: Code
    INVOKE_VIRTUAL_RANGE: Code
    INVOKE_SUPER_RANGE: Code
    INVOKE_DIRECT_RANGE: Code
    INVOKE_STATIC_RANGE: Code
    INVOKE_INTERFACE_RANGE: Code
    UNUSED_79: Code
    UNUSED_7A: Code
    NEG_INT: Code
    NOT_INT: Code
    NEG_LONG: Code
    NOT_LONG: Code
    NEG_FLOAT: Code
    NEG_DOUBLE: Code
    INT_TO_LONG: Code
    INT_TO_FLOAT: Code
    INT_TO_DOUBLE: Code
    LONG_TO_INT: Code
    LONG_TO_FLOAT: Code
    LONG_TO_DOUBLE: Code
    FLOAT_TO_INT: Code
    FLOAT_TO_LONG: Code
    FLOAT_TO_DOUBLE: Code
    DOUBLE_TO_INT: Code
    DOUBLE_TO_LONG: Code
    DOUBLE_TO_FLOAT: Code
    INT_TO_BYTE: Code
    INT_TO_CHAR: Code
    INT_TO_SHORT: Code
    ADD_INT: Code
    SUB_INT: Code
    MUL_INT: Code
    DIV_INT: Code
    REM_INT: Code
    AND_INT: Code
    OR_INT: Code
    XOR_INT: Code
    SHL_INT: Code
    SHR_INT: Code
    USHR_INT: Code
    ADD_LONG: Code
    SUB_LONG: Code
    MUL_LONG: Code
    DIV_LONG: Code
    REM_LONG: Code
    AND_LONG: Code
    OR_LONG: Code
    XOR_LONG: Code
    SHL_LONG: Code
    SHR_LONG: Code
    USHR_LONG: Code
    ADD_FLOAT: Code
    SUB_FLOAT: Code
    MUL_FLOAT: Code
    DIV_FLOAT: Code
    REM_FLOAT: Code
    ADD_DOUBLE: Code
    SUB_DOUBLE: Code
    MUL_DOUBLE: Code
    DIV_DOUBLE: Code
    REM_DOUBLE: Code
    ADD_INT_2ADDR: Code
    SUB_INT_2ADDR: Code
    MUL_INT_2ADDR: Code
    DIV_INT_2ADDR: Code
    REM_INT_2ADDR: Code
    AND_INT_2ADDR: Code
    OR_INT_2ADDR: Code
    XOR_INT_2ADDR: Code
    SHL_INT_2ADDR: Code
    SHR_INT_2ADDR: Code
    USHR_INT_2ADDR: Code
    ADD_LONG_2ADDR: Code
    SUB_LONG_2ADDR: Code
    MUL_LONG_2ADDR: Code
    DIV_LONG_2ADDR: Code
    REM_LONG_2ADDR: Code
    AND_LONG_2ADDR: Code
    OR_LONG_2ADDR: Code
    XOR_LONG_2ADDR: Code
    SHL_LONG_2ADDR: Code
    SHR_LONG_2ADDR: Code
    USHR_LONG_2ADDR: Code
    ADD_FLOAT_2ADDR: Code
    SUB_FLOAT_2ADDR: Code
    MUL_FLOAT_2ADDR: Code
    DIV_FLOAT_2ADDR: Code
    REM_FLOAT_2ADDR: Code
    ADD_DOUBLE_2ADDR: Code
    SUB_DOUBLE_2ADDR: Code
    MUL_DOUBLE_2ADDR: Code
    DIV_DOUBLE_2ADDR: Code
    REM_DOUBLE_2ADDR: Code
    ADD_INT_LIT16: Code
    RSUB_INT: Code
    MUL_INT_LIT16: Code
    DIV_INT_LIT16: Code
    REM_INT_LIT16: Code
    AND_INT_LIT16: Code
    OR_INT_LIT16: Code
    XOR_INT_LIT16: Code
    ADD_INT_LIT8: Code
    RSUB_INT_LIT8: Code
    MUL_INT_LIT8: Code
    DIV_INT_LIT8: Code
    REM_INT_LIT8: Code
    AND_INT_LIT8: Code
    OR_INT_LIT8: Code
    XOR_INT_LIT8: Code
    SHL_INT_LIT8: Code
    SHR_INT_LIT8: Code
    USHR_INT_LIT8: Code
    UNUSED_E3: Code
    UNUSED_E4: Code
    UNUSED_E5: Code
    UNUSED_E6: Code
    UNUSED_E7: Code
    UNUSED_E8: Code
    UNUSED_E9: Code
    UNUSED_EA: Code
    UNUSED_EB: Code
    UNUSED_EC: Code
    UNUSED_ED: Code
    UNUSED_EE: Code
    UNUSED_EF: Code
    UNUSED_F0: Code
    UNUSED_F1: Code
    UNUSED_F2: Code
    UNUSED_F3: Code
    UNUSED_F4: Code
    UNUSED_F5: Code
    UNUSED_F6: Code
    UNUSED_F7: Code
    UNUSED_F8: Code
    UNUSED_F9: Code
    INVOKE_POLYMORPHIC: Code
    INVOKE_POLYMORPHIC_RANGE: Code
    INVOKE_CUSTOM: Code
    INVOKE_CUSTOM_RANGE: Code
    CONST_METHOD_HANDLE: Code
    CONST_METHOD_TYPE: Code

    def __int__(self) -> int: ...
