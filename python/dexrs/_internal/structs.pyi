class Header:
    checksum: int
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    @property
    def version_int(self) -> int: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def magic(self) -> bytes: ...

class StringId:
    string_data_off: int

class TypeId:
    descriptor_idx: int

class FieldId:
    class_idx: int
    type_idx: int
    name_idx: int

class ProtoId:
    shorty_idx: int
    return_type_idx: int
    parameters_off: int

class MethodId:
    class_idx: int
    proto_idx: int
    name_idx: int

class ClassDef:
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    source_file_idx: int
    annotations_off: int
    class_data_off: int
    static_values_off: int

class TypeItem:
    type_idx: int

class CodeItem:
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int
