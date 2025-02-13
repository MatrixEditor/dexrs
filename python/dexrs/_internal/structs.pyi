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
