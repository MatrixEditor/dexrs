from typing import List

class Method:
    index: int
    access_flags: int
    code_offset: int

    def is_static_or_direct(self) -> bool: ...

class Field:
    index: int
    access_flags: int

    def is_static(self) -> bool: ...

class ClassAccessor:
    num_fields: int
    num_methods: int
    num_static_fields: int
    num_instance_fields: int
    num_direct_methods: int
    num_virtual_methods: int

    def get_fields(self) -> List[Field]: ...
    def get_methods(self) -> List[Method]: ...
    def get_static_fields(self) -> List[Field]: ...
    def get_instance_fields(self) -> List[Field]: ...
    def get_direct_methods(self) -> List[Method]: ...
    def get_virtual_methods(self) -> List[Method]: ...
