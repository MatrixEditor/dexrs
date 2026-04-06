"""Type stubs for the ``dexrs._internal.class_accessor`` native extension module.

Provides iterator-style access to the fields and methods declared inside a
``class_data_item``, which is the LEB128-encoded section of a DEX class
definition that lists members.
"""

from typing import List

class Method:
    """A method entry decoded from ``class_data_item``.

    Fields mirror the DEX ``encoded_method`` structure (method index delta
    resolved to an absolute index, access flags, and code offset).
    """

    index: int
    """Absolute index into the ``method_ids`` list."""
    access_flags: int
    """Access flags bitmask (``ACC_PUBLIC``, ``ACC_STATIC``, etc.)."""
    code_offset: int
    """Byte offset in the DEX file of the ``code_item``, or 0 for abstract / native methods."""

    def is_static_or_direct(self) -> bool:
        """Return ``True`` if this is a static or direct (non-virtual) method."""
        ...

class Field:
    """A field entry decoded from ``class_data_item``.

    Fields mirror the DEX ``encoded_field`` structure.
    """

    index: int
    """Absolute index into the ``field_ids`` list."""
    access_flags: int
    """Access flags bitmask (``ACC_PUBLIC``, ``ACC_STATIC``, etc.)."""

    def is_static(self) -> bool:
        """Return ``True`` if this field has the ``ACC_STATIC`` flag set."""
        ...

class ClassAccessor:
    """Accessor for all fields and methods defined in a class.

    Obtain one via :meth:`~dexrs._internal.file.DexFile.get_class_accessor`.
    Iterating ``get_fields()`` / ``get_methods()`` is the primary use-case.
    """

    num_fields: int
    """Total number of fields (static + instance)."""
    num_methods: int
    """Total number of methods (direct + virtual)."""
    num_static_fields: int
    """Number of static fields."""
    num_instance_fields: int
    """Number of instance fields."""
    num_direct_methods: int
    """Number of direct (non-virtual) methods."""
    num_virtual_methods: int
    """Number of virtual methods."""

    def get_fields(self) -> List[Field]:
        """Return all fields (static first, then instance)."""
        ...

    def get_methods(self) -> List[Method]:
        """Return all methods (direct first, then virtual)."""
        ...

    def get_static_fields(self) -> List[Field]:
        """Return only the static fields of this class."""
        ...

    def get_instance_fields(self) -> List[Field]:
        """Return only the instance fields of this class."""
        ...

    def get_direct_methods(self) -> List[Method]:
        """Return only the direct (non-virtual) methods of this class."""
        ...

    def get_virtual_methods(self) -> List[Method]:
        """Return only the virtual methods of this class."""
        ...
