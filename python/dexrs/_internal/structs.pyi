"""Type stubs for the ``dexrs._internal.structs`` native extension module.

Plain-data structs that mirror the on-disk layout of the DEX file format as
described by the `AOSP DEX format specification`_.  Instances are created by
:class:`~dexrs._internal.file.DexFile` accessor methods; they are not meant to
be constructed directly.

.. _AOSP DEX format specification:
   https://source.android.com/docs/core/runtime/dex-format
"""

from typing import List

class Header:
    """The DEX file header (first 112 bytes of the file).

    Contains global metadata: magic number, checksum, SHA-1 signature,
    file size, and offsets/sizes for every ID and data section.
    """

    checksum: int
    """Adler32 checksum of the file contents (excluding magic and this field)."""
    file_size: int
    """Total size of the DEX file in bytes."""
    header_size: int
    """Size of this header in bytes (112 for standard DEX, 120 for DEX 041+)."""
    endian_tag: int
    """Endianness tag - always ``0x12345678`` for standard DEX."""
    link_size: int
    """Size of the link section (0 for statically linked files)."""
    link_off: int
    """Offset to the link section (0 if unused)."""
    string_ids_size: int
    """Number of elements in the string identifiers list."""
    string_ids_off: int
    """Offset to the string identifiers list."""
    type_ids_size: int
    """Number of elements in the type identifiers list."""
    type_ids_off: int
    """Offset to the type identifiers list."""
    proto_ids_size: int
    """Number of elements in the prototype identifiers list."""
    proto_ids_off: int
    """Offset to the prototype identifiers list."""
    field_ids_size: int
    """Number of elements in the field identifiers list."""
    field_ids_off: int
    """Offset to the field identifiers list."""
    method_ids_size: int
    """Number of elements in the method identifiers list."""
    method_ids_off: int
    """Offset to the method identifiers list."""
    class_defs_size: int
    """Number of elements in the class definitions list."""
    class_defs_off: int
    """Offset to the class definitions list."""
    data_size: int
    """Size of the data section in bytes."""
    data_off: int
    """Offset to the data section."""

    @property
    def version_int(self) -> int:
        """DEX format version as an integer (e.g. 35 for ``dex\n035\0``)."""
        ...

    @property
    def signature(self) -> bytes:
        """SHA-1 hash of the file contents (20 bytes), excluding magic, checksum, and this field."""
        ...

    @property
    def magic(self) -> bytes:
        """The 8-byte magic number (e.g. ``b"dex\\n035\\0"``)."""
        ...

class StringId:
    """Points to the raw string data for one entry in the string table."""

    string_data_off: int
    """Byte offset to the ``string_data_item`` for this string."""

class TypeId:
    """Associates a type with its descriptor string."""

    descriptor_idx: int
    """Index into the string identifiers list for this type's descriptor."""

class FieldId:
    """Identifies a field by its class, type, and name."""

    class_idx: int
    """Index into the type identifiers list for the defining class."""
    type_idx: int
    """Index into the type identifiers list for this field's type."""
    name_idx: int
    """Index into the string identifiers list for this field's name."""

class ProtoId:
    """Describes a method prototype (return type + parameter types)."""

    shorty_idx: int
    """Index into the string identifiers list for the shorty descriptor."""
    return_type_idx: int
    """Index into the type identifiers list for the return type."""
    parameters_off: int
    """Offset to the ``type_list`` of parameter types (0 if no parameters)."""

class MethodId:
    """Identifies a method by its class, prototype, and name."""

    class_idx: int
    """Index into the type identifiers list for the defining class."""
    proto_idx: int
    """Index into the prototype identifiers list for this method's prototype."""
    name_idx: int
    """Index into the string identifiers list for this method's name."""

class ClassDef:
    """Top-level class definition entry in the DEX class list."""

    class_idx: int
    """Index into the type identifiers list for this class."""
    access_flags: int
    """Access and property flags bitmask (``ACC_PUBLIC``, etc.)."""
    superclass_idx: int
    """Type-ID index of the superclass, or ``0xFFFFFFFF`` (no-index) for ``Object``."""
    interfaces_off: int
    """Offset to the ``type_list`` of implemented interfaces (0 if none)."""
    source_file_idx: int
    """String-ID index of the source file name, or ``0xFFFFFFFF`` if absent."""
    annotations_off: int
    """Offset to the ``annotations_directory_item`` (0 if no annotations)."""
    class_data_off: int
    """Offset to the ``class_data_item`` (0 if no fields or methods)."""
    static_values_off: int
    """Offset to the ``encoded_array_item`` of static field initial values (0 if none)."""

class TypeItem:
    """A single type reference inside a ``type_list``."""

    type_idx: int
    """Index into the type identifiers list."""

class CodeItem:
    """Header of a ``code_item``, describing register and instruction counts."""

    registers_size: int
    """Total number of virtual registers used by the method."""
    ins_size: int
    """Number of words of incoming arguments."""
    outs_size: int
    """Number of words of outgoing argument space required."""
    tries_size: int
    """Number of ``try_item`` entries."""
    debug_info_off: int
    """Offset to the ``debug_info_item`` (0 if none)."""
    insns_size: int
    """Size of the instruction list in 16-bit code units."""

class TryItem:
    """A single exception-handling range within a method body."""

    start_addr: int
    """Start address of the covered block in 16-bit code units."""
    insn_count: int
    """Number of 16-bit code units covered by this try block."""
    handler_off: int
    """Offset to the catch-handler list (relative to the handlers section start)."""

class CatchHandlerData:
    """A single catch clause within a ``catch_handler_item``."""

    type_idx: int
    """Type-ID index of the caught exception type (``0xFFFFFFFF`` for catch-all)."""
    address: int
    """Handler start address in 16-bit code units."""

    def is_catch_all(self) -> bool:
        """Return ``True`` if this is a catch-all handler (``type_idx == 0xFFFFFFFF``)."""
        ...

class AnnotationsDirectoryItem:
    """Points to all annotations for a class definition."""

    class_annotations_off: int
    """Offset to the class-level ``annotation_set_item`` (0 if none)."""
    fields_size: int
    """Number of ``field_annotations_item`` entries."""
    methods_size: int
    """Number of ``method_annotations_item`` entries."""
    parameters_size: int
    """Number of ``parameter_annotations_item`` entries."""

class FieldAnnotationsItem:
    """Associates a field with its annotation set."""

    field_idx: int
    """Index into the field identifiers list."""
    annotations_off: int
    """Offset to the ``annotation_set_item`` for this field."""

class MethodAnnotationsItem:
    """Associates a method with its annotation set."""

    method_idx: int
    """Index into the method identifiers list."""
    annotations_off: int
    """Offset to the ``annotation_set_item`` for this method."""

class ParameterAnnotationsItem:
    """Associates a method's parameters with their annotation sets."""

    method_idx: int
    """Index into the method identifiers list."""
    annotations_off: int
    """Offset to the ``annotation_set_ref_list`` for this method's parameters."""

class EncodedValue:
    """A tagged union representing any value that can appear in a DEX annotation or static initialiser.

    Each inner class corresponds to one ``VALUE_TYPE`` tag in the DEX spec.
    """

    class Null:
        """A ``null`` reference value."""
        pass

    class Boolean:
        """A boolean constant."""
        value: bool

    class Byte:
        """A signed 8-bit integer constant."""
        value: int

    class Char:
        """An unsigned 16-bit character constant."""
        value: int

    class Short:
        """A signed 16-bit integer constant."""
        value: int

    class Integer:
        """A signed 32-bit integer constant."""
        value: int

    class Float:
        """A 32-bit floating-point constant."""
        value: float

    class Long:
        """A signed 64-bit integer constant."""
        value: int

    class Double:
        """A 64-bit floating-point constant."""
        value: float

    class String:
        """A string constant, referenced by index."""
        index: int
        """Index into the string identifiers list."""

    class Type:
        """A type constant, referenced by index."""
        index: int
        """Index into the type identifiers list."""

    class Field:
        """A field constant, referenced by index."""
        index: int
        """Index into the field identifiers list."""

    class Method:
        """A method constant, referenced by index."""
        index: int
        """Index into the method identifiers list."""

    class MethodType:
        """A method-type constant (proto), referenced by index."""
        index: int
        """Index into the prototype identifiers list."""

    class MethodHandle:
        """A method-handle constant, referenced by index."""
        index: int
        """Index into the method handles list."""

    class Enum:
        """An enum constant, referenced by field index."""
        index: int
        """Index into the field identifiers list for the enum constant."""

    class Array:
        """An array of encoded values."""
        elements: "List[EncodedValue]"
        """The elements of the array."""

    class Annotation:
        """A nested annotation value."""
        annotation: "EncodedAnnotation"
        """The nested encoded annotation."""

class AnnotationElement:
    """A single name–value pair within an encoded annotation."""

    name_idx: int
    """Index into the string identifiers list for the element name."""
    value: EncodedValue
    """The element's value."""

class EncodedAnnotation:
    """An annotation instance with its type and elements."""

    type_idx: int
    """Index into the type identifiers list for the annotation type."""
    elements: List[AnnotationElement]
    """The name–value pairs of the annotation."""

class AnnotationItem:
    """A visibility-tagged annotation as stored in the DEX file."""

    visibility: int
    """Visibility byte: ``0`` = BUILD, ``1`` = RUNTIME, ``2`` = SYSTEM."""
    annotation: EncodedAnnotation
    """The annotation data."""
