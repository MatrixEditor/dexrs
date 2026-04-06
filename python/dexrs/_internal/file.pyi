"""Type stubs for the ``dexrs._internal.file`` native extension module.

The central types for parsing and querying Android DEX files.

- :class:`VerifyPreset` - controls which header checks to run on open.
- :class:`DexFile` - the parsed DEX image; exposes read-only accessors for
  every section described by the `AOSP DEX format specification`_.

.. _AOSP DEX format specification:
   https://source.android.com/docs/core/runtime/dex-format
"""

from typing import Optional, Tuple, List

from .container import InMemoryDexContainer, FileDexContainer
from .structs import (
    Header,
    StringId,
    TypeId,
    FieldId,
    ProtoId,
    MethodId,
    ClassDef,
    TypeItem,
    CatchHandlerData,
    TryItem,
    AnnotationItem,
)
from .class_accessor import ClassAccessor
from .code import CodeItemAccessor
from .annotation import AnnotationSetItem, ClassAnnotationAccessor
from .type_lookup_table import TypeLookupTable

class VerifyPreset:
    """Selects which integrity checks to perform when opening a DEX file.

    Pass one of the class-level constants to
    :meth:`DexFile.from_file` / :meth:`DexFile.from_bytes`.
    """

    ALL: "VerifyPreset"
    """Run all available checks (magic, checksum, and structural validation)."""
    NONE: "VerifyPreset"
    """Skip all verification - fastest open, but unsafe on untrusted input."""
    CHECKSUM_ONLY: "VerifyPreset"
    """Verify the Adler32 checksum only, skipping deeper structural checks."""

class DexFile:
    """A parsed DEX image with read-only accessors for every DEX section.

    Construct via :meth:`from_file` or :meth:`from_bytes`.  All index-based
    getters follow the ``_at`` naming convention for direct integer indices;
    overloads that accept a typed ID struct omit the suffix.

    Example::

        dex = DexFile.from_file(FileDexContainer("classes.dex"), VerifyPreset.ALL)
        header = dex.get_header()
        print(f"DEX version {header.version_int}, {dex.num_class_defs()} classes")
    """

    @staticmethod
    def from_file(data: FileDexContainer, preset: VerifyPreset = ...) -> "DexFile":
        """Open a DEX file from a :class:`~dexrs._internal.container.FileDexContainer`.

        :param data: Memory-mapped file container.
        :param preset: Verification level; defaults to :attr:`VerifyPreset.ALL`.
        :raises PyDexError: If the file is malformed or verification fails.
        """
        ...

    @staticmethod
    def from_bytes(data: InMemoryDexContainer, preset: VerifyPreset = ...) -> "DexFile":
        """Parse a DEX file from an in-memory container.

        :param data: In-memory bytes container.
        :param preset: Verification level; defaults to :attr:`VerifyPreset.ALL`.
        :raises PyDexError: If the bytes are not a valid DEX image.
        """
        ...

    def get_header(self) -> Header:
        """Return the parsed DEX file header."""
        ...

    # ------------------------------------------------------------------ strings

    def get_string_id(self, index: int) -> StringId:
        """Return the :class:`StringId` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_string_id_opt(self, index: int) -> Optional[StringId]:
        """Return the :class:`StringId` at *index*, or ``None`` if *index* is the no-index sentinel."""
        ...

    def num_string_ids(self) -> int:
        """Return the total number of string identifiers in the DEX file."""
        ...

    def get_utf16_at(self, index: int) -> str:
        """Decode and return the string at the given string-ID *index*.

        :raises PyDexError: On MUTF-8 decode error or out-of-bounds *index*.
        """
        ...

    def get_utf16(self, string_id: StringId) -> str:
        """Decode and return the string referenced by *string_id*.

        :raises PyDexError: On MUTF-8 decode error.
        """
        ...

    def get_utf16_opt_at(self, string_id: StringId) -> Optional[str]:
        """Return the decoded string for *string_id*, or ``None`` for the no-index sentinel."""
        ...

    def get_utf16_lossy(self, string_id: StringId) -> str:
        """Decode the string referenced by *string_id*, replacing invalid bytes with U+FFFD."""
        ...

    def get_utf16_lossy_at(self, index: int) -> str:
        """Decode the string at *index*, replacing invalid bytes with U+FFFD."""
        ...

    def get_string_data(self, string_id: StringId) -> Tuple[int, bytes]:
        """Return the raw ``(length_in_utf16_units, mutf8_bytes)`` for *string_id*."""
        ...

    def fast_get_utf8(self, string_id: StringId) -> str:
        """Fast path: return the string referenced by *string_id* (assumes valid ASCII/UTF-8)."""
        ...

    def fast_get_utf8_at(self, index: int) -> str:
        """Fast path: return the string at *index* (assumes valid ASCII/UTF-8)."""
        ...

    # ----------------------------------------------------------------- type ids

    def get_type_id(self, index: int) -> TypeId:
        """Return the :class:`TypeId` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_type_id_opt(self, index: int) -> Optional[TypeId]:
        """Return the :class:`TypeId` at *index*, or ``None`` for the no-index sentinel."""
        ...

    def num_type_ids(self) -> int:
        """Return the total number of type identifiers."""
        ...

    def get_type_desc(self, type_id: TypeId) -> str:
        """Return the type descriptor string (e.g. ``"Ljava/lang/String;"``) for *type_id*."""
        ...

    def get_type_desc_at(self, index: int) -> str:
        """Return the type descriptor string for the type-ID at *index*."""
        ...

    def pretty_type_at(self, index: int) -> str:
        """Return a human-readable type name (e.g. ``"java.lang.String"``) for the type at *index*."""
        ...

    def pretty_type(self, type_id: TypeId) -> str:
        """Return a human-readable type name for *type_id*."""
        ...

    # ---------------------------------------------------------------- field ids

    def get_field_id(self, index: int) -> FieldId:
        """Return the :class:`FieldId` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_field_id_opt(self, index: int) -> Optional[FieldId]:
        """Return the :class:`FieldId` at *index*, or ``None`` for the no-index sentinel."""
        ...

    def num_field_ids(self) -> int:
        """Return the total number of field identifiers."""
        ...

    def get_field_name(self, field_id: FieldId) -> str:
        """Return the simple name string for *field_id*."""
        ...

    def get_field_name_at(self, index: int) -> str:
        """Return the simple name string for the field-ID at *index*."""
        ...

    # ---------------------------------------------------------------- proto ids

    def get_proto_id(self, index: int) -> ProtoId:
        """Return the :class:`ProtoId` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_proto_id_opt(self, index: int) -> Optional[ProtoId]:
        """Return the :class:`ProtoId` at *index*, or ``None`` for the no-index sentinel."""
        ...

    def num_proto_ids(self) -> int:
        """Return the total number of method prototype identifiers."""
        ...

    def get_proto_shorty(self, proto_id: ProtoId) -> str:
        """Return the shorty descriptor string for *proto_id* (e.g. ``"VIL"``)."""
        ...

    def get_proto_shorty_at(self, index: int) -> str:
        """Return the shorty descriptor string for the proto-ID at *index*."""
        ...

    # --------------------------------------------------------------- method ids

    def get_method_id(self, index: int) -> MethodId:
        """Return the :class:`MethodId` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_method_id_opt(self, index: int) -> Optional[MethodId]:
        """Return the :class:`MethodId` at *index*, or ``None`` for the no-index sentinel."""
        ...

    def num_method_ids(self) -> int:
        """Return the total number of method identifiers."""
        ...

    # --------------------------------------------------------------- class defs

    def get_class_def(self, index: int) -> ClassDef:
        """Return the :class:`ClassDef` at *index*.

        :raises PyDexError: If *index* is out of range.
        """
        ...

    def get_class_def_opt(self, index: int) -> Optional[ClassDef]:
        """Return the :class:`ClassDef` at *index*, or ``None`` for the no-index sentinel."""
        ...

    def num_class_defs(self) -> int:
        """Return the total number of class definitions."""
        ...

    def get_class_desc(self, class_def: ClassDef) -> str:
        """Return the type descriptor for the class defined by *class_def*."""
        ...

    def get_interfaces_list(self, class_def: ClassDef) -> Optional[List[TypeItem]]:
        """Return the list of interfaces implemented by *class_def*, or ``None`` if none."""
        ...

    # ------------------------------------------------------------- class data

    def get_class_accessor(self, class_def: ClassDef) -> Optional[ClassAccessor]:
        """Return a :class:`~dexrs._internal.class_accessor.ClassAccessor` for *class_def*.

        Returns ``None`` when the class has no ``class_data_item`` (i.e. it is
        a pure interface or has no members).
        """
        ...

    def get_code_item_accessor(self, code_off: int) -> CodeItemAccessor:
        """Return a :class:`~dexrs._internal.code.CodeItemAccessor` for the ``code_item`` at *code_off*.

        :param code_off: Byte offset from the start of the DEX file.
        :raises PyDexError: If *code_off* is invalid or out of range.
        """
        ...

    def get_try_items(self, ca: CodeItemAccessor) -> List[TryItem]:
        """Return the list of ``try_item`` structures from *ca*'s code item."""
        ...

    def get_catch_handlers(
        self, ca: CodeItemAccessor, try_item: TryItem
    ) -> List[CatchHandlerData]:
        """Return the catch-handler entries for *try_item* within *ca*."""
        ...

    # ------------------------------------------------------------ annotations

    def get_annotation_set(self, offset: int) -> AnnotationSetItem:
        """Return the list of annotation offsets at *offset* in the DEX file."""
        ...

    def get_annotation(self, offset: int) -> AnnotationItem:
        """Return the parsed :class:`~dexrs._internal.structs.AnnotationItem` at *offset*."""
        ...

    def get_class_annotation_accessor(
        self, class_def: ClassDef
    ) -> ClassAnnotationAccessor:
        """Return an accessor for all annotations attached to *class_def*."""
        ...

    # ------------------------------------------------------- type lookup table

    def build_type_lookup_table(self) -> TypeLookupTable:
        """Build and return an O(1) :class:`~dexrs._internal.type_lookup_table.TypeLookupTable` for this DEX file."""
        ...
