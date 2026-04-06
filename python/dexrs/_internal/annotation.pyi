"""Type stubs for the ``dexrs._internal.annotation`` native extension module.

Provides access to class-level annotation data from a DEX file, including
class annotations, field annotations, method annotations, and parameter
annotations.
"""

from typing import List

from .structs import (
    FieldAnnotationsItem,
    MethodAnnotationsItem,
    ParameterAnnotationsItem,
)

AnnotationSetItem = List[int]
"""A list of annotation offsets pointing to :class:`~dexrs._internal.structs.AnnotationItem` records."""

class ClassAnnotationAccessor:
    """Accessor for all annotation data attached to a single class definition.

    Obtain one via :meth:`~dexrs._internal.file.DexFile.get_class_annotation_accessor`.
    """

    def get_class_annotation_set(self) -> AnnotationSetItem:
        """Return the list of annotation offsets for the class itself."""
        ...

    def get_field_annotations_items(self) -> List[FieldAnnotationsItem]:
        """Return annotation metadata for each annotated field in the class."""
        ...

    def get_method_annotations_items(self) -> List[MethodAnnotationsItem]:
        """Return annotation metadata for each annotated method in the class."""
        ...

    def get_parameter_annotations_items(self) -> List[ParameterAnnotationsItem]:
        """Return annotation metadata for each annotated method's parameter list."""
        ...
