from typing import List

from .structs import (
    FieldAnnotationsItem,
    MethodAnnotationsItem,
    ParameterAnnotationsItem,
)

AnnotationSetItem = List[int]

class ClassAnnotationAccessor:
    def get_class_annotation_set(self) -> AnnotationSetItem: ...
    def get_field_annotations_items(self) -> List[FieldAnnotationsItem]: ...
    def get_method_annotations_items(self) -> List[MethodAnnotationsItem]: ...
    def get_parameter_annotations_items(self) -> List[ParameterAnnotationsItem]: ...
