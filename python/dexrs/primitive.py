"""Thin Python wrapper re-exporting the Rust ``PrimitiveType`` enum.

:class:`PrimitiveType` enumerates all Java primitive types (plus ``Void``
and the non-primitive sentinel ``Not``).  It provides helpers for JVM
descriptor characters, boxing classes, storage sizes, and type properties.

Example::

    from dexrs.primitive import PrimitiveType

    pt = PrimitiveType.from_char("I")
    print(pt.pretty_name())       # "int"
    print(pt.descriptor())        # "I"
    print(pt.boxed_descriptor())  # "Ljava/lang/Integer;"
    print(pt.component_size())    # 4
    print(pt.is_numeric())        # True
    print(pt.is_64bit())          # False
"""
from dexrs._internal import primitive as _rust_primitive

PrimitiveType = _rust_primitive.PrimitiveType

__all__ = ["PrimitiveType"]
