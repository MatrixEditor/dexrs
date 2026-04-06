"""Type stubs for the ``dexrs._internal.primitive`` native extension module."""

from typing import Optional


class PrimitiveType:
    """Enumeration of Java primitive types as classified by the DEX format.

    Each variant corresponds to a JVM primitive (or ``void``/``Not`` for the
    non-primitive sentinel).  The enum supports integer comparison via
    ``__int__``, and provides helpers for descriptor characters, boxing classes,
    storage sizes, and type properties.

    Example::

        pt = PrimitiveType.Int
        print(pt.descriptor())       # "I"
        print(pt.boxed_descriptor()) # "Ljava/lang/Integer;"
        print(pt.component_size())   # 4
        print(pt.is_numeric())       # True
        print(PrimitiveType.from_char("D"))  # PrimitiveType.Double
    """

    Not: "PrimitiveType"
    """Sentinel value - not a primitive type."""

    Boolean: "PrimitiveType"
    """Java ``boolean`` (descriptor ``Z``)."""

    Byte: "PrimitiveType"
    """Java ``byte`` (descriptor ``B``)."""

    Char: "PrimitiveType"
    """Java ``char`` (descriptor ``C``)."""

    Short: "PrimitiveType"
    """Java ``short`` (descriptor ``S``)."""

    Int: "PrimitiveType"
    """Java ``int`` (descriptor ``I``)."""

    Long: "PrimitiveType"
    """Java ``long`` (descriptor ``J``)."""

    Float: "PrimitiveType"
    """Java ``float`` (descriptor ``F``)."""

    Double: "PrimitiveType"
    """Java ``double`` (descriptor ``D``)."""

    Void: "PrimitiveType"
    """Java ``void`` (descriptor ``V``)."""

    def descriptor(self) -> Optional[str]:
        """Return the single-character JVM type descriptor, or ``None`` for ``Not``.

        :returns: Descriptor character string (e.g. ``"I"``), or ``None``.
        :rtype: str or None

        Example::

            PrimitiveType.Long.descriptor()  # "J"
        """
        ...

    def boxed_descriptor(self) -> Optional[str]:
        """Return the descriptor of the corresponding boxed class, or ``None`` for ``Not``.

        :returns: Descriptor string (e.g. ``"Ljava/lang/Integer;"``), or ``None``.
        :rtype: str or None

        Example::

            PrimitiveType.Int.boxed_descriptor()  # "Ljava/lang/Integer;"
        """
        ...

    def component_size(self) -> int:
        """Return the storage size of this type in bytes.

        :returns: Storage size: 1 for byte/boolean, 2 for char/short,
            4 for int/float, 8 for long/double, 0 for ``Not``/``Void``.
        :rtype: int

        Example::

            PrimitiveType.Double.component_size()  # 8
        """
        ...

    def is_numeric(self) -> bool:
        """Return ``True`` if this is a numeric primitive (i.e. not boolean, void, or Not).

        :returns: ``True`` for byte, char, short, int, long, float, double.
        :rtype: bool
        """
        ...

    def is_64bit(self) -> bool:
        """Return ``True`` for 64-bit primitives: ``long`` and ``double``.

        :returns: ``True`` for ``Long`` and ``Double``, ``False`` otherwise.
        :rtype: bool
        """
        ...

    def pretty_name(self) -> str:
        """Return the human-readable Java type name (e.g. ``"int"``, ``"double"``).

        :returns: Java keyword name of the primitive type.
        :rtype: str

        Example::

            PrimitiveType.Char.pretty_name()  # "char"
        """
        ...

    def __str__(self) -> str:
        """Return the human-readable Java type name (same as :meth:`pretty_name`).

        :rtype: str
        """
        ...

    def __int__(self) -> int:
        """Return the integer discriminant of this variant.

        :rtype: int
        """
        ...

    @staticmethod
    def from_char(c: str) -> "PrimitiveType":
        """Create a :class:`PrimitiveType` from a JVM descriptor character.

        Returns ``PrimitiveType.Not`` for unrecognised characters.

        :param c: Single JVM descriptor character (e.g. ``'I'``, ``'D'``).
        :type c: str
        :returns: Corresponding primitive type.
        :rtype: PrimitiveType

        Example::

            PrimitiveType.from_char("Z")  # PrimitiveType.Boolean
            PrimitiveType.from_char("?")  # PrimitiveType.Not
        """
        ...
