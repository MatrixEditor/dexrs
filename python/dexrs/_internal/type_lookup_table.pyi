"""Type stubs for the ``dexrs._internal.type_lookup_table`` native extension module."""

from typing import Optional


class TypeLookupTable:
    """Fast O(1) class-descriptor -> class-def-index lookup table.

    Build from a :class:`~dexrs.DexFile` via
    :meth:`~dexrs.DexFile.build_type_lookup_table`.  Lookups use a hash table
    over the descriptor strings, giving constant-time performance regardless of
    how many classes are defined.

    Example::

        tlt = dex.build_type_lookup_table()
        idx = tlt.lookup("Ljava/lang/String;")
        if idx is not None:
            class_def = dex.get_class_def(idx)
    """

    def lookup(self, descriptor: str) -> Optional[int]:
        """Return the ``class_def_idx`` for *descriptor*, or ``None`` if absent.

        *descriptor* must be in DEX format (e.g. ``"Ljava/lang/String;"``).

        :param descriptor: Type descriptor to look up.
        :type descriptor: str
        :returns: The zero-based class-definition index, or ``None``.
        :rtype: int or None

        Example::

            idx = tlt.lookup("Lcom/example/Foo;")
            if idx is not None:
                print(f"Found at class_def index {idx}")
        """
        ...

    def __len__(self) -> int:
        """Return the number of class descriptors in the table.

        :returns: Total number of classes indexed.
        :rtype: int
        """
        ...

    def __contains__(self, descriptor: str) -> bool:
        """Return ``True`` if *descriptor* is present in the table.

        :param descriptor: Type descriptor to test.
        :type descriptor: str
        :returns: ``True`` if found, ``False`` otherwise.
        :rtype: bool

        Example::

            if "Ljava/lang/Object;" in tlt:
                print("Object class is defined")
        """
        ...

    def __repr__(self) -> str:
        """Return a developer-friendly string representation.

        :returns: String of the form ``TypeLookupTable(<n> classes)``.
        :rtype: str
        """
        ...
