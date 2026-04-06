"""Type stubs for the ``dexrs._internal.container`` native extension module.

A *container* is the backing store that supplies raw DEX bytes to
:class:`~dexrs._internal.file.DexFile`.  Choose the variant that best fits
where your DEX data lives.
"""

import abc

class DexContainer(abc.ABC):
    """Abstract base class for DEX backing stores.

    .. deprecated::
        Prefer :class:`InMemoryDexContainer` or :class:`FileDexContainer`
        directly.  This ABC is retained for compatibility only.
    """

    def data(self) -> bytes:
        """Return the raw DEX bytes held by this container."""
        ...

    @property
    @abc.abstractmethod
    def file_size(self) -> int:
        """Total size of the DEX image in bytes."""
        ...

class InMemoryDexContainer:
    """A container that wraps an in-memory ``bytes`` buffer.

    The bytes are copied on construction and owned by the container for the
    lifetime of any :class:`~dexrs._internal.file.DexFile` that references it.

    Example::

        with open("classes.dex", "rb") as f:
            container = InMemoryDexContainer(f.read())
    """

    def __init__(self, data: bytes) -> None:
        """Construct from a raw DEX byte string.

        :param data: Raw bytes of a valid ``.dex`` file.
        """
        ...

    def data(self) -> bytes:
        """Return the raw DEX bytes held by this container."""
        ...

    @property
    def file_size(self) -> int:
        """Total size of the DEX image in bytes."""
        ...

    def __len__(self) -> int:
        """Return the number of bytes in the container (same as :attr:`file_size`)."""
        ...

class FileDexContainer:
    """A container that memory-maps a DEX file on disk (zero-copy reads).

    The file is kept open and mapped for the lifetime of the container.

    Example::

        container = FileDexContainer("classes.dex")
        print(container.location)   # "classes.dex"
        print(container.file_size)  # size in bytes
    """

    def __init__(self, path: str) -> None:
        """Open and memory-map the DEX file at *path*.

        :param path: Filesystem path to a ``.dex`` file.
        :raises IOError: If the file cannot be opened or mapped.
        """
        ...

    def data(self) -> bytes:
        """Return the memory-mapped DEX bytes as a ``bytes`` view."""
        ...

    @property
    def file_size(self) -> int:
        """Total size of the mapped file in bytes."""
        ...

    @property
    def location(self) -> str:
        """The filesystem path that was passed to the constructor."""
        ...

    def __len__(self) -> int:
        """Return the number of bytes in the container (same as :attr:`file_size`)."""
        ...
