"""Type stubs for the ``dexrs._internal.editor`` native extension module."""


class DexEditor:
    """Mutable DEX file editor backed by the Rust ``DexEditor`` implementation.

    Construct an editor from a file path or raw bytes, apply zero or more
    mutations, then call :meth:`build` or :meth:`write_to` to finalise.
    The editor is **consumed** by :meth:`build` or :meth:`write_to` - any
    subsequent call will raise :exc:`IOError`.

    Example::

        editor = DexEditor.from_file("classes.dex")
        editor.rename_class("LMain;", "LEntry;")
        editor.set_class_access_flags("LEntry;", 0x0001)
        editor.write_to("classes_patched.dex")
    """

    @staticmethod
    def from_file(path: str) -> "DexEditor":
        """Open a DEX file from *path* and return a new editor.

        :param path: Filesystem path to the ``.dex`` file.
        :type path: str
        :returns: A new :class:`DexEditor` backed by the file on disk.
        :rtype: DexEditor
        :raises IOError: If the file cannot be opened or parsed.

        Example::

            editor = DexEditor.from_file("classes.dex")
        """
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "DexEditor":
        """Construct a :class:`DexEditor` from raw DEX *data*.

        :param data: Raw bytes of a valid ``.dex`` file.
        :type data: bytes
        :returns: A new :class:`DexEditor` backed by an in-memory copy of *data*.
        :rtype: DexEditor
        :raises IOError: If *data* cannot be parsed as a DEX file.

        Example::

            with open("classes.dex", "rb") as f:
                editor = DexEditor.from_bytes(f.read())
        """
        ...

    def set_class_access_flags(self, class_desc: str, flags: int) -> None:
        """Replace the access flags of *class_desc* with *flags*.

        *class_desc* is accepted in dotted (``com.example.Foo``), slash
        (``com/example/Foo``), or descriptor (``Lcom/example/Foo;``) form.

        :param class_desc: Class name in any supported notation.
        :type class_desc: str
        :param flags: New ``access_flags`` bitmask (e.g. ``0x0001`` for public).
        :type flags: int
        :raises IOError: If the class cannot be found or the editor is consumed.

        Example::

            editor.set_class_access_flags("com.example.Foo", 0x0001)  # public
        """
        ...

    def set_method_access_flags(
        self, class_desc: str, method_name: str, flags: int
    ) -> None:
        """Replace the access flags of *method_name* inside *class_desc*.

        LEB128 re-encoding is handled automatically when the encoded width of
        *flags* differs from the original.

        :param class_desc: Owning class name in any supported notation.
        :type class_desc: str
        :param method_name: Simple method name (no signature).
        :type method_name: str
        :param flags: New ``access_flags`` bitmask.
        :type flags: int
        :raises IOError: If the class or method cannot be found, or the editor
            is consumed.

        Example::

            editor.set_method_access_flags("LMain;", "run", 0x0001)  # public
        """
        ...

    def clear_hiddenapi_flags(self) -> None:
        """Zero out the ``HiddenapiClassData`` section and remove its map entry.

        Useful when the patched DEX is loaded by a runtime that rejects
        hidden-API annotations.

        :raises IOError: If the editor is already consumed.

        Example::

            editor.clear_hiddenapi_flags()
        """
        ...

    def rename_class(self, old_name: str, new_name: str) -> None:
        """Rename a class, updating the string pool, type references, and checksum.

        Both *old_name* and *new_name* accept dotted, slash, or descriptor form.

        :param old_name: Current class name.
        :type old_name: str
        :param new_name: Desired class name.
        :type new_name: str
        :raises IOError: If the class cannot be found or the editor is consumed.

        Example::

            editor.rename_class("LMain;", "LRenamedMain;")
        """
        ...

    def build(self) -> bytes:
        """Finalise all edits, recalculate the Adler32 checksum, and return the
        modified DEX as :class:`bytes`.

        The editor is **consumed** by this call; further mutations will raise
        :exc:`IOError`.

        :returns: Complete, checksum-correct DEX image.
        :rtype: bytes
        :raises IOError: If finalisation fails or the editor is already consumed.

        Example::

            data = editor.build()
            with open("out.dex", "wb") as f:
                f.write(data)
        """
        ...

    def write_to(self, path: str) -> None:
        """Finalise all edits and write the modified DEX directly to *path*.

        The editor is **consumed** by this call; further mutations will raise
        :exc:`IOError`.

        :param path: Destination file path.
        :type path: str
        :raises IOError: If writing fails or the editor is already consumed.

        Example::

            editor.write_to("out.dex")
        """
        ...
