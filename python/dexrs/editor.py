"""Thin Python wrapper re-exporting :class:`DexEditor`.

:class:`DexEditor` provides targeted in-place mutations of a DEX file -
renaming classes, changing access flags, clearing hidden-API annotations -
without requiring a full re-assembly of the DEX.

The editor is **consumed** once :meth:`~DexEditor.build` or
:meth:`~DexEditor.write_to` is called; any further mutation raises
:exc:`IOError`.

Example::

    from dexrs.editor import DexEditor

    editor = DexEditor.from_file("classes.dex")
    editor.rename_class("LMain;", "LEntry;")
    editor.set_class_access_flags("LEntry;", 0x0001)   # public
    editor.clear_hiddenapi_flags()
    editor.write_to("classes_patched.dex")
"""
from dexrs._internal import editor as _rust_editor

DexEditor = _rust_editor.DexEditor

__all__ = ["DexEditor"]
