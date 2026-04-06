"""Tests for DexEditor (Python bindings)."""

import pathlib

import pytest

from dexrs import DexEditor, DexFile
import dexrs.container as container

from . import _util
from .conftest import PRIME_DEX_PATH, FIB_DEX_PATH, prime_dex_bytes, fib_dex_bytes


# -- helpers ------------------------------------------------------------------

def _reparse(data: bytes) -> DexFile:
    """Parse raw bytes and return a DexFile for assertions."""
    c = container.InMemoryDexContainer(data)
    return DexFile.from_bytes(c)


def _class_descriptor(dex: DexFile, idx: int = 0) -> str:
    cd = dex.get_class_def(idx)
    type_id = dex.get_type_id(cd.class_idx)
    return dex.get_utf16_at(type_id.descriptor_idx)


# -- from_file / from_bytes ----------------------------------------------------

def test_from_file_valid(prime_editor: DexEditor) -> None:
    assert prime_editor is not None


def test_from_bytes_valid() -> None:
    data = prime_dex_bytes()
    editor = DexEditor.from_bytes(data)
    assert editor is not None


def test_from_bytes_invalid_magic_raises() -> None:
    with pytest.raises(OSError):
        DexEditor.from_bytes(b"not a dex file at all")


def test_from_bytes_too_short_raises() -> None:
    with pytest.raises(OSError):
        DexEditor.from_bytes(b"\x00" * 10)


def test_from_file_missing_path_raises() -> None:
    with pytest.raises(OSError):
        DexEditor.from_file("/no/such/file.dex")


# -- build ---------------------------------------------------------------------

def test_build_returns_bytes(prime_editor: DexEditor) -> None:
    data = prime_editor.build()
    assert isinstance(data, bytes)
    assert len(data) == len(prime_dex_bytes())


def test_build_produces_parseable_dex(prime_editor: DexEditor) -> None:
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_header().version_int == 35


def test_write_to_creates_file(prime_editor: DexEditor, tmp_path: pathlib.Path) -> None:
    out = str(tmp_path / "out.dex")
    prime_editor.write_to(out)
    assert pathlib.Path(out).stat().st_size == len(prime_dex_bytes())


# -- set_class_access_flags ----------------------------------------------------

def test_set_class_flags_descriptor_form(prime_editor: DexEditor) -> None:
    prime_editor.set_class_access_flags("Lprime/prime;", 0x0011)
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0011


def test_set_class_flags_dotted_form(prime_editor: DexEditor) -> None:
    prime_editor.set_class_access_flags("prime.prime", 0x0001)
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0001


def test_set_class_flags_slash_form(prime_editor: DexEditor) -> None:
    prime_editor.set_class_access_flags("prime/prime", 0x0001)
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0001


def test_set_class_flags_unknown_class_raises(prime_editor: DexEditor) -> None:
    with pytest.raises(OSError):
        prime_editor.set_class_access_flags("Lno/such/Class;", 0x0001)


def test_set_class_flags_all_common_values(prime_editor: DexEditor) -> None:
    for flags in [0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0400]:
        editor = DexEditor.from_file(PRIME_DEX_PATH)
        editor.set_class_access_flags("Lprime/prime;", flags)
        data = editor.build()
        dex = _reparse(data)
        assert dex.get_class_def(0).access_flags == flags


# -- set_method_access_flags ---------------------------------------------------

def test_set_method_flags_main(prime_editor: DexEditor) -> None:
    prime_editor.set_method_access_flags("Lprime/prime;", "main", 0x0009)
    data = prime_editor.build()
    _reparse(data)  # must be parseable


def test_set_method_flags_init(prime_editor: DexEditor) -> None:
    prime_editor.set_method_access_flags("Lprime/prime;", "<init>", 0x10001)
    data = prime_editor.build()
    _reparse(data)


def test_set_method_flags_unknown_method_raises(prime_editor: DexEditor) -> None:
    with pytest.raises(OSError):
        prime_editor.set_method_access_flags("Lprime/prime;", "noSuchMethod", 0x0001)


def test_set_method_flags_unknown_class_raises(prime_editor: DexEditor) -> None:
    with pytest.raises(OSError):
        prime_editor.set_method_access_flags("Lno/such/Class;", "main", 0x0001)


# -- rename_class --------------------------------------------------------------

def test_rename_same_length(prime_editor: DexEditor) -> None:
    # "Lprime/prime;" (13) -> "Lprime/other;" (13)
    prime_editor.rename_class("Lprime/prime;", "Lprime/other;")
    data = prime_editor.build()
    dex = _reparse(data)
    assert _class_descriptor(dex) == "Lprime/other;"


def test_rename_same_length_old_gone(prime_editor: DexEditor) -> None:
    prime_editor.rename_class("Lprime/prime;", "Lprime/other;")
    data = prime_editor.build()
    assert b"Lprime/prime;" not in data


def test_rename_different_length_longer(prime_editor: DexEditor) -> None:
    original_size = len(prime_dex_bytes())
    prime_editor.rename_class("Lprime/prime;", "Lprime/renamed;")
    data = prime_editor.build()
    dex = _reparse(data)
    assert _class_descriptor(dex) == "Lprime/renamed;"
    assert len(data) > original_size


def test_rename_different_length_shorter(prime_editor: DexEditor) -> None:
    original_size = len(prime_dex_bytes())
    prime_editor.rename_class("Lprime/prime;", "La/b;")
    data = prime_editor.build()
    dex = _reparse(data)
    assert _class_descriptor(dex) == "La/b;"
    assert len(data) < original_size


def test_rename_unknown_class_raises(prime_editor: DexEditor) -> None:
    with pytest.raises(OSError):
        prime_editor.rename_class("Lno/such/Class;", "Lnew/name;")


def test_rename_dotted_form(prime_editor: DexEditor) -> None:
    prime_editor.rename_class("prime.prime", "prime.other")
    data = prime_editor.build()
    dex = _reparse(data)
    assert _class_descriptor(dex) == "Lprime/other;"


# -- clear_hiddenapi_flags -----------------------------------------------------

def test_clear_hiddenapi_noop_on_plain_dex(prime_editor: DexEditor) -> None:
    original_size = len(prime_dex_bytes())
    prime_editor.clear_hiddenapi_flags()  # no-op, must not raise
    data = prime_editor.build()
    assert len(data) == original_size


# -- chained mutations ---------------------------------------------------------

def test_chain_flags_and_rename(prime_editor: DexEditor) -> None:
    prime_editor.set_class_access_flags("Lprime/prime;", 0x0011)
    prime_editor.rename_class("Lprime/prime;", "Lprime/renamed;")
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0011
    assert _class_descriptor(dex) == "Lprime/renamed;"


def test_chain_rename_then_method_flags() -> None:
    editor = DexEditor.from_file(PRIME_DEX_PATH)
    editor.rename_class("Lprime/prime;", "Lprime/renamed;")
    editor.set_method_access_flags("Lprime/renamed;", "main", 0x0009)
    data = editor.build()
    _reparse(data)


def test_chain_method_and_class_flags(prime_editor: DexEditor) -> None:
    prime_editor.set_class_access_flags("Lprime/prime;", 0x0011)
    prime_editor.set_method_access_flags("Lprime/prime;", "main", 0x0009)
    prime_editor.clear_hiddenapi_flags()
    data = prime_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0011


# -- fibonacci DEX -------------------------------------------------------------

def test_fib_set_flags(fib_editor: DexEditor) -> None:
    fib_editor.set_class_access_flags("fibonacci.fib", 0x0011)
    data = fib_editor.build()
    dex = _reparse(data)
    assert dex.get_class_def(0).access_flags == 0x0011


def test_fib_rename(fib_editor: DexEditor) -> None:
    fib_editor.rename_class("fibonacci.fib", "fib.renamed")
    data = fib_editor.build()
    dex = _reparse(data)
    assert _class_descriptor(dex) == "Lfib/renamed;"
