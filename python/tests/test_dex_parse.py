import dexrs
import pytest

from dexrs.error import PyDexError

from . import _util


def test_parse_invalid_dex() -> None:
    with pytest.raises(PyDexError):
        data = dexrs.container.InMemoryDexContainer(b"...")
        dexrs.DexFile.from_bytes(data)


def test_parse_valid_dex() -> None:
    path = _util.get_asset("prime/prime.dex")
    data = dexrs.container.FileDexContainer(str(path))
    dex = dexrs.DexFile.from_file(data)

    for i in range(dex.num_class_defs()):
        class_def = dex.get_class_def(i)
        class_a = dex.get_class_accessor(class_def)
        for method in class_a.get_methods():
            if method.code_offset == 0:
                continue

            code_a = dex.get_code_item_accessor(method.code_offset)
            for insn in code_a.insns():
                pass

    assert dex.get_header().version_int == 35
