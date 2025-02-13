import dexrs
import pytest

from . import _util


def test_parse_invalid_dex() -> None:
    with pytest.raises(dexrs.PyDexError):
        data = dexrs.InMemoryDexContainer(b"...")
        dexrs.DexFile.from_bytes(data)


def test_parse_valid_dex() -> None:
    path = _util.get_asset("prime/prime.dex")
    data = dexrs.FileDexContainer(str(path))
    dex = dexrs.DexFile.from_file(data)

    assert dex.get_header().version_int == 35
