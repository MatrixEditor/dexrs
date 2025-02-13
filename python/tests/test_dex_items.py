import dexrs
import pytest

from . import _util


def test_get_type_id() -> None:
    dex = _util.PRIME_DEX
    type_id = dex.get_type_id(0)
    # pre-computed values
    assert type_id.descriptor_idx == 3


def test_get_type_desc() -> None:
    dex = _util.PRIME_DEX
    type_id = dex.get_type_id(0)
    # query type descriptor for type id
    descriptor = dex.get_utf16_at(type_id.descriptor_idx)
    assert descriptor == "I"

def test_invalid_type_id_idx() -> None:
    dex = _util.PRIME_DEX
    index = 0xFFFF # max of u16

    # no error if optional
    assert dex.get_type_id_opt(index) is None

    # error otherwise
    with pytest.raises(dexrs.PyDexError):
        dex.get_type_id(index)
