import pytest

from dexrs.mutf8 import (
    mutf8_to_str,
    mutf8_to_str_lossy,
    str_to_mutf8,
    str_to_mutf8_lossy,
)
from dexrs.error import PyDexError


def test_parse_valid_mutf8() -> None:
    data = b"foobar\0"  # trailing null byte is mandatory

    assert mutf8_to_str(data) == "foobar"
    assert str_to_mutf8("foobar") == b"foobar\0"


# REVISIT: add surrogate examples
def test_parse_valid_mutf8_lossy() -> None:
    data = b"foobar\0"  # trailing null byte is mandatory

    assert mutf8_to_str_lossy(data) == "foobar"
    assert str_to_mutf8_lossy("foobar") == b"foobar\0"


def test_parse_invalid_mutf8() -> None:
    with pytest.raises(PyDexError):
        mutf8_to_str(b"0x00")  # missing null byte
