"""Shared pytest fixtures for the dexrs test suite."""

import pathlib
import pytest

from dexrs import DexEditor

_ASSETS = pathlib.Path(__file__).parent.parent.parent / "tests"

PRIME_DEX_PATH = str(_ASSETS / "prime" / "prime.dex")
FIB_DEX_PATH   = str(_ASSETS / "fibonacci" / "fib.dex")


def prime_dex_bytes() -> bytes:
    return open(PRIME_DEX_PATH, "rb").read()


def fib_dex_bytes() -> bytes:
    return open(FIB_DEX_PATH, "rb").read()


@pytest.fixture
def prime_editor() -> DexEditor:
    return DexEditor.from_file(PRIME_DEX_PATH)


@pytest.fixture
def fib_editor() -> DexEditor:
    return DexEditor.from_file(FIB_DEX_PATH)
