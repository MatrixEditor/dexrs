from dexrs._internal import error as rust_error

PyDexError = rust_error.PyDexError

__all__ = ["PyDexError"]
