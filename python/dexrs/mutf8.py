from dexrs._internal import mutf8 as rust_mutf8


mutf8_to_str = rust_mutf8.mutf8_to_str
mutf8_to_str_lossy = rust_mutf8.mutf8_to_str_lossy
str_to_mutf8 = rust_mutf8.str_to_mutf8
str_to_mutf8_lossy = rust_mutf8.str_to_mutf8_lossy