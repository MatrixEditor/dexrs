"""Type stubs for the ``dexrs._internal`` native extension package.

Sub-modules exposed by the Rust extension:

- :mod:`dexrs._internal.annotation` - class annotation accessors
- :mod:`dexrs._internal.class_accessor` - class data iterators
- :mod:`dexrs._internal.code` - instructions, opcodes, and operand accessors
- :mod:`dexrs._internal.container` - DEX container types (memory / file)
- :mod:`dexrs._internal.editor` - mutable DEX editor
- :mod:`dexrs._internal.error` - :exc:`PyDexError` exception type
- :mod:`dexrs._internal.leb128` - LEB128 varint decoders
- :mod:`dexrs._internal.mutf8` - MUTF-8 / UTF-16 conversion utilities
- :mod:`dexrs._internal.primitive` - Java primitive-type enum
- :mod:`dexrs._internal.structs` - plain-data structs mirroring DEX on-disk layout
- :mod:`dexrs._internal.type_lookup_table` - O(1) type-descriptor lookup table
"""

from . import annotation as annotation
from . import class_accessor as class_accessor
from . import code as code
from . import container as container
from . import editor as editor
from . import error as error
from . import leb128 as leb128
from . import mutf8 as mutf8
from . import primitive as primitive
from . import structs as structs
from . import type_lookup_table as type_lookup_table
