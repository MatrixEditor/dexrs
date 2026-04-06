"""DEX mutation system: build new DEX files from scratch.

Classes
-------
- :class:`DexIrBuilder` - Assemble a full DEX file from class definitions.
- :class:`IrClassDef`   - Define a class (fields, methods, superclass…).
- :class:`IrMethodDef`  - Define a method with optional bytecode body.
- :class:`IrFieldDef`   - Define a field (convenience; usually use the
  ``add_*_field`` methods on :class:`IrClassDef`).
- :class:`CodeBuilder`  - Assemble Dalvik bytecode from disassembly text lines.
- :class:`CodeDef`      - An assembled code item (return value of
  :meth:`CodeBuilder.build`).
- :class:`ProtoKey`     - Method prototype (return type + parameter types).

Quick-start
-----------
::

    from dexrs.builder import DexIrBuilder, IrClassDef, IrMethodDef, CodeBuilder

    cls = IrClassDef("Lhello/World;")
    cls.set_access(0x0001)            # ACC_PUBLIC
    cls.set_superclass("Ljava/lang/Object;")

    code = CodeBuilder(registers=3, ins=1, outs=2)
    code.emit('sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;')
    code.emit('const-string v1, "Hello!"')
    code.emit('invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V')
    code.emit('return-void')

    method = IrMethodDef("main", "([Ljava/lang/String;)V", 0x0009)
    method.set_code(code.build())
    cls.add_direct_method(method)

    builder = DexIrBuilder(version=35)
    builder.add_class(cls)
    dex_bytes = builder.write()     # -> bytes
"""
from dexrs._internal import builder as _b

DexIrBuilder = _b.DexIrBuilder
IrClassDef = _b.IrClassDef
IrMethodDef = _b.IrMethodDef
IrFieldDef = _b.IrFieldDef
CodeBuilder = _b.CodeBuilder
CodeDef = _b.CodeDef
ProtoKey = _b.ProtoKey

__all__ = [
    "DexIrBuilder",
    "IrClassDef",
    "IrMethodDef",
    "IrFieldDef",
    "CodeBuilder",
    "CodeDef",
    "ProtoKey",
]
