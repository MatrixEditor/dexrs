"""Tests for the dexrs.builder Python bindings."""

from __future__ import annotations

import struct

import pytest

import dexrs
from dexrs._internal import builder as b

DEX_MAGIC = b"dex\n035\x00"


def make_class(descriptor: str, *, access: int = 0x0001, superclass: str = "Ljava/lang/Object;") -> b.IrClassDef:
    cls = b.IrClassDef(descriptor)
    cls.set_access(access)
    cls.set_superclass(superclass)
    return cls


# -- DexIrBuilder -------------------------------------------------------------


def test_empty_dex_has_correct_magic():
    ir = b.DexIrBuilder(35)
    data = ir.write()
    assert data[:8] == DEX_MAGIC


def test_empty_dex_minimum_size():
    ir = b.DexIrBuilder(35)
    data = ir.write()
    assert len(data) >= 112


def test_empty_dex_file_size_field():
    ir = b.DexIrBuilder(35)
    data = ir.write()
    file_size = struct.unpack_from("<I", data, 32)[0]
    assert file_size == len(data)


def test_class_count_reflects_adds():
    ir = b.DexIrBuilder(35)
    assert ir.class_count() == 0
    ir.add_class(make_class("Lcom/example/A;"))
    assert ir.class_count() == 1
    ir.add_class(make_class("Lcom/example/B;"))
    assert ir.class_count() == 2


# -- IrClassDef ----------------------------------------------------------------


def test_single_empty_class_produces_one_class_def():
    ir = b.DexIrBuilder(35)
    ir.add_class(make_class("Lcom/example/Empty;"))
    data = ir.write()
    class_defs_size = struct.unpack_from("<I", data, 96)[0]
    assert class_defs_size == 1


def test_class_defs_count_matches_added():
    ir = b.DexIrBuilder(35)
    for i in range(5):
        ir.add_class(make_class(f"Lcom/example/Class{i};"))
    data = ir.write()
    assert struct.unpack_from("<I", data, 96)[0] == 5


def test_class_with_static_field():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/WithField;")
    cls.add_static_field("TAG", "Ljava/lang/String;", 0x0019)  # public static final
    ir.add_class(cls)
    data = ir.write()
    assert len(data) > 0
    field_ids_size = struct.unpack_from("<I", data, 80)[0]
    assert field_ids_size >= 1


def test_class_with_instance_field():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/WithInstField;")
    cls.add_instance_field("value", "I", 0x0002)  # private
    ir.add_class(cls)
    data = ir.write()
    field_ids_size = struct.unpack_from("<I", data, 80)[0]
    assert field_ids_size >= 1


def test_class_with_interface():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/Impl;")
    cls.add_interface("Lcom/example/IFoo;")
    ir.add_class(cls)
    data = ir.write()
    assert len(data) > 0


# -- IrMethodDef + CodeBuilder -------------------------------------------------


def test_class_with_empty_init():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/Hello;")

    code = b.CodeBuilder(1, 0, 0)
    code.emit("return-void")
    m = b.IrMethodDef("<init>", "()V", 0x10001)  # public constructor
    m.set_code(code.build())
    cls.add_direct_method(m)

    ir.add_class(cls)
    data = ir.write()
    assert data[:8] == DEX_MAGIC
    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    assert method_ids_size >= 1


def test_method_with_string_ref():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/StringTest;")

    code = b.CodeBuilder(3, 0, 1)
    code.emit("sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;")
    code.emit('const-string v1, "Hello, World!"')
    code.emit("invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V")
    code.emit("return-void")
    m = b.IrMethodDef("main", "([Ljava/lang/String;)V", 0x0009)
    m.set_code(code.build())
    cls.add_direct_method(m)

    ir.add_class(cls)
    data = ir.write()
    # String pool must contain at least "Hello, World!"
    string_ids_size = struct.unpack_from("<I", data, 56)[0]
    assert string_ids_size > 0


def test_code_builder_label_and_branch():
    code = b.CodeBuilder(2, 0, 0)
    code.emit("const/4 v0, #0")
    code.label("loop_top")
    code.emit("if-eqz v0, :loop_top")
    code.emit("return-void")
    code_def = code.build()
    assert code_def is not None


def test_static_method():
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/Static;")

    code = b.CodeBuilder(1, 0, 0)
    code.emit("const/4 v0, #42")
    code.emit("return v0")
    m = b.IrMethodDef("getAnswer", "()I", 0x0009)  # public static
    m.set_code(code.build())
    cls.add_direct_method(m)

    ir.add_class(cls)
    data = ir.write()
    assert len(data) > 0


# -- ProtoKey ------------------------------------------------------------------


def test_proto_key_from_descriptor_returns_types():
    pk = b.ProtoKey.from_descriptor("(IIZ)Ljava/lang/String;")
    assert pk.return_type == "Ljava/lang/String;"
    assert pk.params == ["I", "I", "Z"]


def test_proto_key_void_return():
    pk = b.ProtoKey.from_descriptor("()V")
    assert pk.return_type == "V"
    assert pk.params == []


def test_proto_key_shorty_primitives():
    pk = b.ProtoKey.from_descriptor("(IZ)I")
    assert pk.shorty() == "IIZ"


# -- Round-trip ----------------------------------------------------------------


def test_write_produces_parseable_dex():
    """Write DEX bytes then parse them back with dexrs DexFile.from_bytes."""
    ir = b.DexIrBuilder(35)
    cls = make_class("Lcom/example/RoundTrip;")

    code = b.CodeBuilder(1, 0, 0)
    code.emit("return-void")
    m = b.IrMethodDef("<init>", "()V", 0x10001)
    m.set_code(code.build())
    cls.add_direct_method(m)
    ir.add_class(cls)

    data = ir.write()
    container = dexrs.InMemoryDexContainer(data)
    dex_file = dexrs.DexFile.from_bytes(container)
    assert dex_file.num_class_defs() == 1


def test_write_bytes_type():
    ir = b.DexIrBuilder(35)
    data = ir.write()
    assert isinstance(data, bytes)
