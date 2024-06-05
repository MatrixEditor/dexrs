use std::io::Write;
use std::rc::Rc;

use crate::dalvik::dex::{AccessFlags, DexType, FieldIdItem, MethodIdItem};
use crate::dalvik::error::Result;
use crate::dalvik::file::annotation::DexAnnotation;
use crate::dalvik::file::field::DexField;
use crate::dalvik::file::method::DexMethod;
use crate::dalvik::file::DexClassDef;
use crate::dalvik::file::{method::DexPrototype, DexValue, IDexRef};
use crate::dalvik::insns::{self, Index, Insn, InsnFormat, Payload};

// A small hack to implement write_* operations for all
// `Write` types.
impl<W: std::io::Write> SmaliWrite for W {}

pub trait SmaliWrite: Write {
    //TODO: docs

    fn write_access_flags(&mut self, access_flags: &AccessFlags) -> Result<()> {
        // Access flags are written using their lowercase names
        access_flags
            .iter_names()
            .map(|(x, _)| x.to_lowercase())
            .try_for_each(|f| write!(self, "{} ", f))?;
        Ok(())
    }

    fn write_type(&mut self, type_: &DexType) -> Result<()> {
        if type_.dim > 0 {
            write!(self, "{}", "[".repeat(type_.dim))?;
        }
        write!(self, "{}", type_.descriptor)?;
        Ok(())
    }

    fn write_field_ref(&mut self, ref_: &Rc<FieldIdItem>, dex: IDexRef<'_>) -> Result<()> {
        // class->field_name:field_type
        let class = dex.get_type(ref_.class_idx as u32)?;
        let name = dex.get_string(ref_.name_idx)?;
        let type_ = dex.get_type(ref_.type_idx as u32)?;
        self.write_type(&class)?;
        write!(self, "->{}:", name)?;
        self.write_type(&type_)?;
        Ok(())
    }

    fn write_method_ref(&mut self, ref_: &Rc<MethodIdItem>, dex: IDexRef<'_>) -> Result<()> {
        // class->method_name|method_descriptor
        let class = dex.get_type(ref_.class_idx as u32)?;
        let name = dex.get_string(ref_.name_idx)?;
        let type_ = dex.get_proto(ref_.proto_idx as u32)?;
        self.write_type(&class)?;
        write!(self, "->{}", name)?;
        self.write_proto(&type_)?;
        Ok(())
    }

    fn write_proto(&mut self, proto: &DexPrototype) -> Result<()> {
        // (param_types) return_type
        write!(self, "(")?;
        for param in proto.parameters.iter() {
            self.write_type(param)?;
        }
        write!(self, ")")?;
        self.write_type(&proto.return_type)?;
        Ok(())
    }

    fn write_value(&mut self, value: &DexValue, dex: IDexRef<'_>) -> Result<()> {
        match value {
            DexValue::String(v) => write!(self, "\"{}\"", v.escape_default())?,
            DexValue::Type(v) => self.write_type(v)?,
            DexValue::FieldRef(v) => self.write_field_ref(v, dex)?,
            DexValue::MethodRef(.., v) => self.write_method_ref(v, dex)?,
            DexValue::MethodType(v) => self.write_proto(v)?,
            DexValue::Int(v) => write!(self, "{:#x}", v)?,
            DexValue::Float(v) => write!(self, "{}", v)?,
            DexValue::Long(v) => write!(self, "{:#x}", v)?,
            DexValue::Double(v) => write!(self, "{}", v)?,
            DexValue::True => write!(self, "true")?,
            DexValue::False => write!(self, "false")?,
            DexValue::Null => write!(self, "null")?,
            DexValue::Array(v) => {
                write!(self, "[")?;
                for (i, value) in v.iter().enumerate() {
                    self.write_value(value, dex)?;
                    if i != v.len() - 1 {
                        write!(self, ", ")?;
                    }
                }
                write!(self, "]")?;
            }
            DexValue::Data(v, _) => write!(self, "<data={}>", v)?,
            DexValue::Char(v) => write!(self, "'{}'", v.escape_default())?,
            DexValue::Short(v) => write!(self, "{:#x}", v)?,
            DexValue::Byte(v) => write!(self, "{:#x}", v)?,
            // DexValue::Annotation(v) => self.w,
            DexValue::Enum(v) => {
                self.write_field_ref(v, dex)?;
            }
            _ => write!(self, "{:?}", value)?,
        }
        Ok(())
    }

    fn write_index(&mut self, index: &Index, dex: IDexRef<'_>) -> Result<()> {
        match index {
            Index::Literal(a) => write!(self, "{:#x}", a)?,
            Index::Field(a) => {
                self.write_field_ref(a, dex)?;
            }
            Index::Method(a) => {
                self.write_method_ref(a, dex)?;
            }
            Index::Proto(a) => {
                // (arg_type)return_type
                self.write_proto(a)?;
            }
            Index::Type(a) => {
                // type_name:field_type
                write!(self, "{}", a)?;
            }
            Index::String(a) => {
                write!(self, "\"{}\"", a.escape_default())?;
            }
            _ => {
                // TODO
                write!(self, "{:?}", index)?;
            }
        }
        Ok(())
    }

    fn write_insn(&mut self, insn: &Insn, dex: IDexRef<'_>, indent: usize) -> Result<()> {
        let indent_val = "    ".repeat(indent);
        write!(self, "{}", indent_val)?;
        if let Some(payload) = &insn.payload {
            let indent2 = "    ".repeat(indent + 1);
            match payload {
                Payload::FillArrayData(data) => {
                    write!(self, ".array-data {:#x} {:#x}", data.width, data.size)?;
                    for v in data.data.iter() {
                        writeln!(self, "{}{:#x}", indent2, v)?;
                    }
                    write!(self, ".end array-data")?;
                }
                Payload::PackedSwitch(pswitch) => {
                    writeln!(self, ".packed-switch {:#x}", pswitch.first_key)?;
                    for v in pswitch.targets.iter() {
                        writeln!(self, "{}{:#x}", indent2, v)?;
                    }
                    writeln!(self, "{}.end packed-switch", indent_val)?;
                }
                Payload::SparseSwitch(switch) => {
                    writeln!(self, ".sparse-switch")?;
                    for (key, target) in switch.keys.iter().zip(switch.targets.iter()) {
                        write!(self, "{}{:#x} -> {:#x}", indent2, key, target)?;
                    }
                    writeln!(self, "{}.end sparse-switch", indent_val)?;
                }
            }
            Ok(())
        } else {
            write!(self, "{}", insn.opcode.name)?;
            if insn.opcode.length > 0 {
                write!(self, " ")?;
            }
            match &insn.format {
                // N/A
                InsnFormat::Format00x => {
                    write!(self, "<invalid>")?;
                }
                InsnFormat::Format10x => { /* op */ }

                InsnFormat::Format12x { a, b } => {
                    write!(self, "v{}, v{}", a, b)?; // op vA, vB
                }
                InsnFormat::Format11n { a, b } => {
                    write!(self, "v{}, {:?}", a, b)?; // op vA, #+B
                }
                InsnFormat::Format11x { a } => {
                    write!(self, "v{}", a)?; // op vAA
                }
                InsnFormat::Format10t { a } => {
                    write!(self, "{}", a)?; // op +AA
                }
                InsnFormat::Format20t { a } => {
                    write!(self, "{}", a)?; // op +AAAA
                }
                InsnFormat::Format22x { a, b } => {
                    write!(self, "v{}, v{}", a, b)?; // op vAA, vBBBB
                }
                InsnFormat::Format21t { a, b } => {
                    write!(self, "v{}, {}", a, b)?; // op vAA, +BBBB
                }
                InsnFormat::Format21s { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAA, +BBBB
                    self.write_index(b, dex)?;
                }
                InsnFormat::Format21h { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAA, +BBBB0000
                    self.write_index(b, dex)?;
                }
                InsnFormat::Format21c { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAA, kind@BBBB
                    self.write_index(b, dex)?;
                }
                InsnFormat::Format23x { a, b, c } => {
                    write!(self, "v{}, v{}, v{}", a, b, c)?; // op vAA, vBB, vCC
                }
                InsnFormat::Format22b { a, b, c } => {
                    write!(self, "v{}, v{}, ", a, b)?; // op vAA, vBB, #+CC
                    self.write_index(c, dex)?;
                }
                InsnFormat::Format22t { a, b, c } => {
                    write!(self, "v{}, v{}, {}", a, b, c)?; // op vAA, vBB, +CCCC
                }
                InsnFormat::Format22s { a, b, c } => {
                    write!(self, "v{}, v{}, ", a, b)?; // op vAA, vBB, +CCCC
                    self.write_index(c, dex)?;
                }
                InsnFormat::Format22c { a, b, c } => {
                    write!(self, "v{}, v{}, ", a, b)?; // op vAA, vBB, kind@CCCC
                    self.write_index(c, dex)?;
                }
                InsnFormat::Format30t { a } => {
                    write!(self, "{}", a)?; // op +AAAAAAAA
                }
                InsnFormat::Format32x { a, b } => {
                    write!(self, "v{}, v{}", a, b)?; // op vAAAA, vBBBB
                }
                InsnFormat::Format31i { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAA, #+BBBBBBBB
                    self.write_index(b, dex)?;
                }
                InsnFormat::Format31t { a, b } => {
                    write!(self, "v{}, {}", a, b)?; // op vAAAA, +BBBB
                }
                InsnFormat::Format31c { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAAAA, kind@BBBB
                    self.write_index(b, dex)?;
                }

                InsnFormat::Format35c {
                    a,
                    b,
                    c,
                    d,
                    e,
                    f,
                    g,
                } => {
                    // [A=n] op {vX...vN}, kind@BBBB
                    write!(self, "{{")?;
                    match a {
                        1 => write!(self, "v{}", c)?,
                        2 => write!(self, "v{}, v{}", c, d)?,
                        3 => write!(self, "v{}, v{}, v{}", c, d, e)?,
                        4 => write!(self, "v{}, v{}, v{}, v{}", c, d, e, f)?,
                        5 => write!(self, "v{}, v{}, v{}, v{}, v{}", c, d, e, f, g)?,
                        _ => {}
                    }
                    write!(self, "}}, ")?;
                    self.write_index(b, dex)?;
                }

                InsnFormat::Format3rc {
                    a: _,
                    b,
                    c: _,
                    regs,
                } => {
                    // [A=n] op {vX...vN}, kind@BBBB
                    write!(self, "{{")?;
                    for i in regs.start..regs.end {
                        write!(self, "v{}", i)?;
                        if i != regs.end {
                            write!(self, ", ")?;
                        }
                    }
                    write!(self, "}}, ")?;
                    self.write_index(b, dex)?;
                }

                InsnFormat::Format45cc {
                    a,
                    b,
                    c,
                    d,
                    e,
                    f,
                    g,
                    h,
                } => {
                    // [A=n] op {vX...vN}, kind@BBBB, proto@HHHH
                    write!(self, "{{")?;
                    match a {
                        1 => write!(self, "v{}", c)?,
                        2 => write!(self, "v{}, v{}", c, d)?,
                        3 => write!(self, "v{}, v{}, v{}", c, d, e)?,
                        4 => write!(self, "v{}, v{}, v{}, v{}", c, d, e, f)?,
                        5 => write!(self, "v{}, v{}, v{}, v{}, v{}", c, d, e, f, g)?,
                        _ => {}
                    }
                    write!(self, "}}, ")?;
                    self.write_index(b, dex)?;
                    write!(self, ", ")?;
                    self.write_index(h, dex)?;
                }

                InsnFormat::Format4rcc {
                    a: _,
                    b,
                    c: _,
                    h,
                    regs,
                } => {
                    // [A=n] op {vX...vN}, kind@BBBB, proto@HHHH
                    write!(self, "{{")?;
                    for i in regs.start..regs.end {
                        write!(self, "v{}", i)?;
                        if i != regs.end {
                            write!(self, ", ")?;
                        }
                    }
                    write!(self, "}}, ")?;
                    self.write_index(b, dex)?;
                    write!(self, ", ")?;
                    self.write_index(h, dex)?;
                }

                InsnFormat::Format51l { a, b } => {
                    write!(self, "v{}, ", a)?; // op vAA, +BBBBBBBB
                    self.write_index(b, dex)?;
                }

                _ => {
                    write!(self, "{}", "<not-implemented>")?;
                }
            }
            return Ok(());
        }
    }

    // --- implementation for multiline content ---

    /// Writes an annotation to the underlying stream using the given
    /// indent. This method uses '.subannotation' if is_sub is true.
    fn write_annotation(
        &mut self,
        annotation: &DexAnnotation,
        dex: IDexRef<'_>,
        indent: usize,
        is_sub: bool,
    ) -> Result<()> {
        let indent_val = "    ".repeat(indent);
        if is_sub {
            write!(self, "{}.subannotation ", indent_val)?;
        } else {
            write!(self, "{}.annotation ", indent_val)?;
        }

        // <visibility> <type>
        if let Some(visibility) = &annotation.visibility {
            write!(self, "{} ", format!("{:?}", visibility).to_lowercase())?;
        }
        self.write_type(&annotation.type_)?;

        // possible values
        if !annotation.values.is_empty() {
            let indent2 = "    ".repeat(indent + 1);
            for (key, value) in annotation.values.iter() {
                write!(self, "\n{}{} = ", indent2, key)?;
                match value {
                    //  let us format annotations with sub-annotations
                    DexValue::Annotation(a) => self.write_annotation(a, dex, indent + 2, true)?,
                    DexValue::Array(a) => {
                        writeln!(self, "[")?;
                        let indent3 = "    ".repeat(indent + 2);
                        for (i, v) in a.iter().enumerate() {
                            write!(self, "{}", indent3)?;
                            self.write_value(v, dex)?;
                            if i != a.len() - 1 {
                                writeln!(self, ",")?;
                            }
                        }
                        write!(self, "\n{}]", indent2)?;
                    }
                    _ => self.write_value(value, dex)?,
                }
            }
        }

        if is_sub {
            write!(self, "\n{}.end subannotation", indent_val)?;
        } else {
            write!(self, "\n{}.end annotation", indent_val)?;
        }

        Ok(())
    }
    /// Writes a field to the underlying stream.
    fn write_field(&mut self, field: &DexField, dex: IDexRef<'_>) -> Result<()> {
        write!(self, ".field ")?;
        if let Some(flags) = &field.access_flags {
            self.write_access_flags(flags)?;
        }
        write!(self, "{}:", field.name)?;
        self.write_type(&field.type_)?;

        if let Some(init_val) = &field.init_value {
            write!(self, " = ")?;
            self.write_value(&init_val, dex)?;
        }

        if !field.annotations.is_empty() {
            writeln!(self)?;
            for annotation in &field.annotations {
                self.write_annotation(annotation, dex, 1, false)?;
            }
            writeln!(self, "\n.end field")?;
        }
        Ok(())
    }

    /// Dex method representation for smali
    fn write_method(&mut self, method: &DexMethod, dex: IDexRef<'_>) -> Result<()> {
        write!(self, ".method ")?;
        if let Some(flags) = &method.access_flags {
            self.write_access_flags(flags)?;
        }
        write!(self, "{}", method.name)?;
        self.write_proto(&method.proto)?;

        if let Some(code) = &method.code {
            let indent = "    ";
            writeln!(self, "\n{}.registers {}", indent, code.registers_size)?;

            if !method.annotations.is_empty() {
                writeln!(self)?;
                for annotation in &method.annotations {
                    self.write_annotation(annotation, dex, 1, false)?;
                }
                writeln!(self)?;
            }

            for instruction in insns::disasm(code, dex)? {
                write!(self, "\n{:#06x}:\n", instruction.range.start)?;
                if let Some(debug) = &method.debug_info {
                    if let Some(line) = debug.lines.get(&(instruction.range.start as u32)) {
                        writeln!(self, "{}.line {}", indent, line)?;
                    }
                }
                self.write_insn(&instruction, dex, 1)?;
            }
        }
        writeln!(self, "\n.end method")?;
        Ok(())
    }

    /// Writes a class to the underlying stream.
    fn write_class(&mut self, class: &DexClassDef, dex: IDexRef<'_>) -> Result<()> {
        // class header includes name, potential superclass, source file
        // name and interfaces.
        write!(self, ".class ")?;
        if let Some(flags) = &class.flags {
            self.write_access_flags(flags)?;
        }
        writeln!(self, "{}", class.type_.descriptor)?;
        if let Some(superclass) = &class.super_class {
            writeln!(self, ".extends {}", superclass.descriptor)?;
        }
        if !class.interfaces.is_empty() {
            for interface in class.interfaces.iter() {
                // We use the descriptor here to avoid having to call
                // self.write_type() multiple times.
                writeln!(self, ".implements {}", interface.descriptor)?;
            }
        }
        if let Some(source) = &class.source_file {
            write!(self, ".source \"{}\"", source.escape_default())?;
        }

        if !class.annotations.is_empty() {
            for annotation in &class.annotations {
                writeln!(self, "\n")?;
                self.write_annotation(annotation, dex, 0, false)?;
            }
        }

        // iterate over all fields and write them
        for (_, field) in class.get_fields() {
            writeln!(self, "\n")?;
            self.write_field(field, dex)?;
        }

        // iterate over all methods and write them
        for (_, method) in class.get_methods() {
            writeln!(self, "\n")?;
            self.write_method(method, dex)?;
        }

        Ok(())
    }
}
