use crate::{
    desc_names::pretty_desc,
    file::{ProtoIndex, TypeIndex},
    Result,
};

use super::{
    signatures, vreg, Code, DexContainer, DexFile, FieldId, Format, Instruction, MethodId,
    StringId, TypeId,
};

pub mod prettify {

    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum Field {
        WithType,
        NoType,
    }

    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum Method {
        WithSig,
        NoSig,
    }
}

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    pub fn pretty_field_at(&self, field_idx: u32, opts: prettify::Field) -> String {
        match self.pretty_field_opt_at(field_idx, opts) {
            Ok(s) => s,
            Err(_) => format!("<<invalid-field-idx-{field_idx}>>"),
        }
    }

    pub fn pretty_field(&self, field_id: &FieldId, opts: prettify::Field) -> String {
        match self.pretty_field_opt(field_id, opts) {
            Ok(s) => s,
            Err(_) => format!("<<invalid-field-idx-{field_id:?}>>"),
        }
    }

    pub fn pretty_field_opt_at(&self, field_idx: u32, opts: prettify::Field) -> Result<String> {
        let field_id = self.get_field_id(field_idx)?;
        self.pretty_field_opt(field_id, opts)
    }

    pub fn pretty_field_opt(&self, field_id: &FieldId, opts: prettify::Field) -> Result<String> {
        let mut result = String::new();
        if opts == prettify::Field::WithType {
            result.push_str(&self.pretty_type_opt_at(field_id.type_idx)?);
            result.push_str(" ");
        }

        result.push_str(&self.pretty_type_opt_at(field_id.class_idx)?);
        result.push_str(".");

        result.push_str(&self.get_utf16_str_lossy_at(field_id.name_idx)?);
        Ok(result)
    }

    pub fn pretty_type_at(&self, type_idx: TypeIndex) -> String {
        match self.pretty_type_opt_at(type_idx) {
            Ok(s) => s,
            Err(_) => format!("<<invalid-type-idx-{type_idx}>>"),
        }
    }

    pub fn pretty_type(&self, type_id: &TypeId) -> String {
        match self.pretty_type_opt(type_id) {
            Ok(s) => s,
            Err(_) => format!("<<invalid-type-idx-{}>>", type_id.descriptor_idx),
        }
    }

    pub fn pretty_type_opt_at(&self, type_idx: TypeIndex) -> Result<String> {
        self.pretty_type_opt(self.get_type_id(type_idx)?)
    }

    pub fn pretty_type_opt(&self, type_id: &TypeId) -> Result<String> {
        Ok(pretty_desc(&self.get_type_desc_utf16_lossy(type_id)?))
    }

    pub fn pretty_utf16(&self, string_id: &StringId) -> String {
        match self.get_utf16_str_lossy(string_id) {
            Ok(str_data) => str_data,
            Err(_) => format!("<<invalid-string-idx-{}>>", string_id.string_data_off),
        }
    }

    pub fn pretty_utf16_at(&self, idx: u32) -> String {
        match self.get_string_id(idx) {
            Ok(str_data) => self.pretty_utf16(&str_data),
            Err(_) => format!("<<invalid-string-idx-{}>>", idx),
        }
    }

    pub fn pretty_method_at(&self, method_idx: u32, opts: prettify::Method) -> String {
        match self.pretty_method_opt_at(method_idx, opts) {
            Ok(s) => s,
            Err(_) => format!("<<invalid-method-idx-{method_idx}>>"),
        }
    }

    pub fn pretty_method_opt_at(&self, idx: u32, opts: prettify::Method) -> Result<String> {
        self.pretty_method_opt(self.get_method_id(idx)?, opts)
    }

    pub fn pretty_method_opt(
        &self,
        method_id: &MethodId,
        opts: prettify::Method,
    ) -> Result<String> {
        let mut result = String::new();
        let proto_id = match opts {
            prettify::Method::WithSig => Some(self.get_proto_id(method_id.proto_idx)?),
            prettify::Method::NoSig => None,
        };

        if let Some(proto_id) = proto_id {
            result.push_str(&self.pretty_type_at(proto_id.return_type_idx));
            result.push(' ');
        }

        result.push_str(&self.pretty_type_at(method_id.class_idx));
        result.push('.');
        result.push_str(&self.get_utf16_str_lossy_at(method_id.name_idx)?);

        if let Some(proto_id) = proto_id {
            result.push('(');
            if let Some(params) = self.get_type_list(proto_id.parameters_off)? {
                // REVISIT: we could use map().collect().join() here
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        result.push_str(", ");
                    }
                    result.push_str(&self.pretty_type_at(param.type_idx));
                }
            }
            result.push(')');
        }
        Ok(result)
    }
}

impl<'a> Instruction<'a> {
    pub fn to_string<C>(&self, dex_file: Option<&DexFile<'a, C>>) -> Result<String>
    where
        C: DexContainer<'a>,
    {
        let opcode = self.name();
        if self.opcode() == Code::NOP {
            return Ok((match self.fetch16(0)? {
                signatures::ArrayDataSignature => "array-data",
                signatures::PackedSwitchSignature => "packed-switch",
                signatures::SparseSwitchSignature => "sparse-switch",
                _ => opcode,
            })
            .to_string());
        }

        Ok(match self.format() {
            &Format::k10x => format!("{opcode}"),
            Format::k12x => format!("{opcode} v{}, v{}", vreg::A(self)?, vreg::B(self)?),
            Format::k11n => format!("{opcode} v{}, #{:+}", vreg::A(self)?, vreg::B(self)?),
            Format::k11x => format!("{opcode} v{}", vreg::A(self)?),
            Format::k10t => format!("{opcode} {:+}", vreg::A(self)?),
            Format::k20t => format!("{opcode} {:+}", vreg::A(self)?),
            Format::k22x => format!("{opcode} v{}, v{}", vreg::A(self)?, vreg::B(self)?),
            Format::k21t => format!("{opcode} v{}, {:+}", vreg::A(self)?, vreg::B(self)?),
            Format::k21s => format!("{opcode} v{}, #{:+}", vreg::A(self)?, vreg::B(self)?),
            Format::k21h => {
                // op vAA, #+BBBB0000[00000000]
                if self.opcode() == Code::CONST_HIGH16 {
                    let value = (vreg::B(self)? as u32) << 16;
                    format!(
                        "{opcode} v{}, #int {:+} // {:#x}",
                        vreg::A(self)?,
                        value,
                        value
                    )
                } else {
                    let value = (vreg::B(self)? as u64) << 48;
                    format!(
                        "{opcode} v{}, #long {:+} // {:#x}",
                        vreg::A(self)?,
                        value,
                        value
                    )
                }
            }
            Format::k21c => {
                // op vAA, type@BBBB               check-cast
                // op vAA, field@BBBB              const-class
                // op vAA, method_handle@BBBB      const-method-handle
                // op vAA, proto@BBBB              const-method-type
                // op vAA, string@BBBB             const-string
                match (dex_file, self.opcode()) {
                    (Some(dex), Code::CONST_STRING) => {
                        let index = vreg::B(self)?;
                        format!(
                            "{opcode} v{}, {:?} // string@{}",
                            vreg::A(self)?,
                            dex.pretty_utf16_at(index as u32),
                            index
                        )
                    }
                    (Some(dex), Code::CHECK_CAST | Code::CONST_CLASS | Code::NEW_INSTANCE) => {
                        let type_idx = vreg::B(self)? as TypeIndex;
                        format!(
                            "{opcode} v{}, {} // type@{}",
                            vreg::A(self)?,
                            dex.pretty_type_at(type_idx),
                            type_idx
                        )
                    }
                    (
                        Some(dex),
                        Code::SGET
                        | Code::SGET_WIDE
                        | Code::SGET_OBJECT
                        | Code::SGET_BOOLEAN
                        | Code::SGET_BYTE
                        | Code::SGET_CHAR
                        | Code::SGET_SHORT
                        | Code::SPUT
                        | Code::SPUT_WIDE
                        | Code::SPUT_OBJECT
                        | Code::SPUT_BOOLEAN
                        | Code::SPUT_BYTE
                        | Code::SPUT_CHAR
                        | Code::SPUT_SHORT,
                    ) => {
                        let field_idx = vreg::B(self)? as u32;
                        format!(
                            "{opcode} v{}, {} // field@{}",
                            vreg::A(self)?,
                            dex.pretty_field_at(field_idx, prettify::Field::WithType),
                            field_idx
                        )
                    }
                    _ => format!("{opcode} v{}, thing@{}", vreg::A(self)?, vreg::B(self)?),
                }
            }
            #[rustfmt::skip]
            &Format::k23x => format!("{opcode} v{}, v{}, v{}", vreg::A(self)?, vreg::B(self)?, vreg::C(self)?),
            #[rustfmt::skip]
            Format::k22b => format!("{opcode} v{}, v{}, #{:+}", vreg::A(self)?, vreg::B(self)?, vreg::C(self)?),
            #[rustfmt::skip]
            Format::k22t => format!("{opcode} v{}, v{}, {:+}", vreg::A(self)?, vreg::B(self)?, vreg::C(self)?),
            #[rustfmt::skip]
            Format::k22s => format!("{opcode} v{}, v{}, #{:+}", vreg::A(self)?, vreg::B(self)?, vreg::C(self)?),
            Format::k22c => {
                let index = vreg::C(self)? as u32;
                match (dex_file, self.opcode()) {
                    (
                        Some(dex),
                        Code::IGET
                        | Code::IGET_WIDE
                        | Code::IGET_OBJECT
                        | Code::IGET_BOOLEAN
                        | Code::IGET_BYTE
                        | Code::IGET_CHAR
                        | Code::IGET_SHORT
                        | Code::IPUT
                        | Code::IPUT_WIDE
                        | Code::IPUT_OBJECT
                        | Code::IPUT_BOOLEAN
                        | Code::IPUT_BYTE
                        | Code::IPUT_CHAR
                        | Code::IPUT_SHORT,
                    ) => {
                        format!(
                            "{opcode} v{}, v{}, {} // field@{}",
                            vreg::A(self)?,
                            vreg::B(self)?,
                            dex.pretty_field_at(index, prettify::Field::WithType),
                            index
                        )
                    }
                    (Some(dex), Code::NEW_ARRAY | Code::INSTANCE_OF) => {
                        format!(
                            "{opcode} v{}, v{}, {} // type@{}",
                            vreg::A(self)?,
                            vreg::B(self)?,
                            dex.pretty_type_at(index as TypeIndex),
                            index
                        )
                    }
                    _ => {
                        format!(
                            "{opcode} v{}, v{}, thing@{}",
                            vreg::A(self)?,
                            vreg::B(self)?,
                            index,
                        )
                    }
                }
            }
            Format::k30t => format!("{opcode} {:+}", vreg::A(self)?),
            Format::k32x => format!("{opcode} v{}, v{}", vreg::A(self)?, vreg::B(self)?),
            Format::k31i => format!("{opcode} v{}, #{:+}", vreg::A(self)?, vreg::B(self)?),
            Format::k31t => format!("{opcode} v{}, {:+}", vreg::A(self)?, vreg::B(self)?),
            Format::k31c => {
                let index = vreg::B(self)? as u32;
                if let (Some(dex), Code::CONST_STRING_JUMBO) = (dex_file, self.opcode()) {
                    format!(
                        "{opcode} v{}, {:?} // string@{}",
                        vreg::A(self)?,
                        dex.pretty_utf16_at(index),
                        index
                    )
                } else {
                    format!("{opcode} v{}, thing@{}", vreg::A(self)?, index,)
                }
            }
            Format::k35c => {
                let var_args = vreg::var_args(self)?;
                let args_str = var_args
                    .arg
                    .iter()
                    .map(|reg| format!("v{}", reg))
                    .collect::<Vec<String>>()
                    .join(", ");
                let index = vreg::B(self)? as u32;
                match (dex_file, self.opcode()) {
                    (Some(dex), Code::FILLED_NEW_ARRAY) => {
                        format!(
                            "{opcode} {{{args_str}}}, {} // type@{}",
                            dex.pretty_type_at(index as TypeIndex),
                            index
                        )
                    }
                    (
                        Some(dex),
                        Code::INVOKE_VIRTUAL
                        | Code::INVOKE_SUPER
                        | Code::INVOKE_DIRECT
                        | Code::INVOKE_STATIC
                        | Code::INVOKE_INTERFACE,
                    ) => {
                        format!(
                            "{opcode} {{{args_str}}}, {} // method@{}",
                            dex.pretty_method_at(index, prettify::Method::WithSig),
                            index
                        )
                    }
                    (_, Code::INVOKE_CUSTOM) => {
                        format!("{opcode} {{{args_str}}}, // call_site@{}", index)
                    }
                    _ => {
                        format!("{opcode} {{{args_str}}}, thing@{}", index,)
                    }
                }
            }
            Format::k3rc => {
                let var_range = vreg::args_range(self)?;
                let index = vreg::B(self)? as u32;
                match (dex_file, self.opcode()) {
                    (
                        Some(dex),
                        Code::INVOKE_VIRTUAL_RANGE
                        | Code::INVOKE_SUPER_RANGE
                        | Code::INVOKE_DIRECT_RANGE
                        | Code::INVOKE_STATIC_RANGE
                        | Code::INVOKE_INTERFACE_RANGE,
                    ) => {
                        format!(
                            "{opcode} {{v{} .. v{}}}, {} // method@{}",
                            var_range.start(),
                            var_range.end(),
                            dex.pretty_method_at(index, prettify::Method::WithSig),
                            index
                        )
                    }
                    (_, Code::INVOKE_CUSTOM_RANGE) => {
                        format!(
                            "{opcode} {{v{} .. v{}}}, // call_site@{}",
                            var_range.start(),
                            var_range.end(),
                            index
                        )
                    }
                    _ => {
                        format!(
                            "{opcode} {{v{} .. v{}}} thing@{}",
                            var_range.start(),
                            var_range.end(),
                            index
                        )
                    }
                }
            }
            Format::k45cc => {
                let var_args = vreg::var_args(self)?;
                let args_str = var_args
                    .arg
                    .iter()
                    .map(|reg| format!("v{}", reg))
                    .collect::<Vec<String>>()
                    .join(", ");
                let method_idx = vreg::B(self)? as u32;
                let proto_idx = vreg::H(self)? as u32;
                if let Some(dex) = dex_file {
                    format!(
                        "{opcode} {{{args_str}}}, {}, {} // method@{}, proto@{}",
                        dex.pretty_method_at(method_idx, prettify::Method::WithSig),
                        dex.get_shorty_lossy_at(proto_idx as ProtoIndex)?,
                        method_idx,
                        proto_idx
                    )
                } else {
                    format!(
                        "{opcode} {{{args_str}}}, method@{}, proto@{}",
                        method_idx, proto_idx
                    )
                }
            }
            Format::k4rcc => {
                let args_range = vreg::args_range(self)?;
                let method_idx = vreg::B(self)? as u32;
                let proto_idx = vreg::H(self)? as u32;
                match (dex_file, self.opcode()) {
                    (Some(dex), Code::INVOKE_POLYMORPHIC_RANGE) => {
                        format!(
                            "{opcode} {{v{} .. v{}}}, {}, {} // method@{}, proto@{}",
                            args_range.start(),
                            args_range.end(),
                            dex.pretty_method_at(method_idx, prettify::Method::WithSig),
                            dex.get_shorty_lossy_at(proto_idx as ProtoIndex)?,
                            method_idx,
                            proto_idx
                        )
                    }
                    _ => {
                        format!(
                            "{opcode} {{v{} .. v{}}}, method@{}, proto@{}",
                            args_range.start(),
                            args_range.end(),
                            method_idx,
                            proto_idx
                        )
                    }
                }
            }
            Format::k51l => format!("{opcode} v{}, #{:+}", vreg::A(self)?, vreg::wide_b(self)?),
            Format::kInvalidFormat => "<invalid-opcode-format>".to_string(),
        })
    }
}
