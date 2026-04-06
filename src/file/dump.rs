use crate::{
    desc_names::pretty_desc,
    file::{ProtoIndex, TypeIndex},
    Result,
};

use super::{
    signatures, vreg, Code, DexContainer, DexFile, FieldId, Format, Instruction, MethodId,
    StringId, TypeId, VarArgs,
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
            result.push(' ');
        }

        result.push_str(&self.pretty_type_opt_at(field_id.class_idx)?);
        result.push('.');

        result.push_str(&self.get_str_lossy_at(field_id.name_idx)?);
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
        match self.get_str_lossy(string_id) {
            Ok(str_data) => str_data,
            Err(_) => format!("<<invalid-string-idx-{}>>", string_id.string_data_off),
        }
    }

    pub fn pretty_utf16_at(&self, idx: u32) -> String {
        match self.get_string_id(idx) {
            Ok(str_data) => self.pretty_utf16(str_data),
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
        result.push_str(&self.get_str_lossy_at(method_id.name_idx)?);

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

// ============================================================================
// Colored output types
// ============================================================================

/// Semantic category of a fragment of formatted instruction text.
///
/// Consumers map this to terminal colors, HTML classes, or any other
/// presentation layer without re-parsing the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Highlight {
    /// Instruction mnemonic (`invoke-virtual`, `const/4`, …).
    Opcode,
    /// Virtual or parameter register (`v0`, `p1`, …).
    Register,
    /// Numeric immediate (`#+42`, `#int +65536 // 0x10000`, …).
    Immediate,
    /// Signed branch offset (`+5`, `-3`, …).
    Offset,
    /// Quoted string literal content (`"hello"`, …).
    StringLiteral,
    /// Resolved type, field, method, or proto reference name.
    Ref,
    /// Index annotation comment (` // field@3`, ` // method@2, proto@1`, …).
    Comment,
    /// Structural punctuation and whitespace (`, `, ` .. `, `{`, `}`, ` `).
    Plain,
}

/// A fragment of formatted instruction text with its semantic highlight.
#[derive(Debug, Clone)]
pub struct Span {
    pub text: String,
    pub hl: Highlight,
}

/// A fully formatted, highlighted instruction line as a sequence of [`Span`]s.
pub type StyledLine = Vec<Span>;

// ============================================================================
// Internal writer abstraction
// ============================================================================

/// Low-level sink for instruction fragments.  Implementors decide whether to
/// concatenate into a plain `String` or collect typed [`Span`]s.
trait InsnWriter {
    fn push(&mut self, text: String, hl: Highlight);

    fn opcode(&mut self, s: &str) {
        self.push(s.to_string(), Highlight::Opcode);
    }
    fn plain(&mut self, s: impl Into<String>) {
        self.push(s.into(), Highlight::Plain);
    }
    fn sep(&mut self) {
        self.push(", ".to_string(), Highlight::Plain);
    }
    fn reg(&mut self, n: i32) {
        self.push(format!("v{n}"), Highlight::Register);
    }
    fn offset_signed(&mut self, n: i32) {
        self.push(format!("{n:+}"), Highlight::Offset);
    }
    fn imm_i32(&mut self, n: i32) {
        self.push(format!("#{n:+}"), Highlight::Immediate);
    }
    fn imm_u64(&mut self, n: u64) {
        self.push(format!("#{n:+}"), Highlight::Immediate);
    }
    fn imm_typed_u32(&mut self, ty: &str, n: u32) {
        self.push(format!("#{ty} {n:+} // {n:#x}"), Highlight::Immediate);
    }
    fn imm_typed_u64(&mut self, ty: &str, n: u64) {
        self.push(format!("#{ty} {n:+} // {n:#x}"), Highlight::Immediate);
    }
    fn string_lit(&mut self, s: &str, idx: impl std::fmt::Display) {
        self.push(format!("{s:?}"), Highlight::StringLiteral);
        self.push(format!(" // string@{idx}"), Highlight::Comment);
    }
    fn type_ref(&mut self, name: &str, idx: impl std::fmt::Display) {
        self.push(name.to_string(), Highlight::Ref);
        self.push(format!(" // type@{idx}"), Highlight::Comment);
    }
    fn field_ref(&mut self, name: &str, idx: u32) {
        self.push(name.to_string(), Highlight::Ref);
        self.push(format!(" // field@{idx}"), Highlight::Comment);
    }
    fn method_ref(&mut self, name: &str, idx: u32) {
        self.push(name.to_string(), Highlight::Ref);
        self.push(format!(" // method@{idx}"), Highlight::Comment);
    }
    /// Emit `method_name, shorty_desc // method@M, proto@P` for polymorphic calls.
    fn method_proto_ref(&mut self, method: &str, method_idx: u32, shorty: &str, proto_idx: u32) {
        self.push(method.to_string(), Highlight::Ref);
        self.sep();
        self.push(shorty.to_string(), Highlight::Ref);
        self.push(
            format!(" // method@{method_idx}, proto@{proto_idx}"),
            Highlight::Comment,
        );
    }
    fn call_site_ref(&mut self, idx: u32) {
        self.push(format!("// call_site@{idx}"), Highlight::Comment);
    }
    fn thing_at(&mut self, kind: &str, idx: impl std::fmt::Display) {
        self.push(format!("{kind}@{idx}"), Highlight::Plain);
    }
}

struct PlainWriter {
    buf: String,
}
impl InsnWriter for PlainWriter {
    fn push(&mut self, text: String, _: Highlight) {
        self.buf.push_str(&text);
    }
}

struct SpanWriter {
    spans: Vec<Span>,
}
impl InsnWriter for SpanWriter {
    fn push(&mut self, text: String, hl: Highlight) {
        self.spans.push(Span { text, hl });
    }
}

/// Emit `{v0, v1, v2}` (var-arg register list) into `w`.
fn push_var_args<W: InsnWriter>(w: &mut W, args: &VarArgs) {
    w.plain("{");
    for (i, &reg) in args.arg.iter().enumerate() {
        if i > 0 {
            w.sep();
        }
        w.reg(reg as i32);
    }
    w.plain("}");
}

/// Emit `{vStart .. vEnd}` (range register list) into `w`.
fn push_range_regs<W: InsnWriter>(w: &mut W, start: u16, end: u16) {
    w.plain("{");
    w.reg(start as i32);
    w.plain(" .. ");
    w.reg(end as i32);
    w.plain("}");
}

/// Core formatting logic: writes every fragment of one instruction into `w`.
///
/// Both [`Instruction::to_string`] and [`Instruction::to_styled`] delegate
/// here, differing only in the [`InsnWriter`] implementation supplied.
fn format_insn<'a, C, W>(
    inst: &Instruction<'a>,
    dex_file: Option<&DexFile<'a, C>>,
    w: &mut W,
) -> Result<()>
where
    C: DexContainer<'a>,
    W: InsnWriter,
{
    let opcode = inst.name();

    if inst.opcode() == Code::NOP {
        let name = match inst.fetch16(0)? {
            signatures::ArrayDataSignature => "array-data",
            signatures::PackedSwitchSignature => "packed-switch",
            signatures::SparseSwitchSignature => "sparse-switch",
            _ => opcode,
        };
        w.opcode(name);
        return Ok(());
    }

    match inst.format() {
        &Format::k10x => w.opcode(opcode),
        Format::k12x => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.reg(vreg::B(inst)?);
        }
        Format::k11n => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.imm_i32(vreg::B(inst)?);
        }
        Format::k11x => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
        }
        Format::k10t => {
            w.opcode(opcode);
            w.plain(" ");
            w.offset_signed(vreg::A(inst)?);
        }
        Format::k20t => {
            w.opcode(opcode);
            w.plain(" ");
            w.offset_signed(vreg::A(inst)?);
        }
        Format::k22x => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.reg(vreg::B(inst)?);
        }
        Format::k21t => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.offset_signed(vreg::B(inst)?);
        }
        Format::k21s => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.imm_i32(vreg::B(inst)?);
        }
        Format::k21h => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            if inst.opcode() == Code::CONST_HIGH16 {
                let value = (vreg::B(inst)? as u32) << 16;
                w.imm_typed_u32("int", value);
            } else {
                let value = (vreg::B(inst)? as u64) << 48;
                w.imm_typed_u64("long", value);
            }
        }
        Format::k21c => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            let index = vreg::B(inst)?;
            match (dex_file, inst.opcode()) {
                (Some(dex), Code::CONST_STRING) => {
                    w.string_lit(&dex.pretty_utf16_at(index as u32), index);
                }
                (Some(dex), Code::CHECK_CAST | Code::CONST_CLASS | Code::NEW_INSTANCE) => {
                    let type_idx = index as TypeIndex;
                    w.type_ref(&dex.pretty_type_at(type_idx), type_idx);
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
                    let field_idx = index as u32;
                    w.field_ref(
                        &dex.pretty_field_at(field_idx, prettify::Field::WithType),
                        field_idx,
                    );
                }
                _ => {
                    w.thing_at("thing", index);
                }
            }
        }
        #[rustfmt::skip]
        &Format::k23x => {
            w.opcode(opcode); w.plain(" ");
            w.reg(vreg::A(inst)?); w.sep();
            w.reg(vreg::B(inst)?); w.sep();
            w.reg(vreg::C(inst)?);
        }
        #[rustfmt::skip]
        Format::k22b => {
            w.opcode(opcode); w.plain(" ");
            w.reg(vreg::A(inst)?); w.sep();
            w.reg(vreg::B(inst)?); w.sep();
            w.imm_i32(vreg::C(inst)?);
        }
        #[rustfmt::skip]
        Format::k22t => {
            w.opcode(opcode); w.plain(" ");
            w.reg(vreg::A(inst)?); w.sep();
            w.reg(vreg::B(inst)?); w.sep();
            w.offset_signed(vreg::C(inst)?);
        }
        #[rustfmt::skip]
        Format::k22s => {
            w.opcode(opcode); w.plain(" ");
            w.reg(vreg::A(inst)?); w.sep();
            w.reg(vreg::B(inst)?); w.sep();
            w.imm_i32(vreg::C(inst)?);
        }
        Format::k22c => {
            let index = vreg::C(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.reg(vreg::B(inst)?);
            w.sep();
            match (dex_file, inst.opcode()) {
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
                    w.field_ref(
                        &dex.pretty_field_at(index, prettify::Field::WithType),
                        index,
                    );
                }
                (Some(dex), Code::NEW_ARRAY | Code::INSTANCE_OF) => {
                    w.type_ref(&dex.pretty_type_at(index as TypeIndex), index);
                }
                _ => {
                    w.thing_at("thing", index);
                }
            }
        }
        Format::k30t => {
            w.opcode(opcode);
            w.plain(" ");
            w.offset_signed(vreg::A(inst)?);
        }
        Format::k32x => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.reg(vreg::B(inst)?);
        }
        Format::k31i => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.imm_i32(vreg::B(inst)?);
        }
        Format::k31t => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.offset_signed(vreg::B(inst)?);
        }
        Format::k31c => {
            let index = vreg::B(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            if let (Some(dex), Code::CONST_STRING_JUMBO) = (dex_file, inst.opcode()) {
                w.string_lit(&dex.pretty_utf16_at(index), index);
            } else {
                w.thing_at("thing", index);
            }
        }
        Format::k35c => {
            let var_args = vreg::var_args(inst)?;
            let index = vreg::B(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            push_var_args(w, &var_args);
            w.sep();
            match (dex_file, inst.opcode()) {
                (Some(dex), Code::FILLED_NEW_ARRAY) => {
                    w.type_ref(&dex.pretty_type_at(index as TypeIndex), index);
                }
                (
                    Some(dex),
                    Code::INVOKE_VIRTUAL
                    | Code::INVOKE_SUPER
                    | Code::INVOKE_DIRECT
                    | Code::INVOKE_STATIC
                    | Code::INVOKE_INTERFACE,
                ) => {
                    w.method_ref(
                        &dex.pretty_method_at(index, prettify::Method::WithSig),
                        index,
                    );
                }
                (_, Code::INVOKE_CUSTOM) => {
                    w.call_site_ref(index);
                }
                _ => {
                    w.thing_at("thing", index);
                }
            }
        }
        Format::k3rc => {
            let var_range = vreg::args_range(inst)?;
            let index = vreg::B(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            push_range_regs(w, *var_range.start(), *var_range.end());
            match (dex_file, inst.opcode()) {
                (
                    Some(dex),
                    Code::INVOKE_VIRTUAL_RANGE
                    | Code::INVOKE_SUPER_RANGE
                    | Code::INVOKE_DIRECT_RANGE
                    | Code::INVOKE_STATIC_RANGE
                    | Code::INVOKE_INTERFACE_RANGE,
                ) => {
                    w.sep();
                    w.method_ref(
                        &dex.pretty_method_at(index, prettify::Method::WithSig),
                        index,
                    );
                }
                (_, Code::INVOKE_CUSTOM_RANGE) => {
                    w.sep();
                    w.call_site_ref(index);
                }
                _ => {
                    // Note: preserved space (not comma) before fallback, matching
                    // the original output.
                    w.plain(" ");
                    w.thing_at("thing", index);
                }
            }
        }
        Format::k45cc => {
            let var_args = vreg::var_args(inst)?;
            let method_idx = vreg::B(inst)? as u32;
            let proto_idx = vreg::H(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            push_var_args(w, &var_args);
            w.sep();
            if let Some(dex) = dex_file {
                w.method_proto_ref(
                    &dex.pretty_method_at(method_idx, prettify::Method::WithSig),
                    method_idx,
                    &dex.get_shorty_lossy_at(proto_idx as ProtoIndex)?,
                    proto_idx,
                );
            } else {
                w.thing_at("method", method_idx);
                w.sep();
                w.thing_at("proto", proto_idx);
            }
        }
        Format::k4rcc => {
            let args_range = vreg::args_range(inst)?;
            let method_idx = vreg::B(inst)? as u32;
            let proto_idx = vreg::H(inst)? as u32;
            w.opcode(opcode);
            w.plain(" ");
            push_range_regs(w, *args_range.start(), *args_range.end());
            w.sep();
            match (dex_file, inst.opcode()) {
                (Some(dex), Code::INVOKE_POLYMORPHIC_RANGE) => {
                    w.method_proto_ref(
                        &dex.pretty_method_at(method_idx, prettify::Method::WithSig),
                        method_idx,
                        &dex.get_shorty_lossy_at(proto_idx as ProtoIndex)?,
                        proto_idx,
                    );
                }
                _ => {
                    w.thing_at("method", method_idx);
                    w.sep();
                    w.thing_at("proto", proto_idx);
                }
            }
        }
        Format::k51l => {
            w.opcode(opcode);
            w.plain(" ");
            w.reg(vreg::A(inst)?);
            w.sep();
            w.imm_u64(vreg::wide_b(inst)?);
        }
        Format::kInvalidFormat => {
            w.plain("<invalid-opcode-format>");
        }
    }
    Ok(())
}

impl<'a> Instruction<'a> {
    /// Format this instruction as a plain string.
    ///
    /// When `dex_file` is supplied, indices are resolved to human-readable
    /// names.  Pass `None` to get raw `thing@N` fallbacks.
    pub fn to_string<C>(&self, dex_file: Option<&DexFile<'a, C>>) -> Result<String>
    where
        C: DexContainer<'a>,
    {
        let mut w = PlainWriter { buf: String::new() };
        format_insn(self, dex_file, &mut w)?;
        Ok(w.buf)
    }

    /// Format this instruction as a sequence of highlighted [`Span`]s.
    ///
    /// Identical output to [`to_string`] when spans are concatenated, but each
    /// fragment carries a [`Highlight`] tag that callers can map to colors or
    /// other markup without re-parsing the text.
    pub fn to_styled<C>(&self, dex_file: Option<&DexFile<'a, C>>) -> Result<StyledLine>
    where
        C: DexContainer<'a>,
    {
        let mut w = SpanWriter { spans: Vec::new() };
        format_insn(self, dex_file, &mut w)?;
        Ok(w.spans)
    }

    /// Format this instruction as assembler text that can be round-tripped back
    /// through [`crate::file::builder::CodeBuilder::emit`].
    ///
    /// Unlike [`to_string`], which uses pretty-printed class/method/field names,
    /// this method outputs raw DEX descriptor form so the output is parseable:
    ///
    /// ```text
    /// invoke-virtual {v0, v1}, Ljava/lang/Object;->toString()Ljava/lang/String;
    /// iget-object v0, v1, Lcom/example/Foo;->bar:Ljava/lang/String;
    /// const/high16 v0, #+65536
    /// goto +5
    /// ```
    ///
    /// Index-annotation comments (`// method@N`) are **not** included.
    pub fn to_assembler_text<C>(&self, dex_file: &DexFile<'a, C>) -> Result<String>
    where
        C: DexContainer<'a>,
    {
        format_insn_assembler(self, dex_file)
    }
}

// -- Raw-descriptor helpers on DexFile ----------------------------------------

impl<'a, C: DexContainer<'a>> DexFile<'a, C> {
    /// Raw DEX type descriptor for `type_idx` (e.g. `"Ljava/lang/Object;"`).
    pub fn raw_type_ref_at(&self, type_idx: TypeIndex) -> String {
        self.get_type_id(type_idx)
            .and_then(|t| self.get_str_lossy_at(t.descriptor_idx))
            .unwrap_or_else(|_| format!("Lunknown/type_{type_idx};"))
    }

    /// Raw DEX method reference (e.g. `"Ljava/lang/Object;->toString()Ljava/lang/String;"`).
    pub fn raw_method_ref_at(&self, method_idx: u32) -> String {
        self.raw_method_ref_at_impl(method_idx)
            .unwrap_or_else(|_| format!("Lunknown/method_{method_idx};->unknown()V"))
    }

    fn raw_method_ref_at_impl(&self, method_idx: u32) -> Result<String> {
        let mid = self.get_method_id(method_idx)?;
        let class = self.raw_type_ref_at(mid.class_idx);
        let name = self.get_str_lossy_at(mid.name_idx)?;
        let proto = self.get_proto_id(mid.proto_idx)?;
        let ret = self.raw_type_ref_at(proto.return_type_idx);
        let mut params = String::new();
        if let Some(type_list) = self.get_type_list(proto.parameters_off)? {
            for item in type_list {
                params.push_str(&self.raw_type_ref_at(item.type_idx));
            }
        }
        Ok(format!("{class}->{name}({params}){ret}"))
    }

    /// Raw DEX field reference (e.g. `"Lcom/example/Foo;->counter:I"`).
    pub fn raw_field_ref_at(&self, field_idx: u32) -> String {
        self.raw_field_ref_at_impl(field_idx)
            .unwrap_or_else(|_| format!("Lunknown/field_{field_idx};->unknown:V"))
    }

    fn raw_field_ref_at_impl(&self, field_idx: u32) -> Result<String> {
        let fid = self.get_field_id(field_idx)?;
        let class = self.raw_type_ref_at(fid.class_idx);
        let name = self.get_str_lossy_at(fid.name_idx)?;
        let ftype = self.raw_type_ref_at(fid.type_idx);
        Ok(format!("{class}->{name}:{ftype}"))
    }
}

// -- Assembler text formatter --------------------------------------------------

/// Format one instruction as assembler text suitable for round-tripping through
/// [`crate::file::builder::CodeBuilder::emit`].  All references use raw DEX
/// descriptor form; index-annotation comments are omitted.
fn format_insn_assembler<'a, C>(inst: &Instruction<'a>, dex: &DexFile<'a, C>) -> Result<String>
where
    C: DexContainer<'a>,
{
    let op = inst.name();
    let mut buf = String::with_capacity(64);

    // Helper closures to avoid repetition
    macro_rules! w   { ($s:expr) => { buf.push_str($s) } }
    macro_rules! wfmt { ($($t:tt)*) => { buf.push_str(&format!($($t)*)) } }

    match inst.format() {
        &Format::k10x => {
            // Distinguish pseudo-instructions (switch/array payloads) from nop
            if inst.opcode() == Code::NOP {
                let name = match inst.fetch16(0)? {
                    signatures::ArrayDataSignature    => "array-data",
                    signatures::PackedSwitchSignature => "packed-switch",
                    signatures::SparseSwitchSignature => "sparse-switch",
                    _ => op,
                };
                w!(name);
            } else {
                w!(op);
            }
        }
        Format::k11x => { wfmt!("{op} v{}", vreg::A(inst)?) }
        Format::k12x => { wfmt!("{op} v{}, v{}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k11n => { wfmt!("{op} v{}, #{:+}", vreg::A(inst)?, vreg::B(inst)?) }
        // Branch targets: emit as signed offsets (parseable without labels)
        Format::k10t | Format::k20t | Format::k30t => {
            wfmt!("{op} {:+}", vreg::A(inst)?)
        }
        Format::k22x => { wfmt!("{op} v{}, v{}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k21t => { wfmt!("{op} v{}, {:+}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k22t => {
            wfmt!("{op} v{}, v{}, {:+}", vreg::A(inst)?, vreg::B(inst)?, vreg::C(inst)?)
        }
        Format::k21s => { wfmt!("{op} v{}, #{:+}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k21h => {
            // Emit the full shifted value so the parser can store it directly.
            let full_val: i64 = if inst.opcode() == Code::CONST_HIGH16 {
                ((vreg::B(inst)? as u32) << 16) as i64
            } else {
                ((vreg::B(inst)? as u64) << 48) as i64
            };
            wfmt!("{op} v{}, #{:+}", vreg::A(inst)?, full_val);
        }
        Format::k21c => {
            let index = vreg::B(inst)? as u32;
            wfmt!("{op} v{}, ", vreg::A(inst)?);
            match inst.opcode() {
                Code::CONST_STRING => {
                    let s = dex.pretty_utf16_at(index);
                    wfmt!("{s:?}");
                }
                Code::CONST_CLASS | Code::CHECK_CAST | Code::NEW_INSTANCE => {
                    w!(&dex.raw_type_ref_at(index as TypeIndex));
                }
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
                | Code::SPUT_SHORT => {
                    w!(&dex.raw_field_ref_at(index));
                }
                _ => {
                    wfmt!("thing@{index}");
                }
            }
        }
        Format::k31c => {
            let index = vreg::B(inst)? as u32;
            wfmt!("{op} v{}, ", vreg::A(inst)?);
            if inst.opcode() == Code::CONST_STRING_JUMBO {
                let s = dex.pretty_utf16_at(index);
                wfmt!("{s:?}");
            } else {
                wfmt!("thing@{index}");
            }
        }
        Format::k22c => {
            let index = vreg::C(inst)? as u32;
            wfmt!("{op} v{}, v{}, ", vreg::A(inst)?, vreg::B(inst)?);
            match inst.opcode() {
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
                | Code::IPUT_SHORT => {
                    w!(&dex.raw_field_ref_at(index));
                }
                Code::NEW_ARRAY | Code::INSTANCE_OF => {
                    w!(&dex.raw_type_ref_at(index as TypeIndex));
                }
                _ => {
                    wfmt!("thing@{index}");
                }
            }
        }
        #[rustfmt::skip]
        Format::k23x => {
            wfmt!("{op} v{}, v{}, v{}", vreg::A(inst)?, vreg::B(inst)?, vreg::C(inst)?)
        }
        #[rustfmt::skip]
        Format::k22b => {
            wfmt!("{op} v{}, v{}, #{:+}", vreg::A(inst)?, vreg::B(inst)?, vreg::C(inst)?)
        }
        #[rustfmt::skip]
        Format::k22s => {
            wfmt!("{op} v{}, v{}, #{:+}", vreg::A(inst)?, vreg::B(inst)?, vreg::C(inst)?)
        }
        Format::k32x => { wfmt!("{op} v{}, v{}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k31i => { wfmt!("{op} v{}, #{:+}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k31t => { wfmt!("{op} v{}, {:+}", vreg::A(inst)?, vreg::B(inst)?) }
        Format::k35c | Format::k45cc => {
            let var_args = vreg::var_args(inst)?;
            let index = vreg::B(inst)? as u32;
            wfmt!("{op} {{");
            for (i, &r) in var_args.arg.iter().enumerate() {
                if i > 0 {
                    w!(", ");
                }
                wfmt!("v{r}");
            }
            w!("}, ");
            match inst.opcode() {
                Code::INVOKE_VIRTUAL
                | Code::INVOKE_SUPER
                | Code::INVOKE_DIRECT
                | Code::INVOKE_STATIC
                | Code::INVOKE_INTERFACE
                | Code::INVOKE_POLYMORPHIC => {
                    w!(&dex.raw_method_ref_at(index));
                }
                Code::FILLED_NEW_ARRAY => {
                    w!(&dex.raw_type_ref_at(index as TypeIndex));
                }
                _ => {
                    wfmt!("thing@{index}");
                }
            }
        }
        Format::k3rc | Format::k4rcc => {
            let range = vreg::args_range(inst)?;
            let index = vreg::B(inst)? as u32;
            wfmt!("{op} {{v{} .. v{}}}", range.start(), range.end());
            match inst.opcode() {
                Code::INVOKE_VIRTUAL_RANGE
                | Code::INVOKE_SUPER_RANGE
                | Code::INVOKE_DIRECT_RANGE
                | Code::INVOKE_STATIC_RANGE
                | Code::INVOKE_INTERFACE_RANGE
                | Code::INVOKE_POLYMORPHIC_RANGE => {
                    w!(", ");
                    w!(&dex.raw_method_ref_at(index));
                }
                _ => {
                    wfmt!(" thing@{index}");
                }
            }
        }
        Format::k51l => {
            wfmt!("{op} v{}, #{:+}", vreg::A(inst)?, vreg::wide_b(inst)? as i64)
        }
        Format::kInvalidFormat => {
            w!("<invalid-opcode-format>");
        }
    }
    Ok(buf)
}
