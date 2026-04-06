//! Instruction-level builder: assemble DEX bytecode from disassembly text.
//!
//! # Overview
//!
//! [`CodeBuilder`] accumulates instructions via [`CodeBuilder::emit`], which
//! accepts a single disassembly line such as:
//!
//! ```text
//! const-string v0, "hello"
//! invoke-virtual {v0, v1}, Ljava/lang/Object;->toString()Ljava/lang/String;
//! if-eqz v0, :my_label
//! ```
//!
//! Labels are placed with [`CodeBuilder::label`].  After all instructions are
//! added, call [`CodeBuilder::build`] to run the branch-width fixup loop and
//! produce a [`CodeDef`] ready for inclusion in a [`DexIr`].
//!
//! # Supported formats
//!
//! | Format   | Example |
//! |----------|---------|
//! | `k10x`   | `return-void` |
//! | `k11x`   | `return v0`, `move-result-object v0` |
//! | `k12x`   | `move v0, v1` |
//! | `k11n`   | `const/4 v0, #3` |
//! | `k10t`   | `goto :label` |
//! | `k20t`   | `goto/16 :label` |
//! | `k30t`   | `goto/32 :label` |
//! | `k21t`   | `if-eqz v0, :label` |
//! | `k22t`   | `if-eq v0, v1, :label` |
//! | `k21s`   | `const/16 v0, #1000` |
//! | `k21h`   | `const/high16 v0, #0x7fff` |
//! | `k31i`   | `const v0, #12345` |
//! | `k51l`   | `const-wide v0, #1234567890123` |
//! | `k21c`   | `const-string v0, "text"`, `new-instance v0, Lfoo;`, `sget-object v0, …` |
//! | `k31c`   | `const-string/jumbo v0, "text"` |
//! | `k22c`   | `iget-object v0, v1, Lclass;->field:Ltype;` |
//! | `k23x`   | `add-int v0, v1, v2` |
//! | `k22b`   | `add-int/lit8 v0, v1, #5` |
//! | `k22s`   | `add-int/lit16 v0, v1, #100` |
//! | `k35c`   | `invoke-virtual {v0, v1}, Lclass;->method(…)…` |
//! | `k3rc`   | `invoke-virtual/range {v0 .. v3}, Lclass;->method(…)…` |
//! | `k22x`   | `move/from16 v0, v256` |
//! | `k32x`   | `move/16 v256, v512` |

use std::collections::HashMap;

use crate::{
    error::DexError,
    file::{
        instruction::{Code, Format, Instruction},
        ir::{
            parse_type_list, BranchTarget, CodeDef, DexRef, InsnNode, MethodDef, ProtoKey, TryDef,
        },
    },
    Result,
};

// -- Opcode name -> Code lookup -------------------------------------------------

fn opcode_map() -> &'static HashMap<&'static str, Code> {
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<&'static str, Code>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for byte in 0u16..=0xFF {
            let code = Instruction::opcode_of(byte);
            let name = Instruction::name_of(code);
            m.entry(name).or_insert(code);
        }
        m
    })
}

// -- Token types ---------------------------------------------------------------

#[derive(Debug, Clone)]
enum Token {
    Register(u16),
    PRegister(u16),
    Literal(i64),
    StringLit(String),
    TypeRef(String),
    MethodRef { class: String, name: String, proto: ProtoKey },
    FieldRef { class: String, name: String, field_type: String },
    Label(String),
    RegList(Vec<u16>),
    RegRange(u16, u16), // first..last inclusive
}

// -- Tokenizer -----------------------------------------------------------------

/// Split `s` into whitespace-separated tokens *after* skipping the opcode.
/// Returns `(operand_str, operands)`.
fn tokenize(operands: &str) -> Result<Vec<Token>> {
    let s = operands.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut tokens = Vec::new();
    let mut rest = s;

    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }
        // Skip commas
        if rest.starts_with(',') {
            rest = &rest[1..];
            continue;
        }

        let (tok, tail) = next_token(rest)?;
        tokens.push(tok);
        rest = tail;
    }
    Ok(tokens)
}

fn next_token(s: &str) -> Result<(Token, &str)> {
    let s = s.trim_start();
    let bytes = s.as_bytes();
    match bytes.first() {
        // Register: v0..v65535
        Some(b'v') => {
            let end = s[1..]
                .find(|c: char| !c.is_ascii_digit())
                .map(|i| i + 1)
                .unwrap_or(s.len());
            let num_str = &s[1..end];
            let n: u16 = num_str
                .parse()
                .map_err(|_| DexError::DexFileError(format!("bad v-register: {s:?}")))?;
            Ok((Token::Register(n), &s[end..]))
        }

        // p-register: p0..p255 — kept as Token::PRegister; caller resolves to vN
        Some(b'p') => {
            let end = s[1..]
                .find(|c: char| !c.is_ascii_digit())
                .map(|i| i + 1)
                .unwrap_or(s.len());
            let num_str = &s[1..end];
            let n: u16 = num_str
                .parse()
                .map_err(|_| DexError::DexFileError(format!("bad p-register: {s:?}")))?;
            Ok((Token::PRegister(n), &s[end..]))
        }

        // Register list: {v0, v1, v2} or {v0 .. v3} or {}
        Some(b'{') => {
            let close =
                s.find('}').ok_or_else(|| DexError::DexFileError("unclosed {".into()))?;
            let inner = &s[1..close];
            let rest = &s[close + 1..];
            // Range form: {vA .. vB}
            if inner.contains("..") {
                let parts: Vec<&str> = inner.splitn(2, "..").collect();
                let first = parse_reg(parts[0].trim())?;
                let last = parse_reg(parts[1].trim())?;
                Ok((Token::RegRange(first, last), rest))
            } else {
                // Handle empty list {}
                let inner = inner.trim();
                let regs = if inner.is_empty() {
                    Vec::new()
                } else {
                    inner
                        .split(',')
                        .map(|r| parse_reg(r.trim()))
                        .collect::<Result<Vec<_>>>()?
                };
                Ok((Token::RegList(regs), rest))
            }
        }

        // String literal: "..." with proper escape handling
        Some(b'"') => {
            let mut chars = s[1..].char_indices();
            let mut end = s.len(); // fallback: consume all
            let mut found = false;
            while let Some((i, c)) = chars.next() {
                if c == '"' {
                    end = 1 + i + 1; // +1 for leading '"', +1 past closing '"'
                    found = true;
                    break;
                }
                if c == '\\' {
                    chars.next(); // skip the escaped character
                }
            }
            if !found {
                return Err(DexError::DexFileError("unclosed string literal".into()));
            }
            let inner = &s[1..end - 1];
            // Unescape \n, \t, \\, \"
            let unescaped = inner
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
            Ok((Token::StringLit(unescaped), &s[end..]))
        }

        // Literal: #<value> or #<type> <value>  (e.g. #+42, #-1, #int +65536)
        Some(b'#') => {
            let rest = s.strip_prefix('#').unwrap().trim_start();
            // Skip optional type keyword (int, long, float, double, short, byte, char)
            let rest = skip_type_keyword(rest);
            let rest = rest.trim_start();
            let end = rest
                .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .unwrap_or(rest.len());
            if end == 0 {
                return Err(DexError::DexFileError(format!(
                    "empty literal after '#' in {s:?}"
                )));
            }
            let v = parse_int(&rest[..end])?;
            Ok((Token::Literal(v), &rest[end..]))
        }

        // Branch target / label: :name
        Some(b':') => {
            let rest = s.strip_prefix(':').unwrap();
            let end = rest
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(rest.len());
            Ok((Token::Label(rest[..end].to_string()), &rest[end..]))
        }

        // Type/Method/Field reference: L...; or [[...
        Some(b'L') | Some(b'[') => parse_reference(s),

        // Primitive type descriptor (V, I, B, etc.) — treat as type ref
        Some(b'V')
        | Some(b'B')
        | Some(b'C')
        | Some(b'D')
        | Some(b'F')
        | Some(b'I')
        | Some(b'J')
        | Some(b'S')
        | Some(b'Z') => {
            let end = s
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(s.len());
            Ok((Token::TypeRef(s[..end].to_string()), &s[end..]))
        }

        // Signed integer literal (no # prefix) — branch offsets (+5, -3) and bare numbers
        Some(c) if (*c as char).is_ascii_digit() || *c == b'-' || *c == b'+' => {
            let end = s
                .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .unwrap_or(s.len());
            let v = parse_int(&s[..end])?;
            Ok((Token::Literal(v), &s[end..]))
        }

        other => Err(DexError::DexFileError(format!(
            "unexpected token start: {:?} in {:?}",
            other.map(|c| *c as char),
            s
        ))),
    }
}

/// Parse a register operand (`vN` or `pN`) and return the raw register index.
/// p-registers are returned as-is; callers must resolve them using `registers - ins + pN`.
fn parse_reg(s: &str) -> Result<u16> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('v') {
        rest.parse().map_err(|_| DexError::DexFileError(format!("bad v-register {s:?}")))
    } else if let Some(rest) = s.strip_prefix('p') {
        rest.parse().map_err(|_| DexError::DexFileError(format!("bad p-register {s:?}")))
    } else {
        Err(DexError::DexFileError(format!("expected register, got {s:?}")))
    }
}

fn parse_int(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(DexError::DexFileError("empty integer".into()));
    }
    let negative = s.starts_with('-');
    // Strip sign prefix (+ or -)
    let s2 = s.trim_start_matches(['-', '+']);
    let v: u64 = if let Some(hex) = s2.strip_prefix("0x").or_else(|| s2.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map_err(|_| DexError::DexFileError(format!("bad hex: {s:?}")))?
    } else {
        s2.parse::<u64>().map_err(|_| DexError::DexFileError(format!("bad int: {s:?}")))?
    };
    Ok(if negative { -(v as i64) } else { v as i64 })
}

/// Skip an optional type-keyword prefix (`int`, `long`, `float`, `double`,
/// `short`, `byte`, `char`) from a literal operand such as `int +65536`.
/// Returns the remainder after the keyword (and any whitespace).
fn skip_type_keyword(s: &str) -> &str {
    const KEYWORDS: &[&str] = &["int", "long", "float", "double", "short", "byte", "char"];
    for kw in KEYWORDS {
        if let Some(rest) = s.strip_prefix(kw) {
            if rest.is_empty()
                || rest.starts_with(|c: char| c.is_whitespace() || c == '+' || c == '-')
            {
                return rest.trim_start();
            }
        }
    }
    s
}

/// Parse a type/method/field reference starting at `s`.
fn parse_reference(s: &str) -> Result<(Token, &str)> {
    // Find the end of the class descriptor (up to but not including '>')
    let (class_desc, after_class) = consume_type_desc(s);
    let after_class = after_class.trim();

    if after_class.starts_with("->") {
        // Method or field reference
        let after_arrow = after_class.strip_prefix("->").unwrap();
        // Find the member name (up to '(' for method, ':' for field)
        if let Some(paren) = after_arrow.find('(') {
            // Method reference: name(params)return
            let name = &after_arrow[..paren];
            let after_name = &after_arrow[paren..];
            // Find matching ')'
            let close = after_name
                .find(')')
                .ok_or_else(|| DexError::DexFileError("unclosed method descriptor".into()))?;
            let params_str = &after_name[1..close];
            let return_str = &after_name[close + 1..];
            // Return type can be any type descriptor; consume one
            let (return_desc, rest_after_ref) = consume_type_desc(return_str);
            let params = parse_type_list(params_str);
            let end = s.len() - rest_after_ref.len();
            Ok((
                Token::MethodRef {
                    class: class_desc.to_string(),
                    name: name.to_string(),
                    proto: ProtoKey::new(return_desc, params),
                },
                &s[end..],
            ))
        } else if let Some(colon) = after_arrow.find(':') {
            // Field reference: name:type
            let name = &after_arrow[..colon];
            let type_str = &after_arrow[colon + 1..];
            let (field_type, rest_after_ref) = consume_type_desc(type_str);
            let end = s.len() - rest_after_ref.len();
            Ok((
                Token::FieldRef {
                    class: class_desc.to_string(),
                    name: name.to_string(),
                    field_type: field_type.to_string(),
                },
                &s[end..],
            ))
        } else {
            Err(DexError::DexFileError(format!(
                "expected '(' or ':' after '->' in {:?}",
                &after_class[..20.min(after_class.len())]
            )))
        }
    } else {
        // Plain type reference (no '->').
        let end = s.len() - after_class.len();
        Ok((Token::TypeRef(class_desc.to_string()), &s[end..]))
    }
}

/// Consume one DEX type descriptor from the start of `s`.
/// Returns `(descriptor, remainder)` where `remainder` is the rest after the descriptor
/// and any optional trailing whitespace.
fn consume_type_desc(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b'[') => {
            let mut i = 0;
            while i < bytes.len() && bytes[i] == b'[' {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'L' {
                let end = s[i..].find(';').map(|p| i + p + 1).unwrap_or(s.len());
                (&s[..end], &s[end..])
            } else if i < bytes.len() {
                (&s[..i + 1], &s[i + 1..])
            } else {
                (s, "")
            }
        }
        Some(b'L') => {
            let end = s.find(';').map(|p| p + 1).unwrap_or(s.len());
            (&s[..end], &s[end..])
        }
        Some(_) => {
            // Primitive
            let end = s
                .find(|c: char| c == ',' || c.is_whitespace() || c == '}')
                .unwrap_or(s.len());
            (&s[..end.max(1)], &s[end.max(1)..])
        }
        None => ("", ""),
    }
}

// -- Instruction encoder -------------------------------------------------------

/// Encode a single [`InsnNode`] (with already-resolved reference index and
/// branch offset) to one or more 16-bit code units.
pub(crate) fn encode_insn(
    opcode: Code,
    regs: &[u16],
    literal: i64,
    ref_idx: Option<u32>,
    branch_offset: Option<i32>,
) -> Result<Vec<u16>> {
    use Format::*;
    let op = opcode as u8 as u16;
    let fmt = Instruction::format_of(opcode);
    let idx = ref_idx.unwrap_or(0);
    let offset = branch_offset.unwrap_or(0);
    let r0 = regs.first().copied().unwrap_or(0);
    let r1 = regs.get(1).copied().unwrap_or(0);
    let r2 = regs.get(2).copied().unwrap_or(0);

    let words: Vec<u16> = match fmt {
        // 1-word formats
        k10x => vec![op],
        k12x => vec![op | ((r0 & 0xF) << 8) | ((r1 & 0xF) << 12)],
        k11n => vec![op | ((r0 & 0xF) << 8) | (((literal as u8) & 0xF) as u16) << 12],
        k11x => vec![op | ((r0 & 0xFF) << 8)],
        k10t => vec![op | (((offset as i8) as u8 as u16) << 8)],
        // 2-word formats
        k20t => vec![op, offset as u16],
        k22x => vec![op | ((r0 & 0xFF) << 8), r1],
        k21t => vec![op | ((r0 & 0xFF) << 8), offset as u16],
        k21s => vec![op | ((r0 & 0xFF) << 8), literal as i16 as u16],
        k21h => {
            // CONST_HIGH16 stores bits [31:16]; CONST_WIDE_HIGH16 stores bits [63:48].
            let encoded = if opcode == Code::CONST_WIDE_HIGH16 {
                (literal >> 48) as u16
            } else {
                (literal >> 16) as u16
            };
            vec![op | ((r0 & 0xFF) << 8), encoded]
        }
        k21c => vec![op | ((r0 & 0xFF) << 8), idx as u16],
        k23x => vec![op | ((r0 & 0xFF) << 8), ((r2 & 0xFF) << 8) | (r1 & 0xFF)],
        k22b => vec![
            op | ((r0 & 0xFF) << 8),
            (((literal as i8) as u8 as u16) << 8) | (r1 & 0xFF),
        ],
        k22t => vec![
            op | ((r0 & 0xF) << 8) | ((r1 & 0xF) << 12),
            offset as u16,
        ],
        k22s => vec![
            op | ((r0 & 0xF) << 8) | ((r1 & 0xF) << 12),
            literal as i16 as u16,
        ],
        k22c => vec![
            op | ((r0 & 0xF) << 8) | ((r1 & 0xF) << 12),
            idx as u16,
        ],
        // 3-word formats
        k32x => vec![op, r0, r1],
        k30t => {
            let o = offset as u32;
            vec![op, o as u16, (o >> 16) as u16]
        }
        k31t | k31i => {
            let v = if matches!(fmt, k31t) { offset as u32 } else { literal as u32 };
            vec![op | ((r0 & 0xFF) << 8), v as u16, (v >> 16) as u16]
        }
        k31c => {
            vec![op | ((r0 & 0xFF) << 8), idx as u16, (idx >> 16) as u16]
        }
        k35c | k45cc => {
            // A|G|op BBBB F|E|D|C [HHHH for k45cc]
            let count = regs.len() as u16;
            let g = regs.get(4).copied().unwrap_or(0) & 0xF;
            let word0 = op | (g << 8) | (count << 12);
            let word2 = (regs.first().copied().unwrap_or(0) & 0xF)
                | ((regs.get(1).copied().unwrap_or(0) & 0xF) << 4)
                | ((regs.get(2).copied().unwrap_or(0) & 0xF) << 8)
                | ((regs.get(3).copied().unwrap_or(0) & 0xF) << 12);
            if matches!(fmt, k45cc) {
                vec![word0, idx as u16, word2, 0] // second idx = 0 for now
            } else {
                vec![word0, idx as u16, word2]
            }
        }
        k3rc | k4rcc => {
            // AA|op BBBB CCCC [HHHH for k4rcc]
            let count = regs.len() as u16;
            let first = r0;
            if matches!(fmt, k4rcc) {
                vec![op | (count << 8), idx as u16, first, 0]
            } else {
                vec![op | (count << 8), idx as u16, first]
            }
        }
        k51l => {
            let v = literal as u64;
            vec![
                op | ((r0 & 0xFF) << 8),
                v as u16,
                (v >> 16) as u16,
                (v >> 32) as u16,
                (v >> 48) as u16,
            ]
        }
        _ => {
            return Err(DexError::DexFileError(format!(
                "unsupported format {fmt:?} for opcode {:?}",
                opcode
            )))
        }
    };
    Ok(words)
}

// -- Instruction node with pending branch / ref --------------------------------

/// An instruction before branch-offset resolution.
#[derive(Clone, Debug)]
struct PendingInsn {
    node: InsnNode,
    /// Width hint for branch instructions (in code units).
    branch_width: u8,
}

impl PendingInsn {
    fn insn_size(&self) -> usize {
        let fmt = Instruction::format_of(self.node.opcode);
        use Format::*;
        match fmt {
            k10x | k12x | k11n | k11x | k10t => 1,
            k20t | k22x | k21t | k21s | k21h | k21c | k23x | k22b | k22t | k22s | k22c => 2,
            k32x | k30t | k31t | k31i | k31c | k35c | k3rc => 3,
            k45cc | k4rcc => 4,
            k51l => 5,
            _ => 1,
        }
    }
}

// -- CodeBuilder ---------------------------------------------------------------

/// Assembler for a single DEX method body.
///
/// Accumulate instructions with [`emit`](Self::emit) and labels with
/// [`label`](Self::label), then call [`build`](Self::build) to produce a
/// [`CodeDef`].
pub struct CodeBuilder {
    registers: u16,
    ins: u16,
    outs: u16,
    insns: Vec<PendingInsn>,
    labels: HashMap<String, usize>, // label -> insn index
    tries: Vec<TryDef>,
}

impl CodeBuilder {
    /// Create a builder for a method with `registers` total registers,
    /// `ins` incoming parameter registers, and `outs` outgoing parameter slots.
    pub fn new(registers: u16, ins: u16, outs: u16) -> Self {
        Self { registers, ins, outs, insns: Vec::new(), labels: HashMap::new(), tries: Vec::new() }
    }

    /// Place a named label at the current instruction position.
    pub fn label(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.insns.len());
    }

    /// Add a try block.
    pub fn add_try(&mut self, t: TryDef) {
        self.tries.push(t);
    }

    /// Parse and add one instruction from disassembly text.
    ///
    /// The line format is `opcode [operand, ...]`, for example:
    /// ```text
    /// const-string v0, "hello"
    /// invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    /// if-eqz v0, :loop
    /// ```
    pub fn emit(&mut self, line: &str) -> Result<()> {
        let node = parse_line(line)?;
        let branch_width = branch_width_for(&node);
        self.insns.push(PendingInsn { node, branch_width });
        Ok(())
    }

    /// Add a pre-built [`InsnNode`] directly (bypass the text parser).
    pub fn add_insn(&mut self, node: InsnNode) {
        let branch_width = branch_width_for(&node);
        self.insns.push(PendingInsn { node, branch_width });
    }

    /// Add raw pre-encoded bytecode words.
    pub fn add_raw(&mut self, words: &[u16]) {
        // Wrap in a NOP node carrying the raw words as a payload via literal.
        // We'll detect this in `build()` by checking a sentinel opcode.
        // Actually, easier to just expand to NOP instructions and embed directly.
        // For now, push each word as a special raw node.
        for (i, &w) in words.iter().enumerate() {
            let opcode = Instruction::opcode_of(w);
            let mut node = InsnNode::new(opcode);
            node.literal = i as i64; // index into original raw slice
            self.insns.push(PendingInsn { node, branch_width: 0 });
        }
    }

    /// Resolve labels and widen branches as needed, then return symbolic
    /// [`InsnNode`]s with all [`BranchTarget::Label`] targets resolved to
    /// [`BranchTarget::Offset`].
    ///
    /// Pool references (strings, types, fields, methods) remain symbolic and
    /// are resolved by [`crate::file::writer::DexWriter`] at serialisation
    /// time.  Returns `Err` if a label is referenced but never defined.
    pub fn build(mut self) -> Result<CodeDef> {
        // Iterative branch-width fixup: widen branches until stable.
        for _ in 0..5 {
            let widened = self.fixup_branches()?;
            if !widened {
                break;
            }
        }

        // Resolve all label targets to concrete PC-relative offsets.
        let pcs = compute_pcs(&self.insns);
        let mut resolved: Vec<InsnNode> = Vec::with_capacity(self.insns.len());

        for (i, pending) in self.insns.into_iter().enumerate() {
            let mut node = pending.node;
            if let Some(BranchTarget::Label(ref lbl)) = node.target.clone() {
                let target_pc = self
                    .labels
                    .get(lbl.as_str())
                    .map(|&idx| pcs[idx] as i32)
                    .ok_or_else(|| {
                        DexError::DexFileError(format!("undefined label: {lbl:?}"))
                    })?;
                node.target = Some(BranchTarget::Offset(target_pc - pcs[i] as i32));
            }
            resolved.push(node);
        }

        Ok(CodeDef {
            registers: self.registers,
            ins: self.ins,
            outs: self.outs,
            insns: resolved,
            tries: self.tries,
        })
    }

    /// One pass of branch-width fixup.  Returns `true` if any branch was widened.
    fn fixup_branches(&mut self) -> Result<bool> {
        let pcs = compute_pcs(&self.insns);
        let mut widened = false;

        for (i, pending) in self.insns.iter_mut().enumerate() {
            let node = &pending.node;
            if let Some(BranchTarget::Label(lbl)) = &node.target {
                let target_idx = self.labels.get(lbl.as_str()).copied().ok_or_else(|| {
                    DexError::DexFileError(format!("undefined label: {lbl:?}"))
                })?;
                let offset = pcs[target_idx] as i32 - pcs[i] as i32;
                let needed = if offset >= i8::MIN as i32 && offset <= i8::MAX as i32 {
                    1
                } else if offset >= i16::MIN as i32 && offset <= i16::MAX as i32 {
                    2
                } else {
                    3
                };
                if needed > pending.branch_width {
                    pending.branch_width = needed;
                    // Widen the opcode
                    pending.node.opcode = widen_branch(pending.node.opcode);
                    widened = true;
                }
            }
        }
        Ok(widened)
    }
}

/// Compute the PC (in code units) of each instruction.
fn compute_pcs(insns: &[PendingInsn]) -> Vec<u32> {
    let mut pcs = Vec::with_capacity(insns.len() + 1);
    let mut pc = 0u32;
    for insn in insns {
        pcs.push(pc);
        pc += insn.insn_size() as u32;
    }
    pcs.push(pc); // sentinel
    pcs
}

fn branch_width_for(node: &InsnNode) -> u8 {
    use Format::*;
    match Instruction::format_of(node.opcode) {
        k10t => 1,
        k20t => 2,
        k30t => 3,
        k21t | k22t => 2,
        k31t => 3,
        _ => 0,
    }
}

/// Widen a branch opcode to handle larger offsets.
fn widen_branch(op: Code) -> Code {
    match op {
        Code::GOTO => Code::GOTO_16,
        Code::GOTO_16 => Code::GOTO_32,
        _ => op, // if-* branches max at 16-bit; can't widen further
    }
}

// -- Disassembly text parser ---------------------------------------------------

/// Parse a single disassembly line into an [`InsnNode`].
fn parse_line(line: &str) -> Result<InsnNode> {
    let line = line.trim();
    // Split opcode from operands (first whitespace).
    let (mnemonic, operands_str) = if let Some(sp) = line.find(|c: char| c.is_whitespace()) {
        (&line[..sp], line[sp..].trim())
    } else {
        (line, "")
    };

    // Strip inline comments (//)
    let operands_str = if let Some(pos) = operands_str.find("//") {
        &operands_str[..pos]
    } else {
        operands_str
    };
    let operands_str = operands_str.trim();

    let opcode = opcode_map()
        .get(mnemonic)
        .copied()
        .ok_or_else(|| DexError::DexFileError(format!("unknown opcode: {mnemonic:?}")))?;

    let fmt = Instruction::format_of(opcode);
    let index_type = Instruction::index_type_of(opcode);

    // Tokenize operands.
    let tokens = tokenize(operands_str)?;

    use Format::*;

    let mut node = InsnNode::new(opcode);

    match fmt {
        // -- No operands ------------------------------------------------------
        k10x => {}

        // -- Single register --------------------------------------------------
        k11x => {
            node.regs = vec![require_reg(&tokens, 0)?];
        }

        // -- Two 4-bit registers (k12x) ---------------------------------------
        k12x => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
        }

        // -- 4-bit reg + 4-bit literal (k11n) ---------------------------------
        k11n => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.literal = require_literal(&tokens, 1)?;
        }

        // -- 8-bit branch (k10t) -----------------------------------------------
        k10t => {
            node.target = Some(require_target(&tokens, 0)?);
        }

        // -- 16-bit branch (k20t) ----------------------------------------------
        k20t => {
            node.target = Some(require_target(&tokens, 0)?);
        }

        // -- 32-bit branch (k30t) ----------------------------------------------
        k30t => {
            node.target = Some(require_target(&tokens, 0)?);
        }

        // -- reg + 16-bit branch (k21t) ----------------------------------------
        k21t => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.target = Some(require_target(&tokens, 1)?);
        }

        // -- two 4-bit regs + 16-bit branch (k22t) ----------------------------
        k22t => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
            node.target = Some(require_target(&tokens, 2)?);
        }

        // -- reg + 16-bit literal (k21s, k22s) --------------------------------
        k21s => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.literal = require_literal(&tokens, 1)?;
        }

        // -- reg + high-16 literal (k21h) --------------------------------------
        // The assembler text carries the full shifted value (e.g. #+65536 for
        // const/high16 v0, 0x10000); encode_insn then extracts the high 16 bits.
        k21h => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.literal = require_literal(&tokens, 1)?;
        }

        // -- reg + 32-bit literal / branch (k31i, k31t) -----------------------
        k31i => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.literal = require_literal(&tokens, 1)?;
        }
        k31t => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.target = Some(require_target(&tokens, 1)?);
        }

        // -- reg + 64-bit literal (k51l) ---------------------------------------
        k51l => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.literal = require_literal(&tokens, 1)?;
        }

        // -- reg + 16-bit index (k21c, k31c) ----------------------------------
        k21c | k31c => {
            node.regs = vec![require_reg(&tokens, 0)?];
            node.reference = Some(make_ref(index_type, &tokens, 1)?);
        }

        // -- 3 × 8-bit reg (k23x) ---------------------------------------------
        k23x => {
            node.regs = vec![
                require_reg(&tokens, 0)?,
                require_reg(&tokens, 1)?,
                require_reg(&tokens, 2)?,
            ];
        }

        // -- 8-bit reg pair + 8-bit literal (k22b) ----------------------------
        k22b => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
            node.literal = require_literal(&tokens, 2)?;
        }

        // -- two 4-bit regs + 16-bit literal (k22s) ---------------------------
        k22s => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
            node.literal = require_literal(&tokens, 2)?;
        }

        // -- two 4-bit regs + 16-bit index (k22c) -----------------------------
        k22c => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
            node.reference = Some(make_ref(index_type, &tokens, 2)?);
        }

        // -- 8-bit reg + 16-bit reg (k22x) ------------------------------------
        k22x => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
        }

        // -- two 16-bit regs (k32x) --------------------------------------------
        k32x => {
            node.regs = vec![require_reg(&tokens, 0)?, require_reg(&tokens, 1)?];
        }

        // -- invoke with register list + index (k35c, k45cc) ------------------
        k35c | k45cc => {
            node.regs = require_reg_list(&tokens, 0)?;
            node.reference = Some(make_ref(index_type, &tokens, 1)?);
        }

        // -- invoke range + index (k3rc, k4rcc) -------------------------------
        k3rc | k4rcc => {
            node.regs = require_reg_range(&tokens, 0)?;
            node.reference = Some(make_ref(index_type, &tokens, 1)?);
        }

        _ => {
            return Err(DexError::DexFileError(format!(
                "unsupported format {fmt:?} for opcode {mnemonic:?}"
            )))
        }
    }
    Ok(node)
}

// -- Token extractors ----------------------------------------------------------

fn require_reg(tokens: &[Token], idx: usize) -> Result<u16> {
    match tokens.get(idx) {
        Some(Token::Register(r)) => Ok(*r),
        Some(Token::PRegister(r)) => Ok(*r), // caller resolves p-regs if needed
        other => Err(DexError::DexFileError(format!(
            "expected register at token {idx}, got {other:?}"
        ))),
    }
}

fn require_literal(tokens: &[Token], idx: usize) -> Result<i64> {
    match tokens.get(idx) {
        Some(Token::Literal(v)) => Ok(*v),
        other => Err(DexError::DexFileError(format!(
            "expected literal at token {idx}, got {other:?}"
        ))),
    }
}

fn require_target(tokens: &[Token], idx: usize) -> Result<BranchTarget> {
    match tokens.get(idx) {
        Some(Token::Label(s)) => Ok(BranchTarget::Label(s.clone())),
        Some(Token::Literal(v)) => Ok(BranchTarget::Offset(*v as i32)),
        other => Err(DexError::DexFileError(format!(
            "expected branch target at token {idx}, got {other:?}"
        ))),
    }
}

fn require_reg_list(tokens: &[Token], idx: usize) -> Result<Vec<u16>> {
    match tokens.get(idx) {
        Some(Token::RegList(r)) => Ok(r.clone()),
        Some(Token::RegRange(first, last)) => Ok((*first..=*last).collect()),
        // Single register not in braces — still valid
        Some(Token::Register(r)) | Some(Token::PRegister(r)) => Ok(vec![*r]),
        other => Err(DexError::DexFileError(format!(
            "expected register list at token {idx}, got {other:?}"
        ))),
    }
}

fn require_reg_range(tokens: &[Token], idx: usize) -> Result<Vec<u16>> {
    match tokens.get(idx) {
        Some(Token::RegRange(first, last)) => Ok((*first..=*last).collect()),
        Some(Token::RegList(r)) => Ok(r.clone()),
        other => Err(DexError::DexFileError(format!(
            "expected register range at token {idx}, got {other:?}"
        ))),
    }
}

fn make_ref(
    index_type: &crate::file::instruction::IndexType,
    tokens: &[Token],
    idx: usize,
) -> Result<DexRef> {
    use crate::file::instruction::IndexType::*;
    let tok = tokens.get(idx).ok_or_else(|| {
        DexError::DexFileError(format!("missing reference operand at token {idx}"))
    })?;
    match (index_type, tok) {
        (StringRef, Token::StringLit(s)) => Ok(DexRef::String(s.clone())),
        (StringRef, Token::TypeRef(s)) => Ok(DexRef::String(s.clone())),
        (TypeRef, Token::TypeRef(s)) => Ok(DexRef::Type(s.clone())),
        (MethodRef, Token::MethodRef { class, name, proto }) => Ok(DexRef::Method {
            class: class.clone(),
            name: name.clone(),
            proto: proto.clone(),
        }),
        (FieldRef, Token::FieldRef { class, name, field_type }) => Ok(DexRef::Field {
            class: class.clone(),
            name: name.clone(),
            field_type: field_type.clone(),
        }),
        // Best-effort fallbacks
        (_, Token::StringLit(s)) => Ok(DexRef::String(s.clone())),
        (_, Token::TypeRef(s)) => Ok(DexRef::Type(s.clone())),
        (_, Token::MethodRef { class, name, proto }) => Ok(DexRef::Method {
            class: class.clone(),
            name: name.clone(),
            proto: proto.clone(),
        }),
        (_, Token::FieldRef { class, name, field_type }) => Ok(DexRef::Field {
            class: class.clone(),
            name: name.clone(),
            field_type: field_type.clone(),
        }),
        _ => Err(DexError::DexFileError(format!(
            "unexpected token {tok:?} for index type {index_type:?} at position {idx}"
        ))),
    }
}

// -- DexIrBuilder — high-level builder facade ----------------------------------

/// High-level builder that progressively constructs a [`DexIr`] and emits classes,
/// methods, and fields through a fluent API.
///
/// ```rust
/// use dexrs::file::builder::DexIrBuilder;
/// use dexrs::file::modifiers::{ACC_PUBLIC, ACC_STATIC};
///
/// let mut b = DexIrBuilder::new(35);
/// let mut cb = b.begin_class("Lhello/World;", ACC_PUBLIC, Some("Ljava/lang/Object;"), None);
/// let (method, mut code) = cb.begin_method("main", "([Ljava/lang/String;)V", ACC_PUBLIC | ACC_STATIC, 3, 1, 2);
/// code.emit("return-void").unwrap();
/// cb.finish_method((method, code)).unwrap();
/// b.finish_class(cb);
/// let ir = b.finish();
/// ```
pub struct DexIrBuilder {
    ir: crate::file::ir::DexIr,
}

/// In-progress class builder returned by [`DexIrBuilder::begin_class`].
pub struct ClassBuilder {
    class: crate::file::ir::ClassDef,
}

impl DexIrBuilder {
    pub fn new(version: u32) -> Self {
        Self { ir: crate::file::ir::DexIr::new(version) }
    }

    /// Begin defining a class.
    pub fn begin_class(
        &mut self,
        descriptor: &str,
        access_flags: u32,
        superclass: Option<&str>,
        source_file: Option<&str>,
    ) -> ClassBuilder {
        let mut c = crate::file::ir::ClassDef::new(descriptor).access(access_flags);
        if let Some(s) = superclass {
            c = c.superclass(s);
        }
        if let Some(sf) = source_file {
            c = c.source_file(sf);
        }
        ClassBuilder { class: c }
    }

    /// Add a completed class to the IR.
    pub fn finish_class(&mut self, builder: ClassBuilder) {
        self.ir.add_class(builder.class);
    }

    /// Consume the builder and return the completed IR.
    pub fn finish(self) -> crate::file::ir::DexIr {
        self.ir
    }
}

impl ClassBuilder {
    /// Begin defining a method.  Returns a [`CodeBuilder`] pre-configured with
    /// the register / in / out counts.
    pub fn begin_method(
        &self,
        name: &str,
        descriptor: &str,
        access_flags: u32,
        registers: u16,
        ins: u16,
        outs: u16,
    ) -> (MethodDef, CodeBuilder) {
        let proto = ProtoKey::from_descriptor(descriptor)
            .unwrap_or_else(|| ProtoKey::new("V", [] as [&str; 0]));
        let method = MethodDef::new(name, proto).access(access_flags);
        let code = CodeBuilder::new(registers, ins, outs);
        (method, code)
    }

    /// Add a static field.
    pub fn add_static_field(&mut self, name: &str, field_type: &str, access_flags: u32) {
        self.class.add_static_field(
            crate::file::ir::FieldDef::new(name, field_type).access(access_flags),
        );
    }

    /// Add an instance field.
    pub fn add_instance_field(&mut self, name: &str, field_type: &str, access_flags: u32) {
        self.class.add_instance_field(
            crate::file::ir::FieldDef::new(name, field_type).access(access_flags),
        );
    }

    /// Finalise a method (build its code) and add it to this class.
    pub fn finish_method(&mut self, method_and_code: (MethodDef, CodeBuilder)) -> Result<()> {
        let (mut method, code_builder) = method_and_code;
        method.code = Some(code_builder.build()?);
        // Determine whether this is direct or virtual based on name + access flags.
        if method.name.starts_with('<') || method.access_flags & 0x0008 != 0
            || method.access_flags & 0x0002 != 0 || method.access_flags & 0x0200 != 0
        {
            self.class.add_direct_method(method);
        } else {
            self.class.add_virtual_method(method);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::instruction::Code;

    #[test]
    fn parse_nop() {
        let node = parse_line("nop").unwrap();
        assert_eq!(node.opcode, Code::NOP);
    }

    #[test]
    fn parse_return_void() {
        let node = parse_line("return-void").unwrap();
        assert_eq!(node.opcode, Code::RETURN_VOID);
    }

    #[test]
    fn parse_const_string() {
        let node = parse_line(r#"const-string v0, "hello""#).unwrap();
        assert_eq!(node.opcode, Code::CONST_STRING);
        assert_eq!(node.regs, vec![0]);
        assert!(matches!(&node.reference, Some(DexRef::String(s)) if s == "hello"));
    }

    #[test]
    fn parse_invoke_virtual() {
        let node =
            parse_line("invoke-virtual {v0, v1}, Ljava/lang/Object;->toString()Ljava/lang/String;")
                .unwrap();
        assert_eq!(node.opcode, Code::INVOKE_VIRTUAL);
        assert_eq!(node.regs, vec![0, 1]);
        assert!(matches!(
            &node.reference,
            Some(DexRef::Method { name, .. }) if name == "toString"
        ));
    }

    #[test]
    fn parse_iget_object() {
        let node =
            parse_line("iget-object v0, v1, Lcom/example/Foo;->bar:Ljava/lang/String;").unwrap();
        assert!(matches!(
            &node.reference,
            Some(DexRef::Field { name, .. }) if name == "bar"
        ));
    }

    #[test]
    fn parse_if_eqz() {
        let node = parse_line("if-eqz v0, :my_label").unwrap();
        assert!(matches!(&node.target, Some(BranchTarget::Label(l)) if l == "my_label"));
    }

    #[test]
    fn parse_const_literal() {
        let node = parse_line("const v0, #42").unwrap();
        assert_eq!(node.literal, 42);
    }

    #[test]
    fn code_builder_return_void() {
        let mut cb = CodeBuilder::new(1, 0, 0);
        cb.emit("return-void").unwrap();
        let code = cb.build().unwrap();
        assert_eq!(code.insns.len(), 1);
        assert_eq!(code.insns[0].opcode, Code::RETURN_VOID);
    }

    #[test]
    fn code_builder_goto_forward() {
        let mut cb = CodeBuilder::new(1, 0, 0);
        cb.emit("nop").unwrap();
        cb.label("end");
        cb.emit("return-void").unwrap();
        // Backward goto test:
        let mut cb2 = CodeBuilder::new(1, 0, 0);
        cb2.label("loop");
        cb2.emit("nop").unwrap();
        cb2.emit("goto :loop").unwrap();
        let code = cb2.build().unwrap();
        // goto is at PC=1, target=0, offset=-1
        let goto_node = &code.insns[1];
        assert_eq!(goto_node.opcode, Code::GOTO);
        assert!(matches!(&goto_node.target, Some(BranchTarget::Offset(-1))));
    }

    #[test]
    fn encode_insn_const_4() {
        let words = encode_insn(Code::CONST_4, &[0], 5, None, None).unwrap();
        assert_eq!(words.len(), 1);
        // const/4: opcode=0x12, A=0, B=5 -> 0x5012
        assert_eq!(words[0], 0x5012);
    }

    // -- Tokenizer hardening tests ---------------------------------------------

    #[test]
    fn parse_positive_signed_literal() {
        // #+42 and +42 must both parse as 42
        let n1 = parse_line("const/16 v0, #+42").unwrap();
        assert_eq!(n1.literal, 42);
        let n2 = parse_line("const v0, #+65536").unwrap();
        assert_eq!(n2.literal, 65536);
    }

    #[test]
    fn parse_negative_signed_literal() {
        let n = parse_line("const/16 v0, #-100").unwrap();
        assert_eq!(n.literal, -100);
    }

    #[test]
    fn parse_hex_literal() {
        let n = parse_line("const v0, #0xff").unwrap();
        assert_eq!(n.literal, 255);
        let n2 = parse_line("const v0, #0x10000").unwrap();
        assert_eq!(n2.literal, 0x10000);
    }

    #[test]
    fn parse_typed_literal_int() {
        // #int +65536 — emitted by dump.rs imm_typed_u32
        let n = parse_line("const/high16 v0, #int +65536").unwrap();
        assert_eq!(n.literal, 65536);
    }

    #[test]
    fn parse_typed_literal_long() {
        // #long +1234567890 — emitted by dump.rs imm_typed_u64
        let n = parse_line("const-wide v0, #long +1234567890").unwrap();
        assert_eq!(n.literal, 1234567890);
    }

    #[test]
    fn parse_goto_positive_offset() {
        // dump.rs emits branch offsets as "+5" or "-3" (no # prefix)
        let n = parse_line("goto +5").unwrap();
        assert!(matches!(n.target, Some(BranchTarget::Offset(5))));
    }

    #[test]
    fn parse_goto_negative_offset() {
        let n = parse_line("goto -3").unwrap();
        assert!(matches!(n.target, Some(BranchTarget::Offset(-3))));
    }

    #[test]
    fn parse_if_eqz_offset() {
        let n = parse_line("if-eqz v0, +12").unwrap();
        assert!(matches!(n.target, Some(BranchTarget::Offset(12))));
    }

    #[test]
    fn parse_invoke_static_empty_args() {
        // invoke-static {} must work (zero-arg static call)
        let n = parse_line("invoke-static {}, Ljava/lang/Object;->clinit()V").unwrap();
        assert_eq!(n.regs, vec![] as Vec<u16>);
        assert!(matches!(&n.reference, Some(DexRef::Method { name, .. }) if name == "clinit"));
    }

    #[test]
    fn parse_string_with_escaped_quote() {
        // The bug: \" inside a string was not properly skipped, terminating early
        let n = parse_line(r#"const-string v0, "say \"hello\"""#).unwrap();
        assert!(
            matches!(&n.reference, Some(DexRef::String(s)) if s == r#"say "hello""#),
            "got: {:?}",
            n.reference
        );
    }

    #[test]
    fn parse_string_with_escape_sequences() {
        let n = parse_line(r#"const-string v0, "line1\nline2\ttab""#).unwrap();
        assert!(matches!(&n.reference, Some(DexRef::String(s)) if s == "line1\nline2\ttab"));
    }

    #[test]
    fn parse_p_register() {
        // p0 should be accepted (treated as register index 0)
        let n = parse_line("return-object p0").unwrap();
        assert_eq!(n.regs, vec![0]);
    }

    #[test]
    fn parse_const_high16_full_value() {
        // The assembler stores the full value; encoder extracts high 16 bits
        let n = parse_line("const/high16 v0, #+65536").unwrap();
        assert_eq!(n.literal, 65536);
        // Encoding: (65536 >> 16) as u16 = 1
        let words = encode_insn(n.opcode, &n.regs, n.literal, None, None).unwrap();
        assert_eq!(words[1], 1); // high word = 1
    }

    #[test]
    fn parse_iget_with_comment() {
        // Comments after // must be stripped before parsing
        let n = parse_line(
            "iget-object v0, v1, Lcom/example/Foo;->mField:Ljava/lang/String; // field@5",
        )
        .unwrap();
        assert!(matches!(&n.reference, Some(DexRef::Field { name, .. }) if name == "mField"));
    }

    #[test]
    fn code_builder_branch_offset_roundtrip() {
        // Build a method where goto uses an offset (not a label)
        let mut cb = CodeBuilder::new(1, 0, 0);
        cb.emit("nop").unwrap();
        cb.emit("goto -1").unwrap(); // jump back to nop at PC=0 (self.offset = -1)
        let code = cb.build().unwrap();
        assert!(matches!(code.insns[1].target, Some(BranchTarget::Offset(-1))));
    }
}
