//! Intermediate representation (IR) for DEX files.
//!
//! The IR stores everything symbolically: class/type/field/method names are kept
//! as plain `String`s, and integer pool indices are assigned only at write time by
//! [`crate::file::writer::DexWriter`].  This makes the representation trivially
//! composable - add a class, add a method, splice in instructions - without having
//! to maintain cross-references by hand.
//!
//! # Quick start
//!
//! ```rust
//! use dexrs::file::ir::{DexIr, ClassDef, MethodDef, ProtoKey, CodeDef};
//! use dexrs::file::builder::CodeBuilder;
//! use dexrs::file::writer::DexWriter;
//! use dexrs::file::modifiers::{ACC_PUBLIC, ACC_STATIC};
//!
//! let mut ir = DexIr::new(35);
//! let mut class = ClassDef::new("Lhello/World;")
//!     .access(ACC_PUBLIC)
//!     .superclass("Ljava/lang/Object;");
//!
//! let mut code = CodeBuilder::new(3, 1, 2);
//! code.emit(r#"sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;"#).unwrap();
//! code.emit(r#"const-string v1, "Hello, World!""#).unwrap();
//! code.emit(r#"invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V"#).unwrap();
//! code.emit("return-void").unwrap();
//!
//! class.add_direct_method(
//!     MethodDef::new("main", ProtoKey::new("V", ["[Ljava/lang/String;"]))
//!         .access(ACC_PUBLIC | ACC_STATIC)
//!         .code(code.build().unwrap()),
//! );
//!
//! ir.add_class(class);
//! let bytes = DexWriter::write(ir).unwrap();
//! ```

use crate::file::instruction::Code;

// -- Proto key -----------------------------------------------------------------

/// Key identifying a method prototype.
///
/// Sorted by return type first, then parameter types lexicographically - the
/// same ordering the DEX spec requires for `proto_ids`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProtoKey {
    /// Return type descriptor, e.g. `"V"`, `"I"`, `"Ljava/lang/String;"`.
    pub return_type: String,
    /// Parameter type descriptors in order.
    pub params: Vec<String>,
}

impl PartialOrd for ProtoKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtoKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rt = self.return_type.cmp(&other.return_type);
        if rt != std::cmp::Ordering::Equal {
            return rt;
        }
        for (a, b) in self.params.iter().zip(other.params.iter()) {
            let c = a.cmp(b);
            if c != std::cmp::Ordering::Equal {
                return c;
            }
        }
        self.params.len().cmp(&other.params.len())
    }
}

impl ProtoKey {
    /// Construct a prototype from a return type and zero or more parameter types.
    pub fn new(
        return_type: impl Into<String>,
        params: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            return_type: return_type.into(),
            params: params.into_iter().map(|s| s.into()).collect(),
        }
    }

    /// Compute the shorty descriptor string, e.g. `"VI"` for `(I)V`.
    ///
    /// Array types (`[...`) and object types (`L...;`) both map to `'L'`.
    pub fn shorty(&self) -> String {
        let mut s = String::with_capacity(1 + self.params.len());
        s.push(shorty_char(&self.return_type));
        for p in &self.params {
            s.push(shorty_char(p));
        }
        s
    }

    /// Parse a JVM-style method descriptor `"(Ljava/lang/String;I)V"` into a `ProtoKey`.
    pub fn from_descriptor(desc: &str) -> Option<Self> {
        let start = desc.find('(')?;
        let end = desc.find(')')?;
        let params_str = &desc[start + 1..end];
        let return_str = &desc[end + 1..];
        let params = parse_type_list(params_str);
        Some(Self::new(return_str, params))
    }
}

/// Map a single DEX type descriptor to its shorty character.
pub(crate) fn shorty_char(desc: &str) -> char {
    match desc.as_bytes().first() {
        Some(b'[') => 'L', // array -> object shorty
        Some(&c) => c as char,
        None => 'V',
    }
}

/// Parse a sequence of DEX type descriptors (as found between `(` and `)` in a method
/// descriptor) into individual descriptors.
pub(crate) fn parse_type_list(mut s: &str) -> Vec<String> {
    let mut result = Vec::new();
    while !s.is_empty() {
        let (desc, rest) = consume_one_type(s);
        result.push(desc.to_string());
        s = rest;
    }
    result
}

/// Consume exactly one DEX type descriptor from the front of `s`.
/// Returns `(descriptor, remainder)`.
pub(crate) fn consume_one_type(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b'[') => {
            // Array: skip all leading '[' and then the element type
            let mut i = 0;
            while i < bytes.len() && bytes[i] == b'[' {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'L' {
                // object array element
                let end = s[i..].find(';').map(|p| i + p + 1).unwrap_or(s.len());
                (&s[..end], &s[end..])
            } else if i < bytes.len() {
                // primitive array element
                (&s[..i + 1], &s[i + 1..])
            } else {
                (s, "")
            }
        }
        Some(b'L') => {
            // Object: read up to and including ';'
            let end = s.find(';').map(|p| p + 1).unwrap_or(s.len());
            (&s[..end], &s[end..])
        }
        Some(_) => (&s[..1], &s[1..]), // primitive
        None => ("", ""),
    }
}

// -- Reference types -----------------------------------------------------------

/// A symbolic DEX reference used in instruction operands.
#[derive(Clone, Debug)]
pub enum DexRef {
    /// A string literal (`const-string`).
    String(String),
    /// A type descriptor (`new-instance`, `check-cast`, `const-class`, etc.).
    Type(String),
    /// A field reference (`iget`, `iput`, `sget`, `sput`, etc.).
    Field {
        class: String,
        name: String,
        field_type: String,
    },
    /// A method reference (`invoke-*`).
    Method {
        class: String,
        name: String,
        proto: ProtoKey,
    },
    /// A method prototype reference (`invoke-polymorphic` second index).
    Proto(ProtoKey),
}

/// A branch target in a code item.
#[derive(Clone, Debug)]
pub enum BranchTarget {
    /// A named label placed with [`CodeBuilder::label`].
    Label(String),
    /// A raw PC-relative offset in code units.
    Offset(i32),
}

// -- Instruction node ----------------------------------------------------------

/// A single instruction in symbolic form (before index assignment or offset
/// resolution).
#[derive(Clone, Debug)]
pub struct InsnNode {
    pub opcode: Code,
    /// Register operands (vA, vB, …). Up to 5 for `k35c`.
    pub regs: Vec<u16>,
    /// Literal value for `const-*`, `add-int/lit*`, etc.
    pub literal: i64,
    /// Reference operand (string, type, field, method, or proto).
    pub reference: Option<DexRef>,
    /// Branch target for `goto`, `if-*`, etc.
    pub target: Option<BranchTarget>,
}

impl InsnNode {
    pub fn new(opcode: Code) -> Self {
        Self {
            opcode,
            regs: Vec::new(),
            literal: 0,
            reference: None,
            target: None,
        }
    }

    pub fn with_regs(mut self, regs: impl IntoIterator<Item = u16>) -> Self {
        self.regs = regs.into_iter().collect();
        self
    }

    pub fn with_literal(mut self, lit: i64) -> Self {
        self.literal = lit;
        self
    }

    pub fn with_reference(mut self, r: DexRef) -> Self {
        self.reference = Some(r);
        self
    }

    pub fn with_target(mut self, t: BranchTarget) -> Self {
        self.target = Some(t);
        self
    }
}

// -- Try/catch IR --------------------------------------------------------------

/// A single catch handler entry.
#[derive(Clone, Debug)]
pub struct CatchHandlerIr {
    /// Exception type descriptor (None = catch-all).
    pub type_desc: Option<String>,
    /// Handler address in code units.
    pub address: u32,
}

/// A try block.
#[derive(Clone, Debug)]
pub struct TryDef {
    /// Start address in code units.
    pub start: u32,
    /// Number of instructions covered.
    pub count: u16,
    /// The catch handlers for this try block.
    pub handlers: Vec<CatchHandlerIr>,
}

// -- Code item IR --------------------------------------------------------------

/// A code item in symbolic form: instructions are kept as [`InsnNode`]s with
/// unresolved pool references.  [`crate::file::writer::DexWriter`] resolves
/// those references against the pool and encodes the instructions to `u16`
/// words during serialization.
///
/// Produced by [`crate::file::builder::CodeBuilder::build`].
#[derive(Clone, Debug)]
pub struct CodeDef {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    /// Symbolic instruction nodes.  Branch offsets are already resolved to
    /// [`BranchTarget::Offset`] by the builder; pool references remain as
    /// symbolic [`DexRef`]s until the writer serializes them.
    pub insns: Vec<InsnNode>,
    pub tries: Vec<TryDef>,
}

impl CodeDef {
    /// A trivial empty code body (a single `return-void`).
    pub fn empty(registers: u16, ins: u16) -> Self {
        Self {
            registers,
            ins,
            outs: 0,
            insns: vec![InsnNode::new(crate::file::instruction::Code::RETURN_VOID)],
            tries: vec![],
        }
    }
}

// -- Static field value IR -----------------------------------------------------

/// A static field initialiser value for `<clinit>` encoded arrays.
#[derive(Clone, Debug)]
pub enum EncodedValueIr {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(String),
    Type(String),
    Null,
}

// -- Field / Method definition -------------------------------------------------

/// A field declaration inside a class.
#[derive(Clone, Debug)]
pub struct FieldDef {
    pub name: String,
    pub field_type: String,
    pub access_flags: u32,
}

impl FieldDef {
    pub fn new(name: impl Into<String>, field_type: impl Into<String>) -> Self {
        Self { name: name.into(), field_type: field_type.into(), access_flags: 0 }
    }

    pub fn access(mut self, flags: u32) -> Self {
        self.access_flags = flags;
        self
    }
}

/// A method declaration (possibly with a body) inside a class.
#[derive(Clone, Debug)]
pub struct MethodDef {
    pub name: String,
    pub proto: ProtoKey,
    pub access_flags: u32,
    pub code: Option<CodeDef>,
}

impl MethodDef {
    pub fn new(name: impl Into<String>, proto: ProtoKey) -> Self {
        Self { name: name.into(), proto, access_flags: 0, code: None }
    }

    pub fn access(mut self, flags: u32) -> Self {
        self.access_flags = flags;
        self
    }

    pub fn code(mut self, code: CodeDef) -> Self {
        self.code = Some(code);
        self
    }
}

// -- Class definition ----------------------------------------------------------

/// A complete class definition, including all fields and methods.
#[derive(Clone, Debug)]
pub struct ClassDef {
    /// Full DEX descriptor, e.g. `"Lcom/example/Foo;"`.
    pub descriptor: String,
    pub access_flags: u32,
    /// Superclass descriptor (`None` means no explicit superclass).
    pub superclass: Option<String>,
    /// Implemented interfaces (type descriptors).
    pub interfaces: Vec<String>,
    /// Source file name (for debug info), e.g. `"Foo.java"`.
    pub source_file: Option<String>,
    pub static_fields: Vec<FieldDef>,
    pub instance_fields: Vec<FieldDef>,
    /// Direct methods: `<init>`, `<clinit>`, and `static` / `private` methods.
    pub direct_methods: Vec<MethodDef>,
    /// Virtual (overridable) methods.
    pub virtual_methods: Vec<MethodDef>,
    /// Initial values for `static` fields (in field declaration order).
    pub static_values: Vec<EncodedValueIr>,
}

impl ClassDef {
    /// Create a minimal class with no superclass, no methods, no fields.
    pub fn new(descriptor: impl Into<String>) -> Self {
        Self {
            descriptor: descriptor.into(),
            access_flags: 0,
            superclass: None,
            interfaces: Vec::new(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
            static_values: Vec::new(),
        }
    }

    pub fn access(mut self, flags: u32) -> Self {
        self.access_flags = flags;
        self
    }

    pub fn superclass(mut self, desc: impl Into<String>) -> Self {
        self.superclass = Some(desc.into());
        self
    }

    pub fn interface(mut self, desc: impl Into<String>) -> Self {
        self.interfaces.push(desc.into());
        self
    }

    pub fn source_file(mut self, name: impl Into<String>) -> Self {
        self.source_file = Some(name.into());
        self
    }

    pub fn add_static_field(&mut self, f: FieldDef) -> &mut Self {
        self.static_fields.push(f);
        self
    }

    pub fn add_instance_field(&mut self, f: FieldDef) -> &mut Self {
        self.instance_fields.push(f);
        self
    }

    pub fn add_direct_method(&mut self, m: MethodDef) -> &mut Self {
        self.direct_methods.push(m);
        self
    }

    pub fn add_virtual_method(&mut self, m: MethodDef) -> &mut Self {
        self.virtual_methods.push(m);
        self
    }
}

// -- Top-level DEX IR ----------------------------------------------------------

/// The complete DEX intermediate representation.
///
/// Build it up with [`DexIr::add_class`], then hand it to
/// [`crate::file::writer::DexWriter::write`] to produce valid DEX bytes.
#[derive(Clone, Debug, Default)]
pub struct DexIr {
    /// DEX version integer (e.g. `35` for `"035\0"`).
    pub version: u32,
    /// All class definitions.  The writer will sort them and assign
    /// indices in the required order.
    pub classes: Vec<ClassDef>,
}

impl DexIr {
    /// Create an empty DEX IR targeting the given version (typically `35`).
    pub fn new(version: u32) -> Self {
        Self { version, classes: Vec::new() }
    }

    /// Add a class definition.
    pub fn add_class(&mut self, class: ClassDef) {
        self.classes.push(class);
    }

    /// Return a mutable reference to the class with the given descriptor, if present.
    pub fn get_class_mut(&mut self, descriptor: &str) -> Option<&mut ClassDef> {
        self.classes.iter_mut().find(|c| c.descriptor == descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_key_shorty_primitives() {
        let p = ProtoKey::new("V", ["I", "J"]);
        assert_eq!(p.shorty(), "VIJ");
    }

    #[test]
    fn proto_key_shorty_objects_and_arrays() {
        let p = ProtoKey::new("Ljava/lang/String;", ["Ljava/lang/Object;", "[I"]);
        assert_eq!(p.shorty(), "LLL"); // return=L, Object->L, [I->L
    }

    #[test]
    fn proto_key_ord() {
        let a = ProtoKey::new("V", [] as [&str; 0]);
        let b = ProtoKey::new("V", ["I"]);
        assert!(a < b);
    }

    #[test]
    fn proto_key_from_descriptor() {
        let p = ProtoKey::from_descriptor("(Ljava/lang/String;I)V").unwrap();
        assert_eq!(p.return_type, "V");
        assert_eq!(p.params, vec!["Ljava/lang/String;", "I"]);
    }

    #[test]
    fn parse_type_list_mixed() {
        let types = parse_type_list("[ILjava/lang/String;B");
        assert_eq!(types, vec!["[I", "Ljava/lang/String;", "B"]);
    }

    #[test]
    fn class_def_builder() {
        let mut c = ClassDef::new("Lcom/example/Foo;")
            .access(0x0001)
            .superclass("Ljava/lang/Object;");
        c.add_direct_method(
            MethodDef::new("<init>", ProtoKey::new("V", [] as [&str; 0]))
                .access(0x0001),
        );
        assert_eq!(c.direct_methods.len(), 1);
        assert_eq!(c.descriptor, "Lcom/example/Foo;");
    }
}
