//! Python bindings for the DEX mutation system.
//!
//! Exposes [`DexIrBuilder`], [`IrClassDef`], [`IrMethodDef`], [`IrFieldDef`],
//! [`CodeBuilder`], [`CodeDef`] and [`ProtoKey`] to Python under
//! `dexrs._internal.builder`.
//!
//! # Python Quick-start
//!
//! ```python
//! from dexrs.builder import DexIrBuilder, IrClassDef, IrMethodDef, CodeBuilder
//!
//! # 1. Build a class
//! cls = IrClassDef("Lhello/World;")
//! cls.set_superclass("Ljava/lang/Object;")
//! cls.set_access(0x0001)          # ACC_PUBLIC
//!
//! # 2. Assemble a method body
//! code = CodeBuilder(registers=3, ins=1, outs=2)
//! code.emit('sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;')
//! code.emit('const-string v1, "Hello!"')
//! code.emit('invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V')
//! code.emit('return-void')
//!
//! # 3. Attach method to class
//! method = IrMethodDef("main", "([Ljava/lang/String;)V", 0x0009)
//! method.set_code(code.build())
//! cls.add_direct_method(method)
//!
//! # 4. Assemble the DEX
//! builder = DexIrBuilder(version=35)
//! builder.add_class(cls)
//! dex_bytes = builder.write()     # -> bytes
//! ```

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

use crate::file::{
    builder::CodeBuilder,
    ir::{ClassDef as IrClassDef, CodeDef, DexIr, FieldDef as IrFieldDef, MethodDef as IrMethodDef, ProtoKey},
    writer::DexWriter,
};

// -- ProtoKey -----------------------------------------------------------------

/// A method prototype: return type + parameter types.
///
/// ```python
/// from dexrs._internal.builder import ProtoKey
/// p = ProtoKey("V", ["I", "Ljava/lang/String;"])
/// assert p.shorty() == "VIL"
/// ```
#[pyclass(name = "ProtoKey", module = "dexrs._internal.builder")]
pub struct PyProtoKey {
    pub(crate) inner: ProtoKey,
}

#[pymethods]
impl PyProtoKey {
    /// ``ProtoKey(return_type, params)``
    #[new]
    pub fn new(return_type: &str, params: Vec<String>) -> Self {
        Self { inner: ProtoKey::new(return_type, params) }
    }

    /// Parse a JVM method descriptor such as ``"([Ljava/lang/String;)V"`` into
    /// a :class:`ProtoKey`.  Returns ``None`` if the descriptor is malformed.
    #[staticmethod]
    pub fn from_descriptor(desc: &str) -> Option<Self> {
        ProtoKey::from_descriptor(desc).map(|p| Self { inner: p })
    }

    /// The return type descriptor, e.g. ``"V"`` or ``"Ljava/lang/String;"``.
    #[getter]
    pub fn return_type(&self) -> &str {
        &self.inner.return_type
    }

    /// List of parameter type descriptors.
    #[getter]
    pub fn params(&self) -> Vec<String> {
        self.inner.params.clone()
    }

    /// Compute the shorty descriptor (e.g. ``"VIL"`` for ``(I Ljava/lang/String;)V``).
    pub fn shorty(&self) -> String {
        self.inner.shorty()
    }

    pub fn __repr__(&self) -> String {
        format!("ProtoKey({:?}, {:?})", self.inner.return_type, self.inner.params)
    }
}

// -- CodeDef ------------------------------------------------------------------

/// A resolved code item produced by :meth:`CodeBuilder.build`.
///
/// Attach to a method with :meth:`IrMethodDef.set_code`.
#[pyclass(name = "CodeDef", module = "dexrs._internal.builder")]
pub struct PyCodeDef {
    pub(crate) inner: CodeDef,
}

#[pymethods]
impl PyCodeDef {
    #[getter]
    pub fn registers(&self) -> u16 {
        self.inner.registers
    }
    #[getter]
    pub fn ins(&self) -> u16 {
        self.inner.ins
    }
    #[getter]
    pub fn outs(&self) -> u16 {
        self.inner.outs
    }
    #[getter]
    pub fn insns_count(&self) -> usize {
        self.inner.insns.len()
    }

    pub fn __repr__(&self) -> String {
        format!(
            "CodeDef(registers={}, ins={}, outs={}, insns={})",
            self.inner.registers,
            self.inner.ins,
            self.inner.outs,
            self.inner.insns.len()
        )
    }
}

// -- CodeBuilder --------------------------------------------------------------

/// Assembles DEX bytecode from disassembly text.
///
/// Usage::
///
///     code = CodeBuilder(registers=2, ins=1, outs=0)
///     code.emit("const/4 v0, #1")
///     code.emit("return v0")
///     code_def = code.build()
///
/// The builder is consumed by :meth:`build`; any further calls raise
/// :exc:`ValueError`.
#[pyclass(name = "CodeBuilder", module = "dexrs._internal.builder")]
pub struct PyCodeBuilder {
    inner: Option<CodeBuilder>,
}

#[pymethods]
impl PyCodeBuilder {
    /// ``CodeBuilder(registers, ins, outs)``
    ///
    /// :param registers: Total number of registers (locals + params).
    /// :param ins: Number of incoming parameter registers.
    /// :param outs: Number of registers required for outgoing calls.
    #[new]
    pub fn new(registers: u16, ins: u16, outs: u16) -> Self {
        Self { inner: Some(CodeBuilder::new(registers, ins, outs)) }
    }

    /// Parse and emit one disassembly line.
    ///
    /// :param line: A single Dalvik disassembly line such as
    ///     ``"invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V"``.
    /// :raises ValueError: If the line cannot be parsed.
    pub fn emit(&mut self, line: &str) -> PyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("CodeBuilder already consumed by build()"))?
            .emit(line)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Place a named label at the current instruction position.
    ///
    /// Reference the label in branch instructions as ``:label``, e.g.
    /// ``"if-eqz v0, :end"``.
    pub fn label(&mut self, name: &str) -> PyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("CodeBuilder already consumed by build()"))?
            .label(name);
        Ok(())
    }

    /// Resolve branches and return a :class:`CodeDef`.
    ///
    /// The builder is consumed and cannot be used after this call.
    ///
    /// :raises ValueError: If a referenced label is undefined.
    pub fn build(&mut self) -> PyResult<PyCodeDef> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyValueError::new_err("CodeBuilder already consumed by build()"))?;
        let code = builder.build().map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyCodeDef { inner: code })
    }

    pub fn __repr__(&self) -> &str {
        if self.inner.is_some() { "CodeBuilder(active)" } else { "CodeBuilder(consumed)" }
    }
}

// -- IrFieldDef ---------------------------------------------------------------

/// A field declaration inside a class IR.
///
/// Normally created via :meth:`IrClassDef.add_static_field` /
/// :meth:`IrClassDef.add_instance_field` rather than directly.
#[pyclass(name = "IrFieldDef", module = "dexrs._internal.builder")]
pub struct PyIrFieldDef {
    pub(crate) inner: IrFieldDef,
}

#[pymethods]
impl PyIrFieldDef {
    /// ``IrFieldDef(name, field_type, access_flags=0)``
    #[new]
    #[pyo3(signature = (name, field_type, access_flags = 0))]
    pub fn new(name: &str, field_type: &str, access_flags: u32) -> Self {
        Self { inner: IrFieldDef::new(name, field_type).access(access_flags) }
    }

    #[getter]
    pub fn name(&self) -> &str { &self.inner.name }
    #[getter]
    pub fn field_type(&self) -> &str { &self.inner.field_type }
    #[getter]
    pub fn access_flags(&self) -> u32 { self.inner.access_flags }
    #[setter]
    pub fn set_access_flags(&mut self, v: u32) { self.inner.access_flags = v; }
}

// -- IrMethodDef --------------------------------------------------------------

/// A method declaration (optionally with a body).
///
/// ```python
/// method = IrMethodDef("<init>", "()V", 0x10001)   # constructor, public
/// code = CodeBuilder(registers=1, ins=1, outs=0)
/// code.emit("return-void")
/// method.set_code(code.build())
/// ```
#[pyclass(name = "IrMethodDef", module = "dexrs._internal.builder")]
pub struct PyIrMethodDef {
    pub(crate) inner: IrMethodDef,
}

#[pymethods]
impl PyIrMethodDef {
    /// ``IrMethodDef(name, descriptor, access_flags)``
    ///
    /// :param name: Method name, e.g. ``"main"`` or ``"<init>"``.
    /// :param descriptor: JVM method descriptor, e.g. ``"([Ljava/lang/String;)V"``.
    /// :param access_flags: Access flags (``ACC_PUBLIC`` = 0x0001, etc.).
    #[new]
    #[pyo3(signature = (name, descriptor, access_flags = 0))]
    pub fn new(name: &str, descriptor: &str, access_flags: u32) -> Self {
        let proto = ProtoKey::from_descriptor(descriptor)
            .unwrap_or_else(|| ProtoKey::new("V", [] as [&str; 0]));
        Self { inner: IrMethodDef::new(name, proto).access(access_flags) }
    }

    #[getter]
    pub fn name(&self) -> &str { &self.inner.name }
    #[getter]
    pub fn access_flags(&self) -> u32 { self.inner.access_flags }
    #[setter]
    pub fn set_access_flags(&mut self, v: u32) { self.inner.access_flags = v; }

    /// Attach a :class:`CodeDef` as this method's body.
    pub fn set_code(&mut self, code: &PyCodeDef) {
        self.inner.code = Some(code.inner.clone());
    }

    pub fn __repr__(&self) -> String {
        format!("IrMethodDef({:?}, {})", self.inner.name, self.inner.proto.shorty())
    }
}

// -- IrClassDef ---------------------------------------------------------------

/// A complete class definition for the DEX IR.
///
/// ```python
/// cls = IrClassDef("Lcom/example/Foo;")
/// cls.set_access(0x0001)
/// cls.set_superclass("Ljava/lang/Object;")
/// cls.add_instance_field("mValue", "I", 0x0002)   # private int mValue
/// cls.add_direct_method(constructor_method)
/// cls.add_virtual_method(overridden_method)
/// ```
#[pyclass(name = "IrClassDef", module = "dexrs._internal.builder")]
pub struct PyIrClassDef {
    pub(crate) inner: IrClassDef,
}

#[pymethods]
impl PyIrClassDef {
    /// ``IrClassDef(descriptor)``
    ///
    /// :param descriptor: Full DEX type descriptor, e.g. ``"Lcom/example/Foo;"``.
    #[new]
    pub fn new(descriptor: &str) -> Self {
        Self { inner: IrClassDef::new(descriptor) }
    }

    #[getter]
    pub fn descriptor(&self) -> &str { &self.inner.descriptor }

    /// Set the class access flags (e.g. ``0x0001`` for public).
    pub fn set_access(&mut self, flags: u32) {
        self.inner.access_flags = flags;
    }

    /// Set the superclass descriptor (e.g. ``"Ljava/lang/Object;"``).
    pub fn set_superclass(&mut self, desc: &str) {
        self.inner.superclass = Some(desc.to_string());
    }

    /// Add an implemented interface.
    pub fn add_interface(&mut self, desc: &str) {
        self.inner.interfaces.push(desc.to_string());
    }

    /// Set the source file name (used in debug info, optional).
    pub fn set_source_file(&mut self, name: &str) {
        self.inner.source_file = Some(name.to_string());
    }

    /// Add a static field declaration.
    #[pyo3(signature = (name, field_type, access_flags = 0))]
    pub fn add_static_field(&mut self, name: &str, field_type: &str, access_flags: u32) {
        self.inner.static_fields.push(IrFieldDef::new(name, field_type).access(access_flags));
    }

    /// Add an instance field declaration.
    #[pyo3(signature = (name, field_type, access_flags = 0))]
    pub fn add_instance_field(&mut self, name: &str, field_type: &str, access_flags: u32) {
        self.inner.instance_fields.push(IrFieldDef::new(name, field_type).access(access_flags));
    }

    /// Add a direct method (``<init>``, ``<clinit>``, or ``static``/``private``).
    pub fn add_direct_method(&mut self, method: &PyIrMethodDef) {
        self.inner.direct_methods.push(method.inner.clone());
    }

    /// Add a virtual (overridable) method.
    pub fn add_virtual_method(&mut self, method: &PyIrMethodDef) {
        self.inner.virtual_methods.push(method.inner.clone());
    }

    pub fn __repr__(&self) -> String {
        format!("IrClassDef({:?})", self.inner.descriptor)
    }
}

// -- DexIrBuilder -------------------------------------------------------------

/// Builds a complete DEX file from scratch.
///
/// ```python
/// builder = DexIrBuilder(version=35)
/// builder.add_class(cls)
/// dex_bytes = builder.write()
///
/// # Or equivalently:
/// with open("output.dex", "wb") as f:
///     f.write(builder.write())
/// ```
#[pyclass(name = "DexIrBuilder", module = "dexrs._internal.builder")]
pub struct PyDexIrBuilder {
    inner: DexIr,
}

#[pymethods]
impl PyDexIrBuilder {
    /// ``DexIrBuilder(version=35)``
    ///
    /// :param version: DEX version integer.  Use ``35`` (Android 5+) unless
    ///     you specifically need a newer format.
    #[new]
    #[pyo3(signature = (version = 35))]
    pub fn new(version: u32) -> Self {
        Self { inner: DexIr::new(version) }
    }

    /// Add a class definition to the IR.
    ///
    /// The class is cloned into the builder; the original :class:`IrClassDef`
    /// is still usable after this call.
    pub fn add_class(&mut self, cls: &PyIrClassDef) {
        self.inner.add_class(cls.inner.clone());
    }

    /// Serialize all classes to a valid DEX byte string.
    ///
    /// :returns: Raw DEX bytes (``bytes`` object).
    /// :raises ValueError: If the IR contains inconsistencies that prevent
    ///     serialization.
    pub fn write<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = DexWriter::write(self.inner.clone())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Number of classes currently in the IR.
    pub fn class_count(&self) -> usize {
        self.inner.classes.len()
    }

    pub fn __repr__(&self) -> String {
        format!("DexIrBuilder(version={}, classes={})", self.inner.version, self.inner.classes.len())
    }
}

// -- Module registration -------------------------------------------------------

#[pyo3::pymodule(name = "builder")]
pub(crate) mod py_builder {
    #[pymodule_export]
    use super::PyProtoKey;
    #[pymodule_export]
    use super::PyCodeDef;
    #[pymodule_export]
    use super::PyCodeBuilder;
    #[pymodule_export]
    use super::PyIrFieldDef;
    #[pymodule_export]
    use super::PyIrMethodDef;
    #[pymodule_export]
    use super::PyIrClassDef;
    #[pymodule_export]
    use super::PyDexIrBuilder;
}
