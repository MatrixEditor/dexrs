use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use std::path::PathBuf;

use crate::file::DexEditor;

/// Python-facing wrapper for `DexEditor`.
///
/// Construct with `DexEditor.from_file(path)` or `DexEditor.from_bytes(data)`.
#[pyclass(name = "DexEditor", module = "dexrs._internal.editor")]
pub struct PyDexEditor {
    // Option so we can move out on build()/write_to()
    inner: Option<DexEditor>,
}

impl PyDexEditor {
    fn editor_mut(&mut self) -> PyResult<&mut DexEditor> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyIOError::new_err("DexEditor already consumed by build() or write_to()"))
    }

    fn take_editor(&mut self) -> PyResult<DexEditor> {
        self.inner
            .take()
            .ok_or_else(|| PyIOError::new_err("DexEditor already consumed by build() or write_to()"))
    }
}

#[pymethods]
impl PyDexEditor {
    /// Open a DEX file from disk.
    ///
    /// ```python
    /// editor = DexEditor.from_file("classes.dex")
    /// ```
    #[staticmethod]
    pub fn from_file(path: &str) -> PyResult<Self> {
        let editor = DexEditor::from_file(PathBuf::from(path).as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(PyDexEditor { inner: Some(editor) })
    }

    /// Construct a `DexEditor` from raw bytes.
    ///
    /// ```python
    /// with open("classes.dex", "rb") as f:
    ///     editor = DexEditor.from_bytes(f.read())
    /// ```
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let editor = DexEditor::from_bytes(data.to_vec())
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(PyDexEditor { inner: Some(editor) })
    }

    /// Set the access flags on a class definition.
    ///
    /// `class_desc` accepts dotted (`com.example.Foo`), slash (`com/example/Foo`),
    /// or descriptor (`Lcom/example/Foo;`) form.
    ///
    /// ```python
    /// editor.set_class_access_flags("com.example.Foo", 0x0001)  # public
    /// ```
    pub fn set_class_access_flags(&mut self, class_desc: &str, flags: u32) -> PyResult<()> {
        self.editor_mut()?
            .set_class_access_flags(class_desc, flags)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Set the access flags on a specific method inside a class.
    ///
    /// LEB128 re-encoding is handled automatically when the flag width changes.
    ///
    /// ```python
    /// editor.set_method_access_flags("LMain;", "run", 0x0001)  # public
    /// ```
    pub fn set_method_access_flags(
        &mut self,
        class_desc: &str,
        method_name: &str,
        flags: u32,
    ) -> PyResult<()> {
        self.editor_mut()?
            .set_method_access_flags(class_desc, method_name, flags)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Zero out the HiddenapiClassData section and remove its map entry.
    ///
    /// Useful when the modified DEX is loaded by a runtime that rejects
    /// hidden-API annotations.
    ///
    /// ```python
    /// editor.clear_hiddenapi_flags()
    /// ```
    pub fn clear_hiddenapi_flags(&mut self) -> PyResult<()> {
        self.editor_mut()?
            .clear_hiddenapi_flags()
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Rename a class, updating the string pool, type references, and checksum.
    ///
    /// Both `old_name` and `new_name` accept dotted, slash, or descriptor form.
    ///
    /// ```python
    /// editor.rename_class("LMain;", "LRenamedMain;")
    /// ```
    pub fn rename_class(&mut self, old_name: &str, new_name: &str) -> PyResult<()> {
        self.editor_mut()?
            .rename_class(old_name, new_name)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Finalise edits: recalculate the Adler32 checksum and return the
    /// modified DEX as a `bytes` object.
    ///
    /// The editor is consumed after this call.
    ///
    /// ```python
    /// data = editor.build()
    /// with open("out.dex", "wb") as f:
    ///     f.write(data)
    /// ```
    pub fn build(&mut self) -> PyResult<Py<pyo3::types::PyBytes>> {
        let data = self
            .take_editor()?
            .build()
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        Python::with_gil(|py| Ok(pyo3::types::PyBytes::new(py, &data).into()))
    }

    /// Finalise edits and write the modified DEX directly to `path`.
    ///
    /// The editor is consumed after this call.
    ///
    /// ```python
    /// editor.write_to("out.dex")
    /// ```
    pub fn write_to(&mut self, path: &str) -> PyResult<()> {
        self.take_editor()?
            .write_to(PathBuf::from(path).as_ref())
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }
}

#[pyo3::pymodule(name = "editor")]
pub(crate) mod py_editor {
    #[pymodule_export]
    use super::PyDexEditor;
}
