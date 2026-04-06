use std::fmt;

/// A decoded method signature in standard DEX format: `"(param1param2...)return_type"`.
///
/// Matches ART's `Signature` class. Created via [`DexFile::get_method_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Signature {
    inner: String,
    num_params: u32,
    is_void: bool,
}

impl Signature {
    pub(super) fn new(inner: String, num_params: u32, is_void: bool) -> Self {
        Self {
            inner,
            num_params,
            is_void,
        }
    }

    /// Returns a no-signature sentinel (empty string, 0 params, not void).
    pub fn no_signature() -> Self {
        Self::default()
    }

    /// Returns `true` if the return type is `void`.
    pub fn is_void(&self) -> bool {
        self.is_void
    }

    /// Returns the number of explicit parameters.
    pub fn num_params(&self) -> u32 {
        self.num_params
    }

    /// Returns the signature string in DEX format: `"(params)return_type"`.
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}
