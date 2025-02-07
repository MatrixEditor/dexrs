use std::result;

pub mod error;
pub mod file;
pub mod leb128;
pub mod utf;

pub mod desc_names;

pub type Result<T> = result::Result<T, error::DexError>;
