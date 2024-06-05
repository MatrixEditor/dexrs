use std::{io, result};

#[derive(Debug)]
pub struct ConstraintError {
    pub identifier: &'static str,
    pub description: String,
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Parse(binrw::Error),
    Custom(&'static str),
    Validation(ConstraintError),
    InvalidData(String),

    //
    InvalidOffset(isize),
    InvalidIndex(usize),
    MalformedDescriptor(String),
    MethodNotFound(usize),
    FieldNotFound(usize),
    ParameterNotFound(usize),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IO(e)
    }
}

impl From<binrw::Error> for Error {
    fn from(e: binrw::Error) -> Self {
        Error::Parse(e)
    }
}

impl From<ConstraintError> for Error {
    fn from(e: ConstraintError) -> Self {
        Error::Validation(e)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Self {
        Error::InvalidData(e.to_string())
    }
}