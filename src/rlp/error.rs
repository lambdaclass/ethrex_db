use thiserror::Error;

// TODO: improve errors
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RLPDecodeError {
    #[error("InvalidLength")]
    InvalidLength,
    #[error("MalformedData")]
    MalformedData,
    #[error("MalformedBoolean")]
    MalformedBoolean,
    #[error("UnexpectedList")]
    UnexpectedList,
    #[error("UnexpectedString")]
    UnexpectedString,
    #[error("IncompatibleProtocol")]
    IncompatibleProtocol,
    #[error("{0}")]
    Custom(String),
}
