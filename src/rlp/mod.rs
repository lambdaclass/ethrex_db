pub mod constants;
pub mod decode;
pub mod encode;
pub mod error;
pub mod structs;

// Re-export commonly used types and traits
pub use self::{
    constants::{RLP_EMPTY_LIST, RLP_NULL},
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
