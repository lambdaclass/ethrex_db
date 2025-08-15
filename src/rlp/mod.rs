pub mod constants;
pub mod decode;
pub mod encode;
pub mod error;
pub mod structs;

// Re-export commonly used types and traits
pub use self::{
    constants::{RLP_NULL, RLP_EMPTY_LIST},
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
