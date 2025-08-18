use super::{
    RLPDecode, RLPDecodeError, RLPEncode,
    decode::{decode_rlp_item, get_item_with_prefix},
    encode::encode_length,
};
use bytes::BufMut;

#[derive(Debug)]
pub struct Decoder<'a> {
    payload: &'a [u8],
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, RLPDecodeError> {
        match decode_rlp_item(buf)? {
            (true, payload, remaining) => Ok(Self { payload, remaining }),
            (false, _, _) => Err(RLPDecodeError::UnexpectedString),
        }
    }

    pub fn decode_field<T: RLPDecode>(self, name: &str) -> Result<(T, Self), RLPDecodeError> {
        let (field, rest) = <T as RLPDecode>::decode_unfinished(self.payload)
            .map_err(|err| field_decode_error::<T>(name, err))?;
        let updated_self = Self {
            payload: rest,
            ..self
        };
        Ok((field, updated_self))
    }
    /// Returns the next field without decoding it, i.e. the payload bytes including its prefix.
    pub fn get_encoded_item(self) -> Result<(Vec<u8>, Self), RLPDecodeError> {
        match get_item_with_prefix(self.payload) {
            Ok((field, rest)) => {
                let updated_self = Self {
                    payload: rest,
                    ..self
                };
                Ok((field.to_vec(), updated_self))
            }
            Err(err) => Err(err),
        }
    }

    /// Finishes encoding the struct and returns the remaining bytes after the item.
    /// If the item's payload is not empty, returns an error.
    pub const fn finish(self) -> Result<&'a [u8], RLPDecodeError> {
        if self.payload.is_empty() {
            Ok(self.remaining)
        } else {
            Err(RLPDecodeError::MalformedData)
        }
    }

    /// Returns true if the decoder has finished decoding the given input
    pub const fn is_done(&self) -> bool {
        self.payload.is_empty()
    }
}

fn field_decode_error<T>(field_name: &str, err: RLPDecodeError) -> RLPDecodeError {
    let typ = std::any::type_name::<T>();
    let err_msg = format!("Error decoding field '{field_name}' of type {typ}: {err}");
    RLPDecodeError::Custom(err_msg)
}

pub struct Encoder<'a> {
    buf: &'a mut dyn BufMut,
    temp_buf: Vec<u8>,
}

// NOTE: BufMut doesn't implement Debug, so we can't derive Debug for Encoder.
impl core::fmt::Debug for Encoder<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encoder")
            .field("buf", &"...")
            .field("temp_buf", &self.temp_buf)
            .finish()
    }
}

impl<'a> Encoder<'a> {
    /// Creates a new encoder that writes to the given buffer.
    pub fn new(buf: &'a mut dyn BufMut) -> Self {
        // PERF: we could pre-allocate the buffer or switch to `ArrayVec`` if we could
        // bound the size of the encoded data.
        Self {
            buf,
            temp_buf: Default::default(),
        }
    }

    /// Stores a field to be encoded.
    pub fn encode_field<T: RLPEncode>(mut self, value: &T) -> Self {
        <T as RLPEncode>::encode(value, &mut self.temp_buf);
        self
    }

    /// If `Some`, stores a field to be encoded, else does nothing.
    pub fn encode_optional_field<T: RLPEncode>(mut self, opt_value: &Option<T>) -> Self {
        if let Some(value) = opt_value {
            <T as RLPEncode>::encode(value, &mut self.temp_buf);
        }
        self
    }

    /// Stores a (key, value) list where the values are already encoded (i.e. value = RLP prefix || payload)
    /// but the keys are not encoded
    pub fn encode_key_value_list(mut self, list: &Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        for (key, value) in list {
            key.as_slice().encode(&mut self.temp_buf);
            // value is already encoded
            self.temp_buf.put_slice(value);
        }
        self
    }

    /// Finishes encoding the struct and writes the result to the buffer.
    pub fn finish(self) {
        encode_length(self.temp_buf.len(), self.buf);
        self.buf.put_slice(&self.temp_buf);
    }

    /// Adds a raw value to the buffer without rlp-encoding it
    pub fn encode_raw(mut self, value: &[u8]) -> Self {
        self.temp_buf.put_slice(value);
        self
    }

    /// Stores a field to be encoded as bytes
    /// This method is used to bypass the conflicting implementations between Vec<T> and Vec<u8>
    pub fn encode_bytes(mut self, value: &[u8]) -> Self {
        <[u8] as RLPEncode>::encode(value, &mut self.temp_buf);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::rlp::{
        decode::RLPDecode,
        encode::RLPEncode,
        structs::{Decoder, Encoder},
    };

    #[derive(Debug, PartialEq, Eq)]
    struct Simple {
        pub a: u8,
        pub b: u16,
    }

    #[test]
    fn test_decoder_simple_struct() {
        let expected = Simple { a: 61, b: 75 };
        let mut buf = Vec::new();
        (expected.a, expected.b).encode(&mut buf);

        let decoder = Decoder::new(&buf).unwrap();
        let (a, decoder) = decoder.decode_field("a").unwrap();
        let (b, decoder) = decoder.decode_field("b").unwrap();
        let rest = decoder.finish().unwrap();

        assert!(rest.is_empty());
        let got = Simple { a, b };
        assert_eq!(got, expected);

        // Decoding the struct as a tuple should give the same result
        let tuple_decode = <(u8, u16) as RLPDecode>::decode(&buf).unwrap();
        assert_eq!(tuple_decode, (a, b));
    }

    #[test]
    fn test_encoder_simple_struct() {
        let input = Simple { a: 61, b: 75 };
        let mut buf = Vec::new();

        Encoder::new(&mut buf)
            .encode_field(&input.a)
            .encode_field(&input.b)
            .finish();

        assert_eq!(buf, vec![0xc2, 61, 75]);

        // Encoding the struct from a tuple should give the same result
        let mut tuple_encoded = Vec::new();
        (input.a, input.b).encode(&mut tuple_encoded);
        assert_eq!(buf, tuple_encoded);
    }
}
