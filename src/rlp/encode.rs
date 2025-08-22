use bytes::BufMut;
use ethereum_types::U256;
use tinyvec::ArrayVec;

use crate::{
    rlp::{Encoder, RLP_NULL},
    trie::{BranchNode, ExtensionNode, LeafNode, Node},
};

pub trait RLPEncode {
    fn encode(&self, buf: &mut dyn BufMut);

    fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }

    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// integer types impls

fn impl_encode<const N: usize>(value_be: [u8; N], buf: &mut dyn BufMut) {
    let mut is_multi_byte_case = false;

    for n in value_be.iter().take(N - 1) {
        // If we encounter a non 0 byte pattern before the last byte, we are
        // at the multi byte case
        if *n != 0 {
            is_multi_byte_case = true;
            break;
        }
    }

    match value_be[N - 1] {
        // 0, also known as null or the empty string is 0x80
        0 if !is_multi_byte_case => buf.put_u8(RLP_NULL),
        // for a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
        n @ 1..=0x7f if !is_multi_byte_case => buf.put_u8(n),
        // if a string is 0-55 bytes long, the RLP encoding consists of a
        // single byte with value RLP_NULL (0x80) plus the length of the string followed by the string.
        _ => {
            let mut bytes = ArrayVec::<[u8; 8]>::new();
            bytes.extend_from_slice(&value_be);
            let start = bytes.iter().position(|&x| x != 0).unwrap();
            let len = bytes.len() - start;
            buf.put_u8(RLP_NULL + len as u8);
            buf.put_slice(&bytes[start..]);
        }
    }
}

impl RLPEncode for u8 {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for u16 {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for u32 {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for u64 {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for usize {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for u128 {
    fn encode(&self, buf: &mut dyn BufMut) {
        impl_encode(self.to_be_bytes(), buf);
    }
}

impl RLPEncode for [u8] {
    #[inline(always)]
    fn encode(&self, buf: &mut dyn BufMut) {
        if self.len() == 1 && self[0] < RLP_NULL {
            buf.put_u8(self[0]);
        } else {
            let len = self.len();
            if len < 56 {
                buf.put_u8(RLP_NULL + len as u8);
            } else {
                let mut bytes = ArrayVec::<[u8; 8]>::new();
                bytes.extend_from_slice(&len.to_be_bytes());
                let start = bytes.iter().position(|&x| x != 0).unwrap();
                let len = bytes.len() - start;
                buf.put_u8(0xb7 + len as u8);
                buf.put_slice(&bytes[start..]);
            }
            buf.put_slice(self);
        }
    }
}

impl<const N: usize> RLPEncode for [u8; N] {
    fn encode(&self, buf: &mut dyn BufMut) {
        self.as_ref().encode(buf)
    }
}

impl RLPEncode for U256 {
    fn encode(&self, buf: &mut dyn BufMut) {
        let leading_zeros_in_bytes: usize = (self.leading_zeros() / 8) as usize;
        let bytes = self.to_big_endian();
        bytes[leading_zeros_in_bytes..].encode(buf)
    }
}

impl<T: RLPEncode> RLPEncode for Vec<T> {
    fn encode(&self, buf: &mut dyn BufMut) {
        if self.is_empty() {
            buf.put_u8(0xc0);
        } else {
            let mut tmp_buf = vec![];
            for item in self {
                item.encode(&mut tmp_buf);
            }
            encode_length(tmp_buf.len(), buf);
            buf.put_slice(&tmp_buf);
        }
    }
}

pub fn encode_length(total_len: usize, buf: &mut dyn BufMut) {
    if total_len < 56 {
        buf.put_u8(0xc0 + total_len as u8);
    } else {
        let mut bytes = ArrayVec::<[u8; 8]>::new();
        bytes.extend_from_slice(&total_len.to_be_bytes());
        let start = bytes.iter().position(|&x| x != 0).unwrap();
        let len = bytes.len() - start;
        buf.put_u8(0xf7 + len as u8);
        buf.put_slice(&bytes[start..]);
    }
}

impl<S: RLPEncode, T: RLPEncode> RLPEncode for (S, T) {
    fn encode(&self, buf: &mut dyn BufMut) {
        let total_len = self.0.length() + self.1.length();
        encode_length(total_len, buf);
        self.0.encode(buf);
        self.1.encode(buf);
    }
}

impl RLPEncode for ethereum_types::H256 {
    fn encode(&self, buf: &mut dyn BufMut) {
        self.as_bytes().encode(buf)
    }
}

// Contains RLP encoding and decoding implementations for Trie Nodes
// This encoding is only used to store the nodes in the DB, it is not the encoding used for hash computation
enum NodeType {
    Branch = 0,
    Extension = 1,
    Leaf = 2,
}

impl RLPEncode for BranchNode {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        // TODO: choices encoded as vec due to conflicting trait impls for [T;N] & [u8;N], check if we can fix this later
        Encoder::new(buf)
            .encode_field(
                &self
                    .choices
                    .iter()
                    .map(|x| x.compute_hash())
                    .collect::<Vec<_>>(),
            )
            .encode_field(&self.value)
            .finish()
    }
}

impl RLPEncode for ExtensionNode {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.prefix)
            .encode_field(&self.child.compute_hash())
            .finish()
    }
}

impl RLPEncode for LeafNode {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.partial)
            .encode_field(&self.value)
            .finish()
    }
}

impl RLPEncode for Node {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        let node_type = match self {
            Node::Branch(_) => NodeType::Branch,
            Node::Extension(_) => NodeType::Extension,
            Node::Leaf(_) => NodeType::Leaf,
        };
        buf.put_u8(node_type as u8);
        match self {
            Node::Branch(n) => n.encode(buf),
            Node::Extension(n) => n.encode(buf),
            Node::Leaf(n) => n.encode(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RLPEncode;
    use crate::rlp::constants::{RLP_EMPTY_LIST, RLP_NULL};
    use ethereum_types::U256;

    #[test]
    fn can_encode_u8() {
        let mut encoded = Vec::new();
        0u8.encode(&mut encoded);
        assert_eq!(encoded, vec![RLP_NULL]);

        let mut encoded = Vec::new();
        1u8.encode(&mut encoded);
        assert_eq!(encoded, vec![0x01]);

        let mut encoded = Vec::new();
        0x7Fu8.encode(&mut encoded);
        assert_eq!(encoded, vec![0x7f]);

        let mut encoded = Vec::new();
        0x80u8.encode(&mut encoded);
        assert_eq!(encoded, vec![RLP_NULL + 1, 0x80]);
    }

    #[test]
    fn can_encode_bytes() {
        let message: [u8; 1] = [0x00];
        let encoded = {
            let mut buf = vec![];
            message.encode(&mut buf);
            buf
        };
        assert_eq!(encoded, vec![0x00]);

        let message: [u8; 2] = [0x04, 0x00];
        let encoded = {
            let mut buf = vec![];
            message.encode(&mut buf);
            buf
        };
        assert_eq!(encoded, vec![RLP_NULL + 2, 0x04, 0x00]);
    }

    #[test]
    fn can_encode_u256() {
        let mut encoded = Vec::new();
        U256::from(1).encode(&mut encoded);
        assert_eq!(encoded, vec![1]);

        let mut encoded = Vec::new();
        U256::from(128).encode(&mut encoded);
        assert_eq!(encoded, vec![0x80 + 1, 128]);
    }

    #[test]
    fn can_encode_tuple() {
        let tuple: (u8, u8) = (0x01, 0x02);
        let mut encoded = Vec::new();
        tuple.encode(&mut encoded);
        let expected = vec![0xc0 + 2, 0x01, 0x02];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn can_encode_vec() {
        let message: Vec<u8> = vec![1, 2, 3];
        let encoded = {
            let mut buf = vec![];
            message.encode(&mut buf);
            buf
        };
        let expected: [u8; 4] = [RLP_EMPTY_LIST + 3, 0x01, 0x02, 0x03];
        assert_eq!(encoded, expected);

        let message: Vec<u8> = vec![];
        let encoded = {
            let mut buf = vec![];
            message.encode(&mut buf);
            buf
        };
        let expected: [u8; 1] = [RLP_EMPTY_LIST];
        assert_eq!(encoded, expected);
    }
}
