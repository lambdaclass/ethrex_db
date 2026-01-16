//! Property-based tests for Merkle trie.

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;
    use crate::merkle::{MerkleTrie, Node, RlpEncoder};
    use crate::merkle::node::EMPTY_ROOT;

    proptest! {
        #[test]
        fn trie_deterministic_root(
            entries in proptest::collection::vec(
                (proptest::collection::vec(any::<u8>(), 1..32),
                 proptest::collection::vec(any::<u8>(), 1..64)),
                1..20
            )
        ) {
            let mut trie1 = MerkleTrie::new();
            let mut trie2 = MerkleTrie::new();

            // Insert in original order
            for (key, value) in &entries {
                trie1.insert(key, value.clone());
            }

            // Insert in reverse order
            for (key, value) in entries.iter().rev() {
                trie2.insert(key, value.clone());
            }

            // Root hashes should be the same
            assert_eq!(trie1.root_hash(), trie2.root_hash());
        }

        #[test]
        fn trie_insert_get(
            key in proptest::collection::vec(any::<u8>(), 1..32),
            value in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            let mut trie = MerkleTrie::new();
            trie.insert(&key, value.clone());

            assert_eq!(trie.get(&key), Some(value.as_slice()));
        }

        #[test]
        fn trie_remove_returns_empty_root(
            key in proptest::collection::vec(any::<u8>(), 1..32),
            value in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            let mut trie = MerkleTrie::new();
            trie.insert(&key, value);
            trie.remove(&key);

            assert_eq!(trie.root_hash(), EMPTY_ROOT);
            assert!(trie.is_empty());
        }

        #[test]
        fn trie_update_changes_root(
            key in proptest::collection::vec(any::<u8>(), 1..32),
            value1 in proptest::collection::vec(any::<u8>(), 1..64),
            value2 in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            prop_assume!(value1 != value2);

            let mut trie = MerkleTrie::new();
            trie.insert(&key, value1);
            let hash1 = trie.root_hash();

            trie.insert(&key, value2);
            let hash2 = trie.root_hash();

            assert_ne!(hash1, hash2);
        }

        #[test]
        fn rlp_encode_bytes_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut encoder = RlpEncoder::new();
            encoder.encode_bytes(&data);
            let encoded = encoder.as_bytes();

            // Verify it starts with correct prefix
            if data.is_empty() {
                assert_eq!(encoded, &[0x80]);
            } else if data.len() == 1 && data[0] < 0x80 {
                assert_eq!(encoded, &data[..]);
            } else if data.len() < 56 {
                assert_eq!(encoded[0], 0x80 + data.len() as u8);
                assert_eq!(&encoded[1..], &data[..]);
            }
        }

        #[test]
        fn node_hash_deterministic(
            path in proptest::collection::vec(0u8..16u8, 0..32),
            value in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            let node1 = Node::leaf(path.clone(), value.clone());
            let node2 = Node::leaf(path, value);

            assert_eq!(node1.keccak(), node2.keccak());
        }
    }
}
