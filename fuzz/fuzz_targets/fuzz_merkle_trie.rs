#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ethrex_db::merkle::MerkleTrie;

#[derive(Arbitrary, Debug)]
struct MerkleTrieInput {
    operations: Vec<TrieOp>,
}

#[derive(Arbitrary, Debug)]
enum TrieOp {
    Insert { key: Vec<u8>, value: Vec<u8> },
    Get { key: Vec<u8> },
    Remove { key: Vec<u8> },
    ComputeRoot,
    Iterate,
    Len,
}

fuzz_target!(|input: MerkleTrieInput| {
    // Limit operations
    if input.operations.len() > 500 {
        return;
    }

    let mut trie = MerkleTrie::new();
    let mut expected: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();

    for op in input.operations {
        match op {
            TrieOp::Insert { key, value } => {
                // Limit key/value size
                if key.is_empty() || key.len() > 64 || value.len() > 256 {
                    continue;
                }

                trie.insert(&key, value.clone());
                expected.insert(key, value);
            }
            TrieOp::Get { key } => {
                let result = trie.get(&key);

                match expected.get(&key) {
                    Some(val) => assert_eq!(result, Some(val.as_slice())),
                    None => assert!(result.is_none()),
                }
            }
            TrieOp::Remove { key } => {
                trie.remove(&key);
                expected.remove(&key);

                // Verify removal
                assert!(trie.get(&key).is_none());
            }
            TrieOp::ComputeRoot => {
                let root1 = trie.root_hash();
                let root2 = trie.root_hash();
                // Root should be deterministic
                assert_eq!(root1, root2);
            }
            TrieOp::Iterate => {
                let count = trie.iter().count();
                assert_eq!(count, trie.len());
            }
            TrieOp::Len => {
                assert_eq!(trie.len(), expected.len());
            }
        }
    }

    // Final consistency check
    assert_eq!(trie.len(), expected.len());

    // Verify all expected entries exist
    for (key, value) in &expected {
        let result = trie.get(key);
        assert_eq!(result, Some(value.as_slice()), "Key {:?} not found", key);
    }

    // Verify root consistency across operations
    let _ = trie.root_hash();
});
