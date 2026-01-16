//! Integration tests for ethrex_db.

use ethrex_db::data::{NibblePath, SlottedArray};
use ethrex_db::store::{PagedDb, PageType, CommitOptions};
use ethrex_db::chain::{Blockchain, Block, Account, WorldState, ReadOnlyWorldState};
use ethrex_db::merkle::{MerkleTrie, Node, keccak256, EMPTY_ROOT};
use primitive_types::{H256, U256};

#[test]
fn test_full_workflow() {
    // Create database
    let db = PagedDb::in_memory(1000).unwrap();

    // Create blockchain
    let blockchain = Blockchain::new(db);

    // Create a block
    let parent_hash = blockchain.last_finalized_hash();
    let mut block = blockchain.start_new(
        parent_hash,
        H256::repeat_byte(0x01),
        1,
    ).unwrap();

    // Add account changes
    let address = H256::repeat_byte(0xAB);
    let account = Account::with_balance(U256::from(1000));
    block.set_account(address, account);

    // Add storage changes
    let storage_key = H256::repeat_byte(0xCD);
    block.set_storage(address, storage_key, U256::from(42));

    // Commit block
    blockchain.commit(block).unwrap();

    // Verify block is committed
    assert_eq!(blockchain.committed_count(), 1);
}

#[test]
fn test_merkle_trie_with_account_data() {
    let mut trie = MerkleTrie::new();

    // Simulate account state
    let accounts = vec![
        (H256::repeat_byte(0x01), Account::with_balance(U256::from(100))),
        (H256::repeat_byte(0x02), Account::with_balance(U256::from(200))),
        (H256::repeat_byte(0x03), Account::with_balance(U256::from(300))),
    ];

    for (address, account) in &accounts {
        let key = address.as_bytes();
        let value = account.encode();
        trie.insert(key, value);
    }

    let root = trie.root_hash();
    assert_ne!(root, EMPTY_ROOT);

    // Verify we can retrieve accounts
    for (address, account) in &accounts {
        let value = trie.get(address.as_bytes()).unwrap();
        let decoded = Account::decode(value).unwrap();
        assert_eq!(decoded.balance, account.balance);
    }
}

#[test]
fn test_slotted_array_stress() {
    let mut arr = SlottedArray::new();

    // Insert many entries
    let mut inserted = Vec::new();
    for i in 0..50 {
        let key_bytes = [i as u8, (i * 2) as u8];
        let key = NibblePath::from_bytes(&key_bytes);
        let value = format!("value_{}", i);

        if arr.try_insert(&key, value.as_bytes()) {
            inserted.push((key_bytes.to_vec(), value));
        } else {
            break; // Page is full
        }
    }

    // Verify all inserted entries
    for (key_bytes, expected_value) in &inserted {
        let key = NibblePath::from_bytes(key_bytes);
        let value = arr.get(&key).expect("Entry should exist");
        assert_eq!(value, expected_value.as_bytes());
    }
}

#[test]
fn test_database_persistence_simulation() {
    // This simulates what would happen with persistence

    // Create initial state
    let mut db = PagedDb::in_memory(1000).unwrap();

    // First batch
    {
        let mut batch = db.begin_batch();
        let (_addr, _page) = batch.allocate_page(PageType::Data, 0).unwrap();
        batch.set_metadata(1, &[0x11; 32]);
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    assert_eq!(db.block_number(), 1);
    assert_eq!(db.block_hash(), [0x11; 32]);

    // Second batch
    {
        let mut batch = db.begin_batch();
        batch.set_metadata(2, &[0x22; 32]);
        batch.commit(CommitOptions::DangerNoFlush).unwrap();
    }

    assert_eq!(db.block_number(), 2);
    assert_eq!(db.block_hash(), [0x22; 32]);
}

#[test]
fn test_parallel_blocks() {
    let db = PagedDb::in_memory(1000).unwrap();
    let blockchain = Blockchain::new(db);

    let parent_hash = blockchain.last_finalized_hash();

    // Create multiple blocks from same parent (simulating parallel execution)
    let mut blocks = Vec::new();
    for i in 0..3 {
        let block = blockchain.start_new(
            parent_hash,
            H256::from_low_u64_be(i as u64 + 1),
            1,
        ).unwrap();
        blocks.push(block);
    }

    // Commit all blocks
    for block in blocks {
        blockchain.commit(block).unwrap();
    }

    // All blocks should be tracked
    assert_eq!(blockchain.committed_count(), 3);
}

#[test]
fn test_trie_branch_node_creation() {
    let mut trie = MerkleTrie::new();

    // Insert keys that will create a branch node
    // Keys starting with same prefix but different next nibble
    trie.insert(&[0x10], b"a".to_vec());
    trie.insert(&[0x11], b"b".to_vec());
    trie.insert(&[0x12], b"c".to_vec());
    trie.insert(&[0x20], b"d".to_vec());

    assert_eq!(trie.len(), 4);

    let root = trie.root_hash();
    assert_ne!(root, EMPTY_ROOT);

    // Verify all entries
    assert_eq!(trie.get(&[0x10]), Some(b"a".as_slice()));
    assert_eq!(trie.get(&[0x11]), Some(b"b".as_slice()));
    assert_eq!(trie.get(&[0x12]), Some(b"c".as_slice()));
    assert_eq!(trie.get(&[0x20]), Some(b"d".as_slice()));
}

#[test]
fn test_keccak256() {
    // Test against known Ethereum values
    let empty = keccak256(&[]);
    assert_eq!(
        hex::encode(empty),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    let hello = keccak256(b"hello");
    assert_eq!(
        hex::encode(hello),
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    );
}

#[test]
fn test_nibble_path_operations() {
    let path = NibblePath::from_bytes(&[0xAB, 0xCD, 0xEF]);

    // Test basic properties
    assert_eq!(path.len(), 6);
    assert_eq!(path.get(0), 0xA);
    assert_eq!(path.get(1), 0xB);
    assert_eq!(path.get(2), 0xC);
    assert_eq!(path.get(3), 0xD);
    assert_eq!(path.get(4), 0xE);
    assert_eq!(path.get(5), 0xF);

    // Test slicing
    let sliced = path.slice_from(2);
    assert_eq!(sliced.len(), 4);
    assert_eq!(sliced.get(0), 0xC);

    // Test common prefix
    let path2 = NibblePath::from_bytes(&[0xAB, 0x00]);
    assert_eq!(path.common_prefix_len(&path2), 2);
}
