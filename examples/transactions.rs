use ethrexdb::EthrexDB;
use ethrexdb::trie::{InMemoryTrieDB, Trie};
use tempdir::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new("ethrex_transaction_example")?;
    let db_path = temp_dir.path().join("example.edb");

    let db = EthrexDB::new(db_path)?;

    println!("EthrexDB Multi-Reader Single-Writer Transaction Demo\n");

    // Initially no active transactions
    assert_eq!(
        db.active_transaction_count(),
        0,
        "Should start with no active transactions"
    );
    println!(
        "Initial state: {} active transactions",
        db.active_transaction_count()
    );

    // Setup initial state
    println!("\n--- Setting up initial blockchain state ---");
    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
    trie.insert(b"account:0x1:balance".to_vec(), b"1000".to_vec())?;
    trie.insert(b"account:0x2:balance".to_vec(), b"500".to_vec())?;
    trie.insert(b"account:0x3:balance".to_vec(), b"250".to_vec())?;

    let root_node = trie.root_node()?.unwrap();
    db.commit(&root_node)?;
    trie.commit().unwrap();

    println!("Block 1 committed");
    println!("  - Account 0x1: 1000 ETH");
    println!("  - Account 0x2: 500 ETH");
    println!("  - Account 0x3: 250 ETH");

    // Multiple Concurrent Readers
    println!("\n--- Creating multiple concurrent read transactions ---");

    let tx1 = db.begin_read()?;
    let tx2 = db.begin_read()?;
    let tx3 = db.begin_read()?;

    assert_eq!(
        db.active_transaction_count(),
        3,
        "Should have 3 active transactions"
    );
    println!("Created 3 concurrent read transactions");
    println!("  - Active transactions: {}", db.active_transaction_count());
    println!(
        "  - Protected snapshots: {}",
        db.get_protected_offsets().len()
    );

    // All transactions should see the same data (same snapshot)
    let snapshot_offset = tx1.snapshot_offset();
    assert_eq!(
        tx1.snapshot_offset(),
        tx2.snapshot_offset(),
        "Same snapshot offset"
    );
    assert_eq!(
        tx2.snapshot_offset(),
        tx3.snapshot_offset(),
        "Same snapshot offset"
    );

    println!(
        "  - All transactions share snapshot offset: {}",
        snapshot_offset
    );

    // Validate all readers can read concurrently
    let balance_0x1_tx1 = tx1.get(b"account:0x1:balance")?.unwrap();
    let balance_0x1_tx2 = tx2.get(b"account:0x1:balance")?.unwrap();
    let balance_0x1_tx3 = tx3.get(b"account:0x1:balance")?.unwrap();

    assert_eq!(balance_0x1_tx1, b"1000", "TX1 should see correct balance");
    assert_eq!(balance_0x1_tx2, b"1000", "TX2 should see correct balance");
    assert_eq!(balance_0x1_tx3, b"1000", "TX3 should see correct balance");

    // Writer commits while readers are active, this should demonstrate snapshot isolation
    println!("\n--- Committing new block while readers are active ---");

    // Simulate a block with transactions
    trie.insert(b"account:0x1:balance".to_vec(), b"800".to_vec())?; // 0x1 sent 200
    trie.insert(b"account:0x2:balance".to_vec(), b"700".to_vec())?; // 0x2 received 200
    trie.insert(b"account:0x4:balance".to_vec(), b"100".to_vec())?; // New account 0x4

    let root_node2 = trie.root_node()?.unwrap();
    db.commit(&root_node2)?;
    trie.commit().unwrap();

    println!("Block 2 committed while 3 readers still active");
    println!("  - Account 0x1: 1000 → 800 ETH (sent 200)");
    println!("  - Account 0x2: 500 → 700 ETH (received 200)");
    println!("  - Account 0x4: 0 → 100 ETH (new account)");

    println!("\n--- SNAPSHOT ISOLATION VERIFICATION ---");

    // Old readers should still see old data (snapshot isolation)
    let old_balance_0x1_tx1 = String::from_utf8(tx1.get(b"account:0x1:balance")?.unwrap()).unwrap();
    let old_balance_0x1_tx2 = String::from_utf8(tx2.get(b"account:0x1:balance")?.unwrap()).unwrap();
    let old_balance_0x1_tx3 = String::from_utf8(tx3.get(b"account:0x1:balance")?.unwrap()).unwrap();
    let new_account_tx3 = tx3.get(b"account:0x4:balance")?;

    println!("Old readers (TX1-3) still see Block 1 data:");
    println!(
        "  - TX1 sees account 0x1 balance: {} ETH",
        old_balance_0x1_tx1
    );
    println!(
        "  - TX2 sees account 0x1 balance: {} ETH",
        old_balance_0x1_tx2
    );
    println!(
        "  - TX3 sees account 0x1 balance: {} ETH",
        old_balance_0x1_tx3
    );
    println!(
        "  - TX3 sees account 0x4 balance: {:?} (new account not visible)",
        new_account_tx3
    );

    assert_eq!(
        old_balance_0x1_tx1, "1000",
        "TX1 should still see old balance"
    );
    assert_eq!(
        old_balance_0x1_tx2, "1000",
        "TX2 should still see old balance"
    );
    assert_eq!(
        old_balance_0x1_tx3, "1000",
        "TX3 should still see old balance"
    );
    assert!(new_account_tx3.is_none(), "TX3 should not see new account");

    // New reader should see new data
    let tx4 = db.begin_read()?;
    assert_eq!(
        db.active_transaction_count(),
        4,
        "Should now have 4 active transactions"
    );

    let new_balance_0x1 = String::from_utf8(tx4.get(b"account:0x1:balance")?.unwrap()).unwrap();
    let new_balance_0x2 = String::from_utf8(tx4.get(b"account:0x2:balance")?.unwrap()).unwrap();
    let new_balance_0x3 = String::from_utf8(tx4.get(b"account:0x3:balance")?.unwrap()).unwrap();
    let new_account_0x4 = String::from_utf8(tx4.get(b"account:0x4:balance")?.unwrap()).unwrap();

    println!("\nNew reader (TX4) sees Block 2 data:");
    println!("  - TX4 sees account 0x1 balance: {} ETH", new_balance_0x1);
    println!("  - TX4 sees account 0x2 balance: {} ETH", new_balance_0x2);
    println!("  - TX4 sees account 0x3 balance: {} ETH", new_balance_0x3);
    println!("  - TX4 sees account 0x4 balance: {} ETH", new_account_0x4);

    assert_eq!(new_balance_0x1, "800", "TX4 should see new balance");
    assert_eq!(new_balance_0x2, "700", "TX4 should see new balance");
    assert_eq!(new_account_0x4, "100", "TX4 should see new account");

    // Transaction lifecycle
    println!("\n--- Transaction reference counting and cleanup ---");

    let protected_offsets_before = db.get_protected_offsets();
    println!(
        "Protected offsets before cleanup: {:?}",
        protected_offsets_before
    );
    assert_eq!(
        protected_offsets_before.len(),
        2,
        "Should protect 2 different snapshots"
    );

    // Drop old transactions
    drop(tx1);
    drop(tx2);
    drop(tx3);

    assert_eq!(
        db.active_transaction_count(),
        1,
        "Should have 1 active transaction after drops"
    );

    let protected_offsets_after = db.get_protected_offsets();
    println!(
        "After dropping TX1-3, active transactions: {}",
        db.active_transaction_count()
    );
    println!(
        "Protected offsets after cleanup: {:?}",
        protected_offsets_after
    );
    assert_eq!(
        protected_offsets_after.len(),
        1,
        "Should only protect 1 snapshot now"
    );

    // Multiple snapshots from different blocks
    println!("\n--- Multiple readers from different block snapshots ---");

    // Create another block
    trie.insert(b"account:0x1:balance".to_vec(), b"600".to_vec())?; // 0x1 sent 200 more
    trie.insert(b"account:0x3:balance".to_vec(), b"450".to_vec())?; // 0x3 received 200

    let root_node3 = trie.root_node()?.unwrap();
    db.commit(&root_node3)?;
    trie.commit().unwrap();

    println!("Block 3 committed");
    println!("  - Account 0x1: 800 → 600 ETH (sent 200 more)");
    println!("  - Account 0x3: 250 → 450 ETH (received 200)\n");

    // Create readers from different snapshots
    let tx_block2 = tx4; // Keep reference to block 2 reader
    let tx_block3 = db.begin_read()?; // New reader sees block 3

    assert_ne!(
        tx_block2.snapshot_offset(),
        tx_block3.snapshot_offset(),
        "Different transactions should have different snapshot offsets"
    );

    // Verify each sees their respective block data
    let block2_balance =
        String::from_utf8(tx_block2.get(b"account:0x1:balance")?.unwrap()).unwrap();
    let block3_balance =
        String::from_utf8(tx_block3.get(b"account:0x1:balance")?.unwrap()).unwrap();

    assert_eq!(block2_balance, "800", "Block 2 reader sees block 2 state");
    assert_eq!(block3_balance, "600", "Block 3 reader sees block 3 state");

    println!(
        "TX from block 2 snapshot sees: 0x1 = {} ETH",
        block2_balance
    );
    println!(
        "TX from block 3 snapshot sees: 0x1 = {} ETH",
        block3_balance
    );

    assert_eq!(
        db.active_transaction_count(),
        2,
        "Should end with 2 active transactions"
    );
    assert_eq!(
        db.get_protected_offsets().len(),
        2,
        "Should protect 2 snapshots"
    );

    Ok(())
}
