use ethrexdb::trie::{InMemoryTrieDB, Trie};
use ethrexdb::{EthrexDB, ReadTransaction};
use tempdir::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new("ethrex_transaction_example")?;
    let db_path = temp_dir.path().join("example.edb");

    let db = EthrexDB::new(db_path)?;

    println!("EthrexDB Transaction Example\n");

    // Setup initial state
    println!("Creating initial state");
    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
    trie.insert(b"user:alice:balance".to_vec(), b"100".to_vec())?;
    trie.insert(b"user:bob:balance".to_vec(), b"50".to_vec())?;

    let root_node = trie.root_node()?.unwrap();
    db.commit(&root_node)?;
    trie.commit().unwrap();

    println!("✓ Initial state committed");
    println!("  - Alice balance: 100");
    println!("  - Bob balance: 50");

    // Create a read transaction (captures current snapshot)
    println!("\nStarting read transaction");
    let read_tx = db.begin_read()?;
    let snapshot_offset = read_tx.snapshot_offset();

    println!(
        "✓ Transaction created with snapshot offset: {}",
        snapshot_offset
    );
    println!(
        "  - Alice: {:?}",
        String::from_utf8(read_tx.get(b"user:alice:balance")?.unwrap_or_default())
    );
    println!(
        "  - Bob: {:?}",
        String::from_utf8(read_tx.get(b"user:bob:balance")?.unwrap_or_default())
    );

    let protected_offsets = db.get_protected_offsets();
    assert_eq!(protected_offsets.len(), 1);

    // Make changes to the database while transaction exists
    println!("\nMaking changes to database");

    trie.insert(b"user:alice:balance".to_vec(), b"150".to_vec())?; // Alice got +50
    trie.insert(b"user:bob:balance".to_vec(), b"25".to_vec())?; // Bob spent 25
    trie.insert(b"user:charlie:balance".to_vec(), b"75".to_vec())?; // New user Charlie

    let root_node2 = trie.root_node()?.unwrap();
    db.commit(&root_node2)?;
    trie.commit().unwrap();

    println!("✓ Changes committed to DB");
    println!("  - Alice balance: 100 → 150");
    println!("  - Bob balance: 50 → 25");
    println!("  - Charlie balance: 0 → 75 (new user)");

    // Create transaction from old snapshot to demonstrate isolation
    println!("\nDemonstrating snapshot isolation");
    let old_tx = ReadTransaction::new(&db, snapshot_offset, 999); // Dummy tx_id for example
    let new_tx = db.begin_read()?;

    println!("✓ Old transaction (snapshot {}) sees:", snapshot_offset);
    println!(
        "  - Alice: {:?}",
        String::from_utf8(old_tx.get(b"user:alice:balance").unwrap().unwrap())
    );
    println!(
        "  - Bob: {:?}",
        String::from_utf8(old_tx.get(b"user:bob:balance").unwrap().unwrap())
    );
    let charlie_balance = old_tx.get(b"user:charlie:balance").unwrap();
    assert!(charlie_balance.is_none());
    println!("  - Charlie: {charlie_balance:?} (None - user didn't exist)");

    println!(
        "\n✓ New transaction (snapshot {}) sees:",
        new_tx.snapshot_offset()
    );
    println!(
        "  - Alice: {:?}",
        String::from_utf8(new_tx.get(b"user:alice:balance").unwrap().unwrap())
    );
    println!(
        "  - Bob: {:?}",
        String::from_utf8(new_tx.get(b"user:bob:balance").unwrap().unwrap())
    );

    let charlie_balance = new_tx.get(b"user:charlie:balance").unwrap();
    assert!(charlie_balance.is_some());
    println!(
        "  - Charlie: {:?}",
        String::from_utf8(charlie_balance.unwrap())
    );

    // Latest transaction always sees most recent data
    println!("\nLatest transaction (always sees most recent data):");
    let latest_tx = db.begin_read()?;
    println!(
        "  - Alice: {:?}",
        String::from_utf8(latest_tx.get(b"user:alice:balance").unwrap().unwrap())
    );
    println!(
        "   - Bob: {:?}",
        String::from_utf8(latest_tx.get(b"user:bob:balance").unwrap().unwrap())
    );
    println!(
        "   - Charlie: {:?}",
        String::from_utf8(latest_tx.get(b"user:charlie:balance").unwrap().unwrap())
    );

    Ok(())
}
