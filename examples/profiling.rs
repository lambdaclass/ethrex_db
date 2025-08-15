use ethrexdb::{
    EthrexDB,
    trie::trie::{InMemoryTrieDB, Trie},
};
use rand::{Rng, thread_rng};
use std::time::Instant;

fn main() {
    let db_path = std::env::temp_dir().join("profile_gets.edb");
    let mut db = EthrexDB::new(db_path).unwrap();

    println!("Phase 1: Inserting 1,000,000 keys...");

    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
    let mut keys = Vec::new();

    for i in 0..1_000_000 {
        let key = format!("benchmark_key_{:08}", i);
        let value = format!("value_for_key_{:08}", i);

        trie.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec())
            .unwrap();
        keys.push(key);
    }

    // Single commit with all data
    let start_insert = Instant::now();
    let root_node = trie.root_node().unwrap().unwrap();
    db.commit(&root_node).unwrap();
    println!("Insert phase completed in {:?}", start_insert.elapsed());

    // === PHASE 2: Random gets (this is what we want to profile) ===
    println!("Phase 2: Performing 1,000,000 random gets...");
    let start_gets = Instant::now();

    let mut rng = thread_rng();
    let mut hit_count = 0;
    let mut miss_count = 0;

    for i in 0..1_000_000 {
        let key = if i % 10 == 0 {
            // 10% misses - random non-existent keys
            format!("nonexistent_key_{}", rng.r#gen::<u32>())
        } else {
            // 90% hits - existing keys
            keys[rng.gen_range(0..keys.len())].clone()
        };

        match db.get(key.as_bytes()).unwrap() {
            Some(_) => hit_count += 1,
            None => miss_count += 1,
        }

        if i % 10_000 == 0 {
            println!("Completed {} gets", i);
        }
    }

    let gets_duration = start_gets.elapsed();
    println!("Gets phase completed in {:?}", gets_duration);
    println!("Hits: {}, Misses: {}", hit_count, miss_count);
    println!("Total get time: {:?}", gets_duration);
    println!("Average get time: {:?}", gets_duration / 1_000_000);
}
