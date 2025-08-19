//! Profile of EthrexDB when inserting 100k keys and then 20 batches of 5k keys.
//! Then, it does 500k random gets.

use ethrexdb::{
    EthrexDB,
    trie::{InMemoryTrieDB, Trie},
};
use rand::{Rng, thread_rng};
use std::time::Instant;

fn main() {
    let db_path = std::env::temp_dir().join("profile_ethrexdb.db");
    let mut db = EthrexDB::new(db_path.clone()).unwrap();

    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));
    let mut keys = Vec::new();

    // Phase 1: Initial population (100k keys)
    print!("Initial population (100k keys)... ");
    let start_phase1 = Instant::now();

    for i in 0..100_000 {
        let key = format!("initial_key_{:08}", i);
        let value = format!("initial_value_{:08}", i);

        trie.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec())
            .unwrap();
        keys.push(key);
    }

    let root_node = trie.root_node().unwrap().unwrap();
    let initial_file_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap();
    db.commit(&root_node).unwrap();
    let after_initial_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap();
    trie.commit().unwrap(); // Convert to CoW references

    println!(
        "Done in {:?} - DB size: {:.1} MB",
        start_phase1.elapsed(),
        (after_initial_size - initial_file_size) as f64 / 1_048_576.0
    );

    print!("Incremental updates (20 batches of 5k keys)... ");
    let start_phase2 = Instant::now();

    for batch in 0..20 {
        let batch_start = Instant::now();
        let pre_batch_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap();

        // Add 5,000 new keys
        for i in 0..5_000 {
            let key = format!("batch_{}_key_{:08}", batch, i);
            let value = format!("batch_{}_value_{:08}", batch, i);

            trie.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec())
                .unwrap();
            keys.push(key);
        }

        // Also update some existing keys to demonstrate CoW efficiency
        let mut rng = thread_rng();
        for _ in 0..100 {
            let idx = rng.gen_range(0..keys.len().min(100_000)); // Only update initial keys
            let updated_value = format!("updated_in_batch_{}_value", batch);
            trie.insert(
                keys[idx].as_bytes().to_vec(),
                updated_value.as_bytes().to_vec(),
            )
            .unwrap();
        }

        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node).unwrap();
        let post_batch_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap();
        trie.commit().unwrap(); // Convert to CoW references

        let _batch_time = batch_start.elapsed();
        let _batch_growth = post_batch_size - pre_batch_size;
    }

    let phase2_duration = start_phase2.elapsed();
    let final_file_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap();
    let incremental_growth = final_file_size - after_initial_size;

    println!(
        "Done in {:?} - DB grew: {:.1} MB",
        phase2_duration,
        incremental_growth as f64 / 1_048_576.0
    );

    print!("Performance test (500k random gets)... ");
    let start_gets = Instant::now();

    let mut rng = thread_rng();

    for i in 0..500_000 {
        let key = if i % 10 == 0 {
            // 10% misses - random non-existent keys
            format!("nonexistent_key_{}", rng.r#gen::<u32>())
        } else {
            // 90% hits - existing keys
            keys[rng.gen_range(0..keys.len())].clone()
        };
        db.get(key.as_bytes()).unwrap();
    }

    let gets_duration = start_gets.elapsed();
    println!(
        "Done in {:?} - Avg: {:?}/get",
        gets_duration,
        gets_duration / 500_000
    );

    println!("Total keys: {}", keys.len());
    println!(
        "Final DB size: {:.1} MB",
        final_file_size as f64 / 1_048_576.0
    );
    println!("Total time: {:?}", start_phase1.elapsed());

    // Clean up temp file
    drop(db);
    let _ = std::fs::remove_file(&db_path);
}
