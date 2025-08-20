//! Ethereum mainnet-like comparison benchmark
//!
//! Compares EthrexDB vs LibMDBX Hash performance with:
//! - Random hash keys (like real accounts)
//! - 104-byte account info (2 hashes + u256 + u64)
//! - 1% random read samples (10x more reads)
//! - Multiple scales: 10k, 100k, 500k, 1M, 10M accounts

use ethrexdb::EthrexDB;
use ethrexdb::trie::{InMemoryTrieDB, NodeHash, Trie, TrieDB, TrieError};
use libmdbx::orm::{Database, Table, table_info};
use libmdbx::table;
use rand::{seq::SliceRandom, thread_rng};
use sha3::{Digest, Keccak256};
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Generate realistic 32-byte hash key (like account address)
fn generate_account_hash(id: u64) -> Vec<u8> {
    Keccak256::new()
        .chain_update(id.to_be_bytes())
        .finalize()
        .to_vec()
}

/// Generate 104-byte account info: 2 hashes + u256 + u64
fn generate_account_info(id: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(104);

    // Storage hash (32 bytes)
    value.extend_from_slice(
        &Keccak256::new()
            .chain_update((id * 2).to_be_bytes())
            .finalize(),
    );

    // Code hash (32 bytes)
    value.extend_from_slice(
        &Keccak256::new()
            .chain_update((id * 3).to_be_bytes())
            .finalize(),
    );

    // Balance u256 (32 bytes) - deterministic based on id
    let balance = (id as u128 % 1000) * 1_000_000_000_000_000_000u128; // ETH in wei
    value.extend_from_slice(&[0u8; 16]); // High 128 bits
    value.extend_from_slice(&balance.to_be_bytes()); // Low 128 bits

    // Nonce u64 (8 bytes)
    value.extend_from_slice(&(id % 1000).to_be_bytes());

    value
}

table!(
    /// Test table for benchmarks.
    (TestNodes) NodeHash => Vec<u8>
);

/// Creates a new temporary DB
fn new_db<T: Table>() -> Arc<Database> {
    use libmdbx::{DatabaseOptions, Mode, ReadWriteOptions};

    let tables = [table_info!(T)].into_iter().collect();
    let options = DatabaseOptions {
        mode: Mode::ReadWrite(ReadWriteOptions {
            max_size: Some(2 * 1024 * 1024 * 1024), // 2GB instead of default
            ..Default::default()
        }),
        ..Default::default()
    };

    Arc::new(
        Database::create_with_options(None, options, &tables).expect("Failed to create temp DB"),
    )
}

pub struct LibmdbxTrieDB<T: Table> {
    db: Arc<Database>,
    phantom: PhantomData<T>,
}

impl<T> LibmdbxTrieDB<T>
where
    T: Table<Key = NodeHash, Value = Vec<u8>>,
{
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            phantom: PhantomData,
        }
    }
}

impl<T> TrieDB for LibmdbxTrieDB<T>
where
    T: Table<Key = NodeHash, Value = Vec<u8>>,
{
    fn get(&self, key: NodeHash) -> Result<Option<Vec<u8>>, TrieError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| TrieError::DbError(e.to_string()))?;
        txn.get::<T>(key)
            .map_err(|e| TrieError::DbError(e.to_string()))
    }

    fn put_batch(&self, key_values: Vec<(NodeHash, Vec<u8>)>) -> Result<(), TrieError> {
        let txn = self
            .db
            .begin_readwrite()
            .map_err(|e| TrieError::DbError(e.to_string()))?;
        for (key, value) in key_values {
            txn.upsert::<T>(key, value)
                .map_err(|e| TrieError::DbError(e.to_string()))?;
        }
        txn.commit().map_err(|e| TrieError::DbError(e.to_string()))
    }
}

#[derive(Debug)]
struct BenchmarkResults {
    db_name: String,
    total_accounts: usize,
    write_time_ms: u64,
    read_time_ms: u64,
    reads_per_sec: f64,
}

fn run_ethrex_benchmark(
    accounts: &[(Vec<u8>, Vec<u8>)],
    sample_keys: &[Vec<u8>],
) -> Result<BenchmarkResults, Box<dyn std::error::Error>> {
    println!("🔥 EthrexDB Benchmark");

    let db_path = PathBuf::from("ethrex_bench.edb");
    let _ = fs::remove_file(&db_path);

    let mut db = EthrexDB::new(db_path.clone())?;
    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));

    // Write performance test - batch processing like Ethereum blocks
    let batch_size = 15_000; // ~Ethereum block size
    let batches: Vec<_> = accounts.chunks(batch_size).collect();
    
    println!("  📝 Processing {} accounts in {} batches of ~{}", 
             accounts.len(), batches.len(), batch_size);
    
    let total_write_start = Instant::now();
    
    for (batch_idx, batch) in batches.iter().enumerate() {
        let batch_start = Instant::now();
        
        // Insert batch into trie
        for (key, value) in batch.iter() {
            trie.insert(key.clone(), value.clone())?;
        }
        
        // Commit batch (like block commit)
        let root_node = trie.root_node()?.ok_or("No root node")?;
        db.commit(&root_node)?;
        trie.commit()?; // Convert to hashes for CoW efficiency
        
        let batch_time = batch_start.elapsed();
        if batch_idx % 10 == 0 || batch_idx == batches.len() - 1 {
            println!("    Batch {}/{}: {}ms ({} accounts)", 
                     batch_idx + 1, batches.len(), batch_time.as_millis(), batch.len());
        }
    }
    
    let total_write_time = total_write_start.elapsed();

    // Read performance test
    let read_start = Instant::now();
    let mut _successful_reads = 0;

    for key in sample_keys {
        if db.get(key)?.is_some() {
            _successful_reads += 1;
        }
    }

    let read_time = read_start.elapsed();
    let reads_per_sec = sample_keys.len() as f64 / read_time.as_secs_f64();

    println!(
        "  ✅ Write: {}ms, Read: {}ms ({:.0} reads/sec)",
        total_write_time.as_millis(),
        read_time.as_millis(),
        reads_per_sec
    );

    // Cleanup
    let _ = fs::remove_file(&db_path);

    Ok(BenchmarkResults {
        db_name: "EthrexDB".to_string(),
        total_accounts: accounts.len(),
        write_time_ms: total_write_time.as_millis() as u64,
        read_time_ms: read_time.as_millis() as u64,
        reads_per_sec,
    })
}

fn run_libmdbx_benchmark(
    accounts: &[(Vec<u8>, Vec<u8>)],
    sample_keys: &[Vec<u8>],
) -> Result<BenchmarkResults, Box<dyn std::error::Error>> {
    println!("🔥 LibMDBX Hash Benchmark");

    let db: LibmdbxTrieDB<TestNodes> = LibmdbxTrieDB::new(new_db::<TestNodes>());
    let mut trie = Trie::new(Box::new(db));

    // Write performance test - batch processing like Ethereum blocks
    let batch_size = 15_000; // ~Ethereum block size
    let batches: Vec<_> = accounts.chunks(batch_size).collect();
    
    println!("  📝 Processing {} accounts in {} batches of ~{}", 
             accounts.len(), batches.len(), batch_size);
    
    let total_write_start = Instant::now();
    
    for (batch_idx, batch) in batches.iter().enumerate() {
        let batch_start = Instant::now();
        
        // Insert batch into trie
        for (key, value) in batch.iter() {
            trie.insert(key.clone(), value.clone())?;
        }
        
        // Commit batch (like block commit)
        trie.commit()?;
        
        let batch_time = batch_start.elapsed();
        if batch_idx % 10 == 0 || batch_idx == batches.len() - 1 {
            println!("    Batch {}/{}: {}ms ({} accounts)", 
                     batch_idx + 1, batches.len(), batch_time.as_millis(), batch.len());
        }
    }
    
    let total_write_time = total_write_start.elapsed();

    // Read performance test
    let read_start = Instant::now();
    let mut _successful_reads = 0;

    for key in sample_keys {
        if trie.get(key)?.is_some() {
            _successful_reads += 1;
        }
    }

    let read_time = read_start.elapsed();
    let reads_per_sec = sample_keys.len() as f64 / read_time.as_secs_f64();

    println!(
        "  ✅ Write: {}ms, Read: {}ms ({:.0} reads/sec)",
        total_write_time.as_millis(),
        read_time.as_millis(),
        reads_per_sec
    );

    Ok(BenchmarkResults {
        db_name: "LibMDBX Hash".to_string(),
        total_accounts: accounts.len(),
        write_time_ms: total_write_time.as_millis() as u64,
        read_time_ms: read_time.as_millis() as u64,
        reads_per_sec,
    })
}

fn print_comparison_table(results: &[BenchmarkResults]) {
    println!("\n📊 COMPARISON TABLE");
    println!("=====================================================================================");
    println!("Database        Accounts    Write Time    Read Time    Reads/Sec    Read Sample");
    println!("---------       --------    ----------    ---------    ---------    -----------");

    for result in results {
        println!(
            "{:<14}  {:>8}    {:>8}ms    {:>7}ms    {:>9.0}    {:>8} keys",
            result.db_name,
            result.total_accounts,
            result.write_time_ms,
            result.read_time_ms,
            result.reads_per_sec,
            if result.total_accounts >= 100 {
                result.total_accounts / 100
            } else {
                result.total_accounts / 10
            }
        );
    }
    println!("=====================================================================================");
}

fn run_scale_benchmark(
    total_accounts: usize,
) -> Result<Vec<BenchmarkResults>, Box<dyn std::error::Error>> {
    println!("\n🔥 Scale: {} accounts", total_accounts);
    println!("========================");

    let mut results = Vec::new();

    // Generate all account data upfront (like mainnet snapshot)
    println!("Generating {} account hashes...", total_accounts);
    let gen_start = Instant::now();
    let mut accounts: Vec<(Vec<u8>, Vec<u8>)> = (0..total_accounts)
        .map(|id| {
            let key = generate_account_hash(id as u64);
            let value = generate_account_info(id as u64);
            (key, value)
        })
        .collect();
    println!("✅ Generated in {:.2}s", gen_start.elapsed().as_secs_f64());

    // Shuffle for random distribution (like real accounts)
    let mut rng = thread_rng();
    accounts.shuffle(&mut rng);

    // Prepare read samples (1% for more reads)
    let sample_size = (total_accounts / 100).clamp(1000, 50_000);
    let mut sample_indices: Vec<usize> = (0..total_accounts).collect();
    sample_indices.shuffle(&mut rng);
    let sample_keys: Vec<_> = sample_indices[..sample_size]
        .iter()
        .map(|&i| accounts[i].0.clone())
        .collect();

    println!(
        "📊 Running benchmarks with {} read samples (1% of total)...",
        sample_keys.len()
    );

    // Benchmark 1: EthrexDB
    results.push(run_ethrex_benchmark(&accounts, &sample_keys)?);

    // Benchmark 2: LibMDBX Hash (Trie)
    results.push(run_libmdbx_benchmark(&accounts, &sample_keys)?);

    // Print comparison table
    print_comparison_table(&results);

    Ok(results)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 EthrexDB vs LibMDBX Mainnet Benchmark");
    println!("========================================");
    println!("Simulating Ethereum account storage patterns");
    println!("Comparing EthrexDB vs LibMDBX Hash (Trie) performance");

    // Multiple scales with more reads (1% sample = 10x more reads than before)
    let scales = [10_000, 100_000, 500_000, 1_000_000, 10_000_000];
    let mut all_results = Vec::new();

    for &scale in &scales {
        let results = run_scale_benchmark(scale)?;
        all_results.extend(results);
    }

    println!("\n🎯 FINAL SUMMARY");
    println!("=================");
    println!("All benchmarks completed with 1% random read samples (10x more reads than before)");
    println!("EthrexDB: mmap + CoW trie with pure HashMap index");
    println!("LibMDBX:  LMDB-based persistent trie storage");

    Ok(())
}
