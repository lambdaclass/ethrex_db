//! Ethereum mainnet-like comparison benchmark
//!
//! Compares EthrexDB vs LibMDBX Hash performance with:
//! - Random hash keys (like real accounts)
//! - 104-byte account info (2 hashes + u256 + u64)
//! - 1% random read samples (10x more reads)
//! - Multiple scales: 10k, 100k, 500k and 1M accounts

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

/// Create a libmdbx database with a specific path
fn new_db_with_path<T: Table>(path: PathBuf) -> Arc<Database> {
    use libmdbx::{DatabaseOptions, Mode, ReadWriteOptions};

    let tables = [table_info!(T)].into_iter().collect();
    let options = DatabaseOptions {
        mode: Mode::ReadWrite(ReadWriteOptions {
            max_size: Some(2 * 1024 * 1024 * 1024),
            ..Default::default()
        }),
        ..Default::default()
    };

    Arc::new(
        Database::create_with_options(Some(path), options, &tables)
            .expect("Failed to create DB with path"),
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
    total_accounts: usize,
    write_time_ms: u64,
    read_time_ms: u64,
}

fn run_ethrex_benchmark(
    accounts: &[(Vec<u8>, Vec<u8>)],
    sample_keys: &[Vec<u8>],
) -> Result<BenchmarkResults, Box<dyn std::error::Error>> {
    let db_path = PathBuf::from("ethrex_bench.edb");
    let _ = fs::remove_file(&db_path);

    let mut db = EthrexDB::new(db_path.clone())?;
    let mut trie = Trie::new(Box::new(InMemoryTrieDB::new_empty()));

    let batch_size = 15_000;
    let batches: Vec<_> = accounts.chunks(batch_size).collect();

    let total_write_start = Instant::now();

    for batch in batches.iter() {
        for (key, value) in batch.iter() {
            trie.insert(key.clone(), value.clone())?;
        }

        // Commit db and trie (Convert NodeRef::Node to NodeRef::Hash)
        let root_node = trie.root_node().unwrap().unwrap();
        db.commit(&root_node)?;
        trie.commit()?;
    }

    let total_write_time = total_write_start.elapsed();

    let read_start = Instant::now();
    let mut _successful_reads = 0;

    for key in sample_keys {
        if db.get(key)?.is_some() {
            _successful_reads += 1;
        }
    }

    let read_time = read_start.elapsed();

    // Cleanup
    let _ = fs::remove_file(&db_path);

    Ok(BenchmarkResults {
        total_accounts: accounts.len(),
        write_time_ms: total_write_time.as_millis() as u64,
        read_time_ms: read_time.as_millis() as u64,
    })
}

fn run_libmdbx_benchmark(
    accounts: &[(Vec<u8>, Vec<u8>)],
    sample_keys: &[Vec<u8>],
) -> Result<BenchmarkResults, Box<dyn std::error::Error>> {
    // LibMDBX needs a directory path, it will create the database files inside
    let libmdbx_dir = PathBuf::from("libmdbx_bench_dir");
    let _ = fs::remove_dir_all(&libmdbx_dir);
    fs::create_dir_all(&libmdbx_dir)?;

    let db: LibmdbxTrieDB<TestNodes> =
        LibmdbxTrieDB::new(new_db_with_path::<TestNodes>(libmdbx_dir.clone()));
    let mut trie = Trie::new(Box::new(db));

    let batch_size = 15_000;
    let batches: Vec<_> = accounts.chunks(batch_size).collect();

    let total_write_start = Instant::now();

    for batch in batches.iter() {
        for (key, value) in batch.iter() {
            trie.insert(key.clone(), value.clone())?;
        }

        trie.commit()?;
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

    // Cleanup
    let _ = fs::remove_dir_all(&libmdbx_dir);

    Ok(BenchmarkResults {
        total_accounts: accounts.len(),
        write_time_ms: total_write_time.as_millis() as u64,
        read_time_ms: read_time.as_millis() as u64,
    })
}

fn print_scale_summary(results: &[BenchmarkResults], sample_size: usize, batch_count: usize) {
    let ethrex_result = &results[0];
    let libmdbx_result = &results[1];

    let ethrex_avg_batch = ethrex_result.write_time_ms as f64 / batch_count as f64;
    let libmdbx_avg_batch = libmdbx_result.write_time_ms as f64 / batch_count as f64;

    println!(
        "\n{} accounts ({} batches):",
        ethrex_result.total_accounts, batch_count
    );
    println!(
        "  EthrexDB: {:.0}ms avg/batch, {}ms total write, {}ms read ({} keys)",
        ethrex_avg_batch, ethrex_result.write_time_ms, ethrex_result.read_time_ms, sample_size
    );
    println!(
        "  LibMDBX:  {:.0}ms avg/batch, {}ms total write, {}ms read ({} keys)",
        libmdbx_avg_batch, libmdbx_result.write_time_ms, libmdbx_result.read_time_ms, sample_size
    );
}

fn run_benchmark(
    total_accounts: usize,
) -> Result<Vec<BenchmarkResults>, Box<dyn std::error::Error>> {
    println!("\nBenchmark: {} accounts", total_accounts);
    println!("========================");

    let mut results = Vec::new();

    let mut accounts: Vec<(Vec<u8>, Vec<u8>)> = (0..total_accounts)
        .map(|id| {
            let key = generate_account_hash(id as u64);
            let value = generate_account_info(id as u64);
            (key, value)
        })
        .collect();

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
        "Running benchmarks with {} read samples (1% of total)...",
        sample_keys.len()
    );

    results.push(run_ethrex_benchmark(&accounts, &sample_keys)?);
    results.push(run_libmdbx_benchmark(&accounts, &sample_keys)?);

    let batch_count = accounts.len().div_ceil(15_000);
    print_scale_summary(&results, sample_keys.len(), batch_count);

    Ok(results)
}

fn print_final_comparison(all_results: &[BenchmarkResults], read_samples: &[usize]) {
    println!("\n\nFINAL COMPARISON");
    println!("=================");
    println!(
        "Scale     EthrexDB Write    LibMDBX Write    EthrexDB Read    LibMDBX Read    Keys Read"
    );
    println!(
        "------    -------------    -------------    -------------    ------------    ---------"
    );

    for (i, chunk) in all_results.chunks(2).enumerate() {
        if chunk.len() == 2 {
            let ethrex = &chunk[0];
            let libmdbx = &chunk[1];

            let scale_str = if ethrex.total_accounts >= 1_000_000 {
                format!("{}M", ethrex.total_accounts / 1_000_000)
            } else if ethrex.total_accounts >= 1_000 {
                format!("{}k", ethrex.total_accounts / 1_000)
            } else {
                ethrex.total_accounts.to_string()
            };

            let keys_read = read_samples[i];

            println!(
                "{:<8}  {:>11}ms    {:>11}ms    {:>11}ms    {:>10}ms    {:>9}",
                scale_str,
                ethrex.write_time_ms,
                libmdbx.write_time_ms,
                ethrex.read_time_ms,
                libmdbx.read_time_ms,
                keys_read
            );
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ETHREXDB VS LIBMDBX");
    println!("===================");

    let scales = [10_000, 100_000, 500_000, 1_000_000];
    let mut all_results = Vec::new();
    let mut read_samples = Vec::new();

    for &scale in &scales {
        let sample_size = (scale / 100).clamp(1000, 50_000);
        read_samples.push(sample_size);
        let results = run_benchmark(scale)?;
        all_results.extend(results);
    }

    print_final_comparison(&all_results, &read_samples);

    Ok(())
}
