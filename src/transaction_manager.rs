use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique identifier for transactions
pub type TransactionId = u64;

/// This manager tracks which root offsets are currently being used by active
/// read transactions
pub struct TransactionManager {
    /// Maps root offsets to the number of active transactions using them
    active_snapshots: HashMap<u64, AtomicU64>,
    /// Counter for generating unique transaction IDs
    next_tx_id: AtomicU64,
}

impl TransactionManager {
    /// Creates a new transaction manager
    pub fn new() -> Self {
        Self {
            active_snapshots: HashMap::new(),
            next_tx_id: AtomicU64::new(1),
        }
    }

    /// Registers a new transaction using the given snapshot offset
    /// Returns a unique transaction ID
    pub fn register_snapshot(&mut self, offset: u64) -> TransactionId {
        let tx_id = self.next_tx_id.fetch_add(1, Ordering::Relaxed);

        // Increment reference count for this offset
        self.active_snapshots
            .entry(offset)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        tx_id
    }

    /// Unregisters a transaction, decrementing the reference count
    /// If the count reaches zero, the snapshot is removed from tracking
    pub fn unregister_snapshot(&mut self, offset: u64) {
        if let Some(count) = self.active_snapshots.get(&offset) {
            let new_count = count.fetch_sub(1, Ordering::Relaxed);

            // If count reached 0 (was 1, now 0), remove from HashMap
            if new_count == 1 {
                self.active_snapshots.remove(&offset);
            }
        }
    }

    /// Returns all currently active snapshot offsets
    pub fn get_active_offsets(&self) -> Vec<u64> {
        self.active_snapshots.keys().copied().collect()
    }

    /// Returns the total number of active transactions
    pub fn active_transaction_count(&self) -> usize {
        self.active_snapshots
            .values()
            .map(|count| count.load(Ordering::Relaxed) as usize)
            .sum()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_unregister_single_transaction() {
        let mut tm = TransactionManager::new();

        // No active transactions initially
        assert_eq!(tm.active_transaction_count(), 0);

        // Register a transaction
        let tx_id = tm.register_snapshot(1000);
        assert!(tx_id > 0);
        assert_eq!(tm.active_transaction_count(), 1);

        let active_offsets = tm.get_active_offsets();
        assert_eq!(active_offsets.len(), 1);
        assert!(active_offsets.contains(&1000));

        // Unregister the transaction
        tm.unregister_snapshot(1000);
        assert_eq!(tm.active_transaction_count(), 0);
        assert_eq!(tm.get_active_offsets().len(), 0);
    }

    #[test]
    fn test_multiple_transactions_same_snapshot() {
        let mut tm = TransactionManager::new();

        // Register two transactions for the same offset
        let tx1 = tm.register_snapshot(1000);
        let tx2 = tm.register_snapshot(1000);

        assert_ne!(tx1, tx2); // Different transaction IDs
        assert_eq!(tm.active_transaction_count(), 2);

        // Unregister one transaction
        tm.unregister_snapshot(1000);
        assert_eq!(tm.active_transaction_count(), 1);

        // Unregister the second transaction
        tm.unregister_snapshot(1000);
        assert_eq!(tm.active_transaction_count(), 0);
    }

    #[test]
    fn test_multiple_transactions_different_snapshots() {
        let mut tm = TransactionManager::new();

        // Register transactions for different offsets
        let _tx1 = tm.register_snapshot(1000);
        let _tx2 = tm.register_snapshot(2000);
        let _tx3 = tm.register_snapshot(3000);

        assert_eq!(tm.active_transaction_count(), 3);

        let active_offsets = tm.get_active_offsets();
        assert_eq!(active_offsets.len(), 3);
        assert!(active_offsets.contains(&1000));
        assert!(active_offsets.contains(&2000));
        assert!(active_offsets.contains(&3000));

        // Unregister middle transaction
        tm.unregister_snapshot(2000);
        assert_eq!(tm.active_transaction_count(), 2);
    }

    #[test]
    fn test_unregister_nonexistent_snapshot() {
        let mut tm = TransactionManager::new();

        // Unregistering a non-existent snapshot should not panic
        tm.unregister_snapshot(9999);

        // Should still work normally
        let _tx = tm.register_snapshot(1000);
        assert_eq!(tm.active_transaction_count(), 1);
    }
}
