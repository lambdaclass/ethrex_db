use crate::rlp::RLPDecodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrieError {
    #[error(transparent)]
    RLPDecode(#[from] RLPDecodeError),
    #[error("Verification Error: {0}")]
    Verify(String),
    #[error("Inconsistent internal tree structure")]
    InconsistentTree,
    #[error("Lock Error: Panicked when trying to acquire a lock")]
    LockError,
    #[error("DB Error: {0}")]
    DbError(String),
    #[error("Other Error: {0}")]
    Other(String),
}
