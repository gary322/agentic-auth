//! Tamper-evident receipts: append-only log with hash chaining.
//!
//! The purpose is auditability and debugging without leaking secrets. Store only
//! metadata and hashes, not raw secrets.

mod store;

pub use store::{ReceiptStore, ReceiptStoreError, ReceiptStoreOptions};
