use std::path::PathBuf;

use anyhow::Context as _;
use briefcase_core::{ReceiptRecord, util::sha256_hex_concat};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use thiserror::Error;
use tokio_rusqlite::Connection;

#[derive(Debug, Clone)]
pub struct ReceiptStoreOptions {
    pub path: PathBuf,
}

impl ReceiptStoreOptions {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptStore {
    conn: Connection,
}

#[derive(Debug, Error)]
pub enum ReceiptStoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("other error: {0}")]
    Other(#[from] anyhow::Error),
}

impl ReceiptStore {
    pub async fn open(opts: ReceiptStoreOptions) -> Result<Self, ReceiptStoreError> {
        if let Some(parent) = opts.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create receipts dir {}", parent.display()))?;
        }

        let conn = Connection::open(&opts.path)
            .await
            .map_err(|e| ReceiptStoreError::Other(anyhow::anyhow!(e)))?;
        conn.call(|conn| {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS receipts (
                  id            INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts_rfc3339     TEXT NOT NULL,
                  prev_hash_hex  TEXT NOT NULL,
                  hash_hex       TEXT NOT NULL,
                  event_json     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS receipts_ts_idx ON receipts(ts_rfc3339);
                "#,
            )?;
            Ok(())
        })
        .await
        .map_err(|e| ReceiptStoreError::Other(anyhow::anyhow!(e)))?;

        Ok(Self { conn })
    }

    pub async fn append(&self, event: Value) -> Result<ReceiptRecord, ReceiptStoreError> {
        // Serialize as a stable struct with deterministic field ordering.
        // serde_json preserves struct field order, which makes the chained hash stable.
        let event_json = serde_json::to_string(&event)?;
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;

                let last: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT id, hash_hex FROM receipts ORDER BY id DESC LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;

                let prev_hash_hex =
                    last.map(|(_, h)| h).unwrap_or_else(|| "0".repeat(64));
                let hash_hex =
                    sha256_hex_concat(&prev_hash_hex, event_json.as_bytes());

                let ts = Utc::now();
                let ts_rfc3339 = ts.to_rfc3339();

                tx.execute(
                    "INSERT INTO receipts (ts_rfc3339, prev_hash_hex, hash_hex, event_json) VALUES (?1, ?2, ?3, ?4)",
                    params![ts_rfc3339, prev_hash_hex, hash_hex, event_json],
                )?;

                let id = tx.last_insert_rowid();
                tx.commit()?;

                Ok(ReceiptRecord {
                    id,
                    ts,
                    prev_hash_hex,
                    hash_hex,
                    event,
                })
            })
            .await
            .map_err(|e| ReceiptStoreError::Other(anyhow::anyhow!(e)))
    }

    pub async fn list(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ReceiptRecord>, ReceiptStoreError> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, ts_rfc3339, prev_hash_hex, hash_hex, event_json
                     FROM receipts ORDER BY id DESC LIMIT ?1 OFFSET ?2",
                )?;

                let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
                    let id: i64 = row.get(0)?;
                    let ts_rfc3339: String = row.get(1)?;
                    let ts: DateTime<Utc> = ts_rfc3339.parse::<DateTime<Utc>>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    let prev_hash_hex: String = row.get(2)?;
                    let hash_hex: String = row.get(3)?;
                    let event_json: String = row.get(4)?;
                    let event: Value = serde_json::from_str(&event_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(ReceiptRecord {
                        id,
                        ts,
                        prev_hash_hex,
                        hash_hex,
                        event,
                    })
                })?;

                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .map_err(|e| ReceiptStoreError::Other(anyhow::anyhow!(e)))
    }

    pub async fn verify_chain(&self) -> Result<(), ReceiptStoreError> {
        let rows: Vec<(i64, String, String, String)> = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, prev_hash_hex, hash_hex, event_json FROM receipts ORDER BY id ASC",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .map_err(|e| ReceiptStoreError::Other(anyhow::anyhow!(e)))?;

        let mut prev_hash_hex = "0".repeat(64);
        for (id, row_prev_hash, row_hash, event_json) in rows {
            if row_prev_hash != prev_hash_hex {
                return Err(ReceiptStoreError::Other(anyhow::anyhow!(
                    "receipt chain broken at id={id}: expected prev_hash={prev_hash_hex}, got {row_prev_hash}"
                )));
            }

            let computed = sha256_hex_concat(&prev_hash_hex, event_json.as_bytes());
            if computed != row_hash {
                return Err(ReceiptStoreError::Other(anyhow::anyhow!(
                    "receipt hash mismatch at id={id}: expected hash={computed}, got {row_hash}"
                )));
            }

            prev_hash_hex = row_hash;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn appends_and_verifies_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.sqlite");
        let store = ReceiptStore::open(ReceiptStoreOptions::new(path))
            .await
            .unwrap();

        store
            .append(serde_json::json!({"kind":"tool_call","tool_id":"echo"}))
            .await
            .unwrap();
        store
            .append(serde_json::json!({"kind":"tool_call","tool_id":"quote"}))
            .await
            .unwrap();

        store.verify_chain().await.unwrap();
        let list = store.list(10, 0).await.unwrap();
        assert_eq!(list.len(), 2);
    }
}
