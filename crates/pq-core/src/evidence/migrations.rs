//! Epoch-versioned migration running — the plumbing behind the store's
//! ([`schema_migrations`]), the tasking plane's (`task_migrations`), and
//! the hub's (`hub_migrations`) schema ledgers.
//!
//! The Command pattern applied to schema changes: every migration file is
//! a command — an incremental schema change (create, alter, or drop; the
//! file decides) — named `<epoch>.sql` for its definition time in unix
//! seconds; the per-plane ledger table is the journal of executed
//! commands; and the runner applies not-yet-journaled commands in
//! ascending epoch order, one transaction per command. Append-only: a new
//! schema change is always a new command, never an edit of an applied one.
//!
//! Epochs sort like time, name files directly, and never renumber: two
//! planes may even share an epoch, since each ledger only compares within
//! itself.

use crate::evidence::error::Result;
use crate::evidence::store::now_secs;
use rusqlite::Connection;

/// One step of a migration command: an SQL batch, or a Rust hook for what
/// SQL cannot express (SQLite has no conditional `ALTER TABLE`).
pub enum Step {
    Sql(&'static str),
    Fn(fn(&Connection) -> Result<()>),
}

/// Apply every migration whose epoch is newer than the ledger's newest
/// applied epoch (idempotent: a second run is a no-op). Each command runs
/// in its own transaction together with its journal insert — a command is
/// recorded applied iff it ran to completion.
pub fn apply(conn: &Connection, ledger: &str, migrations: &[(i64, &[Step])]) -> Result<()> {
    debug_assert!(
        !ledger.is_empty()
            && ledger
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "ledger must be a plain SQL identifier"
    );
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {ledger} (
             epoch      INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         );"
    ))?;
    let current: i64 = conn.query_row(
        &format!("SELECT COALESCE(MAX(epoch), 0) FROM {ledger}"),
        [],
        |r| r.get(0),
    )?;
    for &(epoch, steps) in migrations {
        if epoch <= current {
            continue;
        }
        let txn = conn.unchecked_transaction()?;
        for step in steps {
            match step {
                Step::Sql(sql) => txn.execute_batch(sql)?,
                Step::Fn(f) => f(&txn)?,
            }
        }
        txn.execute(
            &format!("INSERT INTO {ledger} (epoch, applied_at) VALUES (?1, ?2)"),
            rusqlite::params![epoch, now_secs()],
        )?;
        txn.commit()?;
    }
    Ok(())
}
