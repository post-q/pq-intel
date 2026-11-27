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

/// One step of a migration command: an SQL batch, a Rust hook for what SQL
/// cannot express, or the one guarded change SQLite has no syntax for
/// (`ADD COLUMN IF NOT EXISTS` does not exist).
pub enum Step {
    Sql(&'static str),
    Fn(fn(&Connection) -> Result<()>),
    /// Add `column` to `table` when absent; `ddl` is the full
    /// `ALTER TABLE … ADD COLUMN` statement. The guard keeps commands
    /// re-runnable over stores that already have the column from a
    /// pre-epoch numbering of the same migration.
    AddColumnIfAbsent {
        table: &'static str,
        column: &'static str,
        ddl: &'static str,
    },
}

/// One migration command: its definition epoch (unix seconds) and the
/// steps that realize it.
pub type Migration = (i64, &'static [Step]);

/// Apply every migration whose epoch is newer than the ledger's newest
/// applied epoch (idempotent: a second run is a no-op). Each command runs
/// in its own transaction together with its journal insert — a command is
/// recorded applied iff it ran to completion.
///
/// The ledger is a journal, and every command is re-runnable, so a ledger
/// of unexpected shape — a store whose journal predates the epoch
/// renaming, keyed by bare `version` numbers — is dropped and rebuilt:
/// replaying every command over the schema it recorded is a no-op by
/// design.
pub fn apply(conn: &Connection, ledger: &str, migrations: &[Migration]) -> Result<()> {
    debug_assert!(
        is_plain_identifier(ledger),
        "ledger must be a plain SQL identifier"
    );
    // A missing table answers zero rows too, so this one probe covers
    // fresh stores (create) and foreign-shaped journals (rebuild) alike.
    let epoch_shaped: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM pragma_table_info('{ledger}') WHERE name = 'epoch'"),
        [],
        |r| r.get(0),
    )?;
    if epoch_shaped == 0 {
        conn.execute_batch(&format!(
            "DROP TABLE IF EXISTS {ledger};
             CREATE TABLE {ledger} (
                 epoch      INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             );"
        ))?;
    }
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
                Step::AddColumnIfAbsent { table, column, ddl } => {
                    debug_assert!(
                        is_plain_identifier(table),
                        "table must be a plain SQL identifier"
                    );
                    let present: i64 = txn.query_row(
                        &format!(
                            "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"
                        ),
                        [column],
                        |r| r.get(0),
                    )?;
                    if present == 0 {
                        txn.execute_batch(ddl)?;
                    }
                }
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

fn is_plain_identifier(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
