//! The store's schema migrations: epoch-versioned commands under
//! `migrations/`, run by the shared runner ([`super::migrations`]) into the
//! `schema_migrations` ledger. The first command creates exactly the eight
//! collection-plane tables (the interpretation plane — entities, facts,
//! findings — arrives in its own later migration), the documented indexes,
//! and seeds the default refresh policies; later commands are incremental
//! policy rows and the scans/task link.

use crate::evidence::error::Result;
use rusqlite::Connection;

use super::migrations::{self, Step};

/// Ordered migration commands: `(epoch, steps)`. Append-only; a new
/// migration is always a new entry, never an edit of an applied one.
pub(crate) const MIGRATIONS: &[(i64, &[Step])] = &[
    (
        1_795_432_897,
        &[Step::Sql(include_str!("migrations/1795432897.sql"))],
    ),
    (
        1_795_432_898,
        &[Step::Sql(include_str!("migrations/1795432898.sql"))],
    ),
    (
        1_795_697_236,
        &[Step::Sql(include_str!("migrations/1795697236.sql"))],
    ),
    (
        1_795_774_756,
        &[
            Step::Fn(add_scans_task_id_column),
            Step::Sql(include_str!("migrations/1795774756.sql")),
        ],
    ),
];

/// **Low-level seam.** Apply the store's versioned migrations to a raw
/// SQLite connection.
///
/// Exists for the tasking plane's bundle path, which materializes a fresh
/// store-shaped SQLite file (the exported evidence bundle) without opening
/// a [`crate::evidence::Store`]. Everything else opens a store and lets
/// `Store::open` run this.
pub fn migrate(conn: &Connection) -> Result<()> {
    migrations::apply(conn, "schema_migrations", MIGRATIONS)
}

/// Add `scans.task_id` if absent. SQLite cannot `ADD COLUMN IF NOT
/// EXISTS`; stores whose ledger predates the epoch renaming already have
/// the column (the command originally ran as schema_v4), so the pragma
/// guard keeps the command re-runnable across both ledger shapes.
fn add_scans_task_id_column(conn: &Connection) -> Result<()> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name = 'task_id'",
        [],
        |r| r.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE scans ADD COLUMN task_id INTEGER;")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_all_migrations_and_records_epochs() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let applied: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT epoch FROM schema_migrations ORDER BY epoch")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            applied,
            MIGRATIONS.iter().map(|(v, _)| *v).collect::<Vec<_>>()
        );

        // Re-running is a no-op (open is idempotent).
        migrate(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, MIGRATIONS.len() as i64);
    }

    #[test]
    fn migrations_create_exactly_the_expected_tables() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let mut tables: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        tables.retain(|t| t != "schema_migrations");
        assert_eq!(
            tables,
            [
                "artifacts",
                "collection_state",
                "collections",
                "observation_artifacts",
                "observations",
                "refresh_policies",
                "scan_observations",
                "scans",
            ]
        );
    }

    /// Old development stores carry ledgers recording versions 1..4 from
    /// the pre-epoch numbering, over a fully built schema; the epoch
    /// commands must adopt them (every statement a no-op, ledger extended,
    /// data untouched) rather than crash on re-creation.
    #[test]
    fn epoch_commands_adopt_pre_epoch_ledgers() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn.execute_batch(
            "DELETE FROM schema_migrations;
             INSERT INTO schema_migrations (epoch, applied_at) VALUES (1, 0), (2, 0), (3, 0), (4, 0);",
        )
        .unwrap();
        let policies_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM refresh_policies", [], |r| r.get(0))
            .unwrap();

        migrate(&conn).unwrap();

        let applied: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT epoch FROM schema_migrations ORDER BY epoch")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            applied,
            [1, 2, 3, 4]
                .into_iter()
                .chain(MIGRATIONS.iter().map(|(v, _)| *v))
                .collect::<Vec<_>>()
        );
        let policies_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM refresh_policies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(policies_after, policies_before, "no seed duplicated");
    }
}
