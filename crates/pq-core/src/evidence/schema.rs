//! The store's schema migrations: epoch-versioned commands under
//! `migrations/`, run by the shared runner ([`super::migrations`]) into the
//! `schema_migrations` ledger. The first command creates exactly the eight
//! collection-plane tables (the interpretation plane — entities, facts,
//! findings — arrives in its own later migration), the documented indexes,
//! and seeds the default refresh policies; later commands are incremental
//! policy rows and the scans/task link.

use crate::evidence::error::Result;
use rusqlite::Connection;

use super::migrations::{self, Migration, Step};

/// Ordered migration commands. Append-only; a new migration is always a
/// new entry, never an edit of an applied one.
pub(crate) const MIGRATIONS: &[Migration] = &[
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
            Step::AddColumnIfAbsent {
                table: "scans",
                column: "task_id",
                ddl: "ALTER TABLE scans ADD COLUMN task_id INTEGER;",
            },
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

    /// A genuine pre-epoch store: schema fully built, journal keyed by
    /// bare `version` numbers as the old runner recorded them. The epoch
    /// commands must adopt it — journal rebuilt with the real epochs,
    /// replay a no-op, data untouched — not crash on the missing `epoch`
    /// column.
    #[test]
    fn epoch_commands_adopt_pre_epoch_ledgers() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn.execute_batch(
            "DROP TABLE schema_migrations;
             CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
             INSERT INTO schema_migrations (version, applied_at) VALUES (1, 0), (2, 0), (3, 0), (4, 0);",
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
            MIGRATIONS.iter().map(|(v, _)| *v).collect::<Vec<_>>()
        );
        let policies_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM refresh_policies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(policies_after, policies_before, "no seed duplicated");
    }
}
