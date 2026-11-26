//! Versioned schema migrations.
//!
//! The v1 migration creates exactly the eight v1 tables (the collection
//! plane; the interpretation plane — entities, facts, findings — arrives in
//! its own later migration), the documented indexes, and seeds the default
//! refresh policies. v2 adds policy rows for collection kinds introduced
//! after the v1 seed (port sweeps, the certwatch DB read path).

use crate::evidence::error::Result;
use crate::evidence::store::now_secs;
use rusqlite::Connection;

/// Ordered migration list: `(version, sql)`. Append-only; a new migration is
/// always a new entry, never an edit of an applied one.
pub(crate) const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("schema_v1.sql")),
    (2, include_str!("schema_v2.sql")),
    (3, include_str!("schema_v3.sql")),
];

/// **Low-level seam.** Apply the store's versioned migrations to a raw
/// SQLite connection.
///
/// Exists for the tasking plane's bundle path, which materializes a fresh
/// store-shaped SQLite file (the exported evidence bundle) without opening
/// a [`crate::evidence::Store`]. Everything else opens a store and lets
/// `Store::open` run this.
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         );",
    )?;
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    for &(version, sql) in MIGRATIONS {
        if version <= current {
            continue;
        }
        conn.execute_batch(&format!(
            "BEGIN;
             {sql}
             INSERT INTO schema_migrations (version, applied_at) VALUES ({version}, {});
             COMMIT;",
            now_secs()
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_all_migrations_and_records_versions() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let applied: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT version FROM schema_migrations ORDER BY version")
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
}
