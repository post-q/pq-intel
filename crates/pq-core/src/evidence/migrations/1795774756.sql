-- Epoch 1795774756 (2026-11-27): the tasking plane's link as plain data.
-- A scan records the task it executes (NULL for task-less interactive
-- runs) so per-task due selection and freshness are plain column reads;
-- previously the task id was only recoverable by JSON-deserializing
-- `invocation` on every row of every query. The write path extracts it
-- once at insert; this backfill covers stores written before the
-- migration.
--
-- The ADD COLUMN itself runs as a guarded code step paired with this file
-- in schema.rs (SQLite cannot ADD COLUMN IF NOT EXISTS, and stores whose
-- ledger predates the epoch renaming already have the column); this file
-- holds the index and the backfill, both idempotent.
CREATE INDEX IF NOT EXISTS idx_scans_task ON scans(task_id);
UPDATE scans
   SET task_id = json_extract(invocation, '$.task_id')
 WHERE json_extract(invocation, '$.task_id') IS NOT NULL;
