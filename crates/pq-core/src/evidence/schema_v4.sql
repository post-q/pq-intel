-- v4: the tasking plane's link as plain data. A scan records the task it
-- executes (NULL for task-less interactive runs) so per-task due selection
-- and freshness are plain column reads; previously the task id was only
-- recoverable by JSON-deserializing `invocation` on every row of every
-- query. The write path extracts it once at insert; this backfill covers
-- stores written before the migration.
ALTER TABLE scans ADD COLUMN task_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_scans_task ON scans(task_id);
UPDATE scans
   SET task_id = json_extract(invocation, '$.task_id')
 WHERE json_extract(invocation, '$.task_id') IS NOT NULL;
