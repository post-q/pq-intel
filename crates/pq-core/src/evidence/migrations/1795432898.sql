-- Epoch 1795432898 (2026-11-23): policy rows for collection kinds added
-- after the epoch-1795432897 seed. All timestamps are UTC Unix seconds.
--
-- Port-sweep collections are first-class: fresh ~24h, stale reuse
-- permitted ~7d (conservative connect sweep).
INSERT OR IGNORE INTO refresh_policies (kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs) VALUES
    ('ports', 'default', 86400, 1, 604800, NULL, NULL);

-- Refresh policy for the certwatch DB read path (kind `ct-db`,
-- pq-map's primary CT source, promoted into pq-core). Same freshness
-- shape as `ct`: results are cached indefinitely (the query itself
-- filters to currently-valid certificates).
INSERT OR IGNORE INTO refresh_policies (kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs) VALUES
    ('ct-db', 'default', NULL, 0, NULL, NULL, NULL)
;
