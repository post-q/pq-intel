-- Epoch 1795697236 (2026-11-26): refresh policy for the ASN capture (kind
-- `asn`): IP registration
-- facts from the RIPEstat `network-info` endpoint. Registration-shaped:
-- fresh ~30d, matching the ripestat/network-info seed (the canonical
-- resource is the IP, so one lookup serves every hostname on it).
INSERT OR IGNORE INTO refresh_policies (kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs) VALUES
    ('asn', 'network-info', 2592000, 0, NULL, NULL, NULL)
;
