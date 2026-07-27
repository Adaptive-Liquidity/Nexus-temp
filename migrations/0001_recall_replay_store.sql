SELECT pg_advisory_xact_lock(5640004627203514946);

CREATE TABLE IF NOT EXISTS public.nexus_recall_replay_schema (
    schema_name TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT nexus_recall_replay_schema_name
        CHECK (schema_name = 'nexus.recall.replay'),
    CONSTRAINT nexus_recall_replay_schema_version_positive
        CHECK (schema_version > 0)
);

INSERT INTO public.nexus_recall_replay_schema (schema_name, schema_version)
VALUES ('nexus.recall.replay', 1)
ON CONFLICT (schema_name) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.nexus_recall_replay_nonces (
    replay_namespace BYTEA NOT NULL,
    nonce TEXT NOT NULL,
    expires_at_unix_ms BIGINT NOT NULL,
    first_consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT nexus_recall_replay_nonces_pkey
        PRIMARY KEY (replay_namespace, nonce),
    CONSTRAINT nexus_recall_replay_namespace_length
        CHECK (octet_length(replay_namespace) = 32),
    CONSTRAINT nexus_recall_replay_nonce_shape
        CHECK (octet_length(nonce) = 64 AND nonce ~ '^[0-9a-f]{64}$'),
    CONSTRAINT nexus_recall_replay_expiry_nonnegative
        CHECK (expires_at_unix_ms >= 0)
);

CREATE INDEX IF NOT EXISTS nexus_recall_replay_expiry_idx
    ON public.nexus_recall_replay_nonces
    (expires_at_unix_ms, replay_namespace, nonce);
