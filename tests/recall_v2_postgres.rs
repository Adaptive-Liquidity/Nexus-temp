#![cfg(feature = "aeon-replay-postgres")]

use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use aeon_nexus_bridge::v2::{
    recall_signed_payload_digest, recall_signing_bytes, to_lowercase_hex, RecallEnvelopeV2,
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use futures::future::join_all;
use nexus::aeon::recall_v2::{
    Clock, ExpectedRecallContext, RecallVerificationPolicy, RecallVerifier, ReplayConsumeResult,
    ReplayNamespace, ReplayStore, ReplayStoreError, TrustedKey, TrustedKeyBundle,
};
use nexus::aeon::recall_v2_postgres::{
    PostgresReplayStore, MAX_PURGE_BATCH_SIZE, POSTGRES_REPLAY_SCHEMA_VERSION,
    POSTGRES_REPLAY_TABLE,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::sync::Barrier;

const DATABASE_URL_ENV: &str = "NEXUS_RECALL_REPLAY_TEST_DATABASE_URL";
const REQUIRE_DATABASE_ENV: &str = "NEXUS_REQUIRE_POSTGRES_REPLAY_TESTS";
const ALLOW_RESET_ENV: &str = "NEXUS_ALLOW_POSTGRES_REPLAY_TEST_RESET";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const ISSUED_AT_MS: i64 = 1_760_000_000_000;
const VECTOR_KEY_ID: &str = "test-key-0001";
const VECTOR_PUBLIC_KEY: [u8; 32] = [
    0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
    0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12,
];

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

struct AlwaysFreshStore;

#[async_trait]
impl ReplayStore for AlwaysFreshStore {
    async fn consume_once(
        &self,
        _namespace: ReplayNamespace,
        _nonce: &str,
        _expires_at_unix_ms: i64,
    ) -> Result<ReplayConsumeResult, ReplayStoreError> {
        Ok(ReplayConsumeResult::Fresh)
    }
}

fn expected_context() -> ExpectedRecallContext {
    ExpectedRecallContext {
        tenant_id: "tenant-0001".to_owned(),
        workspace_id: None,
        agent_id: "agent-0001".to_owned(),
        session_id: Some("session-0001".to_owned()),
        mission_id: None,
        run_id: "9f1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"
            .parse()
            .expect("canonical run id"),
        request_id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
            .parse()
            .expect("canonical request id"),
        query: "what did we decide about retries?".to_owned(),
    }
}

async fn replay_namespaces() -> (ReplayNamespace, ReplayNamespace) {
    let vector_key =
        TrustedKey::from_bytes(VECTOR_KEY_ID, VECTOR_PUBLIC_KEY).expect("valid vector key");
    let second_seed = [0x5a; 32];
    let second_signing_key = SigningKey::from_bytes(&second_seed);
    let second_key = TrustedKey::from_bytes(
        "test-key-0002",
        second_signing_key.verifying_key().to_bytes(),
    )
    .expect("valid second key");
    let verifier = RecallVerifier::new(
        TrustedKeyBundle::new([vector_key, second_key]).expect("trusted test keys"),
        RecallVerificationPolicy::new(5_000).expect("valid policy"),
        FixedClock(ISSUED_AT_MS + 1_000),
        Arc::new(AlwaysFreshStore),
    );

    let vector_json =
        include_str!("../crates/aeon_nexus_bridge/vectors/recall_envelope_v2/envelope.json");
    let first = verifier
        .verify_json(vector_json, &expected_context())
        .await
        .expect("frozen vector verifies")
        .replay_namespace();

    let mut second_envelope: RecallEnvelopeV2 =
        serde_json::from_str(vector_json).expect("vector envelope");
    second_envelope.signature.key_id = "test-key-0002".to_owned();
    second_envelope.signature.signed_payload_digest =
        recall_signed_payload_digest(&second_envelope.payload).expect("payload digest");
    let signing_bytes =
        recall_signing_bytes(&second_envelope.payload).expect("canonical signing bytes");
    second_envelope.signature.signature =
        to_lowercase_hex(&second_signing_key.sign(&signing_bytes).to_bytes());
    let second_json = serde_json::to_string(&second_envelope).expect("second envelope JSON");
    let second = verifier
        .verify_json(&second_json, &expected_context())
        .await
        .expect("second signer verifies")
        .replay_namespace();

    assert_ne!(first, second);
    (first, second)
}

fn nonce(value: u64) -> String {
    format!("{value:064x}")
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn database_url() -> Option<String> {
    match std::env::var(DATABASE_URL_ENV) {
        Ok(value) if !value.trim().is_empty() => {
            assert!(
                env_truthy(ALLOW_RESET_ENV),
                "{ALLOW_RESET_ENV}=1 is required because this test resets dedicated replay tables"
            );
            Some(value)
        }
        _ if env_truthy(REQUIRE_DATABASE_ENV) => {
            panic!("{DATABASE_URL_ENV} is required when {REQUIRE_DATABASE_ENV}=1")
        }
        _ => {
            println!("SKIP: PostgreSQL replay-store integration test - {DATABASE_URL_ENV} unset");
            None
        }
    }
}

async fn connect(database_url: &str, max_connections: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(OPERATION_TIMEOUT)
        .connect(database_url)
        .await
        .unwrap_or_else(|error| panic!("failed to reach PostgreSQL: {error}"))
}

async fn reset_replay_schema(pool: &PgPool) {
    sqlx::raw_sql(
        "DROP TABLE IF EXISTS public.nexus_recall_replay_nonces;
         DROP TABLE IF EXISTS public.nexus_recall_replay_schema;",
    )
    .execute(pool)
    .await
    .expect("dedicated test database permits replay-table reset");
}

async fn count_fresh(
    store: Arc<PostgresReplayStore>,
    namespace: ReplayNamespace,
    nonce: String,
    attempts: usize,
) -> usize {
    let barrier = Arc::new(Barrier::new(attempts));
    let tasks = (0..attempts).map(|_| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let nonce = nonce.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_once(namespace, &nonce, ISSUED_AT_MS + 30_000)
                .await
                .expect("concurrent consume succeeds")
        })
    });
    join_all(tasks)
        .await
        .into_iter()
        .map(|result| result.expect("consume task did not panic"))
        .filter(|result| *result == ReplayConsumeResult::Fresh)
        .count()
}

async fn assert_schema_contract(pool: &PgPool) {
    let version: i32 = sqlx::query_scalar(
        "SELECT schema_version
         FROM public.nexus_recall_replay_schema
         WHERE schema_name = 'nexus.recall.replay'",
    )
    .fetch_one(pool)
    .await
    .expect("schema version row exists");
    assert_eq!(version, POSTGRES_REPLAY_SCHEMA_VERSION);

    let columns = sqlx::query(
        "SELECT column_name, data_type, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(POSTGRES_REPLAY_TABLE)
    .fetch_all(pool)
    .await
    .expect("table columns are inspectable");
    let column = |name: &str| {
        columns
            .iter()
            .find(|row| row.get::<String, _>("column_name") == name)
            .unwrap_or_else(|| panic!("missing {name} column"))
    };
    assert_eq!(
        column("replay_namespace").get::<String, _>("data_type"),
        "bytea"
    );
    assert_eq!(column("nonce").get::<String, _>("data_type"), "text");
    assert_eq!(
        column("expires_at_unix_ms").get::<String, _>("data_type"),
        "bigint"
    );
    assert_eq!(
        column("first_consumed_at").get::<String, _>("data_type"),
        "timestamp with time zone"
    );
    for name in [
        "replay_namespace",
        "nonce",
        "expires_at_unix_ms",
        "first_consumed_at",
    ] {
        assert_eq!(column(name).get::<String, _>("is_nullable"), "NO");
    }

    let primary_key: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE conrelid = 'public.nexus_recall_replay_nonces'::regclass
           AND contype = 'p'",
    )
    .fetch_one(pool)
    .await
    .expect("replay table primary key exists");
    assert_eq!(primary_key, "PRIMARY KEY (replay_namespace, nonce)");

    let index_definitions: Vec<String> = sqlx::query_scalar(
        "SELECT indexdef
         FROM pg_indexes
         WHERE schemaname = 'public' AND tablename = $1",
    )
    .bind(POSTGRES_REPLAY_TABLE)
    .fetch_all(pool)
    .await
    .expect("replay indexes are inspectable");
    assert!(index_definitions
        .iter()
        .any(|definition| definition.contains("(expires_at_unix_ms, replay_namespace, nonce)")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn postgres_replay_store_live_database_contract() {
    let Some(database_url) = database_url() else {
        return;
    };
    let pool = connect(&database_url, 40).await;
    let current_database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("PostgreSQL identity query succeeds");
    println!("POSTGRES_REPLAY_LIVE_DB_REACHED database={current_database}");

    reset_replay_schema(&pool).await;
    assert!(
        PostgresReplayStore::new(pool.clone(), Duration::ZERO)
            .await
            .is_err(),
        "zero operation timeout must fail before schema access"
    );
    assert!(
        PostgresReplayStore::new(pool.clone(), OPERATION_TIMEOUT)
            .await
            .is_err(),
        "construction must fail closed before migration"
    );

    PostgresReplayStore::apply_migrations(&pool, OPERATION_TIMEOUT)
        .await
        .expect("first migration application succeeds");
    PostgresReplayStore::apply_migrations(&pool, OPERATION_TIMEOUT)
        .await
        .expect("migration is idempotent");
    assert_schema_contract(&pool).await;

    sqlx::query(
        "UPDATE public.nexus_recall_replay_schema
         SET schema_version = 2
         WHERE schema_name = 'nexus.recall.replay'",
    )
    .execute(&pool)
    .await
    .expect("test can set an unsupported schema version");
    assert!(
        PostgresReplayStore::new(pool.clone(), OPERATION_TIMEOUT)
            .await
            .is_err(),
        "unsupported schema version must fail construction"
    );
    sqlx::query("UPDATE public.nexus_recall_replay_schema SET schema_version = 1")
        .execute(&pool)
        .await
        .expect("test restores supported schema version");

    let store = Arc::new(
        PostgresReplayStore::new(pool.clone(), OPERATION_TIMEOUT)
            .await
            .expect("migrated schema constructs a store"),
    );
    let (namespace_a, namespace_b) = replay_namespaces().await;
    assert_eq!(store.operation_timeout(), OPERATION_TIMEOUT);

    let exhausted_pool = connect(&database_url, 1).await;
    let exhausted_store =
        PostgresReplayStore::new(exhausted_pool.clone(), Duration::from_millis(250))
            .await
            .expect("pool-exhaustion store constructs");
    let held_connection = exhausted_pool
        .acquire()
        .await
        .expect("test holds the only pooled connection");
    let exhausted = exhausted_store
        .consume_once(namespace_a, &nonce(40), ISSUED_AT_MS + 30_000)
        .await
        .expect_err("pool exhaustion must fail closed");
    assert!(exhausted
        .source()
        .expect("timeout error has source")
        .to_string()
        .contains("timed out"));
    drop(held_connection);
    exhausted_pool.close().await;

    assert_eq!(
        store
            .consume_once(namespace_a, &nonce(1), ISSUED_AT_MS + 30_000)
            .await
            .expect("first consume"),
        ReplayConsumeResult::Fresh
    );
    assert_eq!(
        store
            .consume_once(namespace_a, &nonce(1), ISSUED_AT_MS + 30_000)
            .await
            .expect("second consume"),
        ReplayConsumeResult::Replayed
    );
    assert_eq!(
        store
            .consume_once(namespace_b, &nonce(1), ISSUED_AT_MS + 30_000)
            .await
            .expect("same nonce in different namespace"),
        ReplayConsumeResult::Fresh
    );
    assert_eq!(
        store
            .consume_once(namespace_a, &nonce(2), ISSUED_AT_MS + 30_000)
            .await
            .expect("different nonce in same namespace"),
        ReplayConsumeResult::Fresh
    );

    assert_eq!(
        count_fresh(Arc::clone(&store), namespace_a, nonce(3), 32).await,
        1,
        "one pool must yield exactly one Fresh"
    );

    let second_pool = connect(&database_url, 20).await;
    let second_store = Arc::new(
        PostgresReplayStore::new(second_pool.clone(), OPERATION_TIMEOUT)
            .await
            .expect("second independent pool constructs"),
    );
    let barrier = Arc::new(Barrier::new(32));
    let tasks = (0..32).map(|attempt| {
        let store = if attempt % 2 == 0 {
            Arc::clone(&store)
        } else {
            Arc::clone(&second_store)
        };
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_once(namespace_a, &nonce(4), ISSUED_AT_MS + 30_000)
                .await
                .expect("multi-pool consume")
        })
    });
    let multi_pool_fresh = join_all(tasks)
        .await
        .into_iter()
        .map(|result| result.expect("multi-pool task did not panic"))
        .filter(|result| *result == ReplayConsumeResult::Fresh)
        .count();
    assert_eq!(multi_pool_fresh, 1);

    let restart_pool = connect(&database_url, 2).await;
    let restart_store = PostgresReplayStore::new(restart_pool.clone(), OPERATION_TIMEOUT)
        .await
        .expect("pre-restart store constructs");
    assert_eq!(
        restart_store
            .consume_once(namespace_a, &nonce(5), ISSUED_AT_MS + 30_000)
            .await
            .expect("pre-restart consume"),
        ReplayConsumeResult::Fresh
    );
    drop(restart_store);
    restart_pool.close().await;
    drop(restart_pool);

    let after_restart_pool = connect(&database_url, 2).await;
    let after_restart_store =
        PostgresReplayStore::new(after_restart_pool.clone(), OPERATION_TIMEOUT)
            .await
            .expect("post-restart store constructs");
    assert_eq!(
        after_restart_store
            .consume_once(namespace_a, &nonce(5), ISSUED_AT_MS + 30_000)
            .await
            .expect("post-restart consume"),
        ReplayConsumeResult::Replayed
    );

    for (value, expires_at) in [(10, 100), (11, 200), (12, 300), (13, 50), (14, 60)] {
        assert_eq!(
            store
                .consume_once(namespace_a, &nonce(value), expires_at)
                .await
                .expect("cleanup fixture consume"),
            ReplayConsumeResult::Fresh
        );
    }
    assert_eq!(
        store
            .purge_expired_before(200, 2)
            .await
            .expect("first bounded purge"),
        2
    );
    assert_eq!(
        store
            .purge_expired_before(200, 2)
            .await
            .expect("second bounded purge"),
        1
    );
    assert_eq!(
        store
            .purge_expired_before(200, 2)
            .await
            .expect("idempotent bounded purge"),
        0
    );
    let retained: Vec<String> = sqlx::query_scalar(
        "SELECT nonce FROM public.nexus_recall_replay_nonces
         WHERE replay_namespace = $1 AND nonce = ANY($2)
         ORDER BY nonce",
    )
    .bind(namespace_a.as_bytes().as_slice())
    .bind(vec![nonce(11), nonce(12)])
    .fetch_all(&pool)
    .await
    .expect("retained cleanup rows are readable");
    assert_eq!(retained, vec![nonce(11), nonce(12)]);

    assert_eq!(
        store
            .consume_once(namespace_a, &nonce(20), 10)
            .await
            .expect("race fixture consume"),
        ReplayConsumeResult::Fresh
    );
    let race_barrier = Arc::new(Barrier::new(34));
    let purge_store = Arc::clone(&store);
    let purge_barrier = Arc::clone(&race_barrier);
    let purge = tokio::spawn(async move {
        purge_barrier.wait().await;
        purge_store
            .purge_expired_before(20, 1)
            .await
            .expect("racing purge")
    });
    let race_tasks = (0..32)
        .map(|attempt| {
            let store = if attempt % 2 == 0 {
                Arc::clone(&store)
            } else {
                Arc::clone(&second_store)
            };
            let barrier = Arc::clone(&race_barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .consume_once(namespace_a, &nonce(20), 30)
                    .await
                    .expect("racing consume")
            })
        })
        .collect::<Vec<_>>();
    race_barrier.wait().await;
    let race_fresh = join_all(race_tasks)
        .await
        .into_iter()
        .map(|result| result.expect("race task did not panic"))
        .filter(|result| *result == ReplayConsumeResult::Fresh)
        .count();
    purge.await.expect("purge task did not panic");
    assert!(
        race_fresh <= 1,
        "cleanup racing with consume_once produced {race_fresh} Fresh results"
    );

    let failure_pool = connect(&database_url, 1).await;
    let failure_store = PostgresReplayStore::new(failure_pool.clone(), OPERATION_TIMEOUT)
        .await
        .expect("failure-test store constructs");
    failure_pool.close().await;

    let invalid_nonce = failure_store
        .consume_once(namespace_a, "not-a-protocol-nonce", ISSUED_AT_MS + 30_000)
        .await
        .expect_err("malformed nonce is rejected before SQL");
    assert!(invalid_nonce
        .source()
        .expect("input error has source")
        .to_string()
        .contains("nonce"));
    let invalid_expiry = failure_store
        .consume_once(namespace_a, &nonce(32), -1)
        .await
        .expect_err("negative expiry is rejected before SQL");
    assert!(invalid_expiry
        .source()
        .expect("expiry error has source")
        .to_string()
        .contains("expiry"));
    assert!(failure_store
        .consume_once(namespace_a, &"A".repeat(64), ISSUED_AT_MS + 30_000,)
        .await
        .is_err());
    assert!(failure_store
        .purge_expired_before(-1, 1)
        .await
        .expect_err("negative cutoff rejected before SQL")
        .to_string()
        .contains("cutoff"));
    assert!(failure_store
        .purge_expired_before(0, 0)
        .await
        .expect_err("zero batch rejected before SQL")
        .to_string()
        .contains("batch size"));
    assert!(failure_store
        .purge_expired_before(0, MAX_PURGE_BATCH_SIZE + 1)
        .await
        .expect_err("oversized batch rejected before SQL")
        .to_string()
        .contains("batch size"));
    assert!(
        failure_store
            .consume_once(namespace_a, &nonce(30), ISSUED_AT_MS + 30_000)
            .await
            .is_err(),
        "closed pool must fail closed"
    );

    let wrong_namespace = sqlx::query(
        "INSERT INTO public.nexus_recall_replay_nonces
         (replay_namespace, nonce, expires_at_unix_ms)
         VALUES (decode('00', 'hex'), $1, $2)",
    )
    .bind(nonce(31))
    .bind(ISSUED_AT_MS + 30_000)
    .execute(&pool)
    .await;
    assert!(
        wrong_namespace.is_err(),
        "database rejects malformed namespace"
    );
    let wrong_nonce = sqlx::query(
        "INSERT INTO public.nexus_recall_replay_nonces
         (replay_namespace, nonce, expires_at_unix_ms)
         VALUES ($1, $2, $3)",
    )
    .bind(namespace_a.as_bytes().as_slice())
    .bind("A".repeat(64))
    .bind(ISSUED_AT_MS + 30_000)
    .execute(&pool)
    .await;
    assert!(wrong_nonce.is_err(), "database rejects malformed nonce");

    let missing_table_store = PostgresReplayStore::new(pool.clone(), OPERATION_TIMEOUT)
        .await
        .expect("store constructs before table removal");
    sqlx::query("DROP TABLE public.nexus_recall_replay_nonces")
        .execute(&pool)
        .await
        .expect("test removes replay table");
    assert!(
        missing_table_store
            .consume_once(namespace_a, &nonce(33), ISSUED_AT_MS + 30_000)
            .await
            .is_err(),
        "missing table must fail closed at operation time"
    );

    second_pool.close().await;
    after_restart_pool.close().await;
    pool.close().await;
}
