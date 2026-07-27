#![cfg(feature = "aeon-replay-postgres")]

use std::time::Duration;

use aeon_nexus_bridge::v2::to_lowercase_hex;
use ed25519_dalek::SigningKey;
use nexus::aeon::recall_v2_config::{
    RecallV2ComponentConfig, RecallV2ComponentConfigError, RecallV2ConfigValues,
    RecallV2RuntimeMode, TrustedAeonKeyProvider, TrustedAeonKeyProviderError,
};
use serde_json::json;

const DATABASE_URL: &str =
    "postgres://nexus_config:sensitive-password@db.internal.example/nexus_replay";

fn public_key_hex(seed: u8) -> String {
    to_lowercase_hex(
        &SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn trusted_keys_json(active_key: &str, retired_key: &str) -> String {
    json!({
        "version": 1,
        "keys": [
            {
                "key_id": "aeon-active-2026-07",
                "public_key_hex": active_key,
                "state": "active"
            },
            {
                "key_id": "aeon-retired-2026-06",
                "public_key_hex": retired_key,
                "state": "retired"
            }
        ]
    })
    .to_string()
}

fn enforced_values(trusted_keys_json: Option<String>) -> RecallV2ConfigValues {
    RecallV2ConfigValues {
        mode: Some("enforced".to_owned()),
        trusted_keys_json,
        replay_database_url: Some(DATABASE_URL.to_owned()),
        pool_max_connections: None,
        connect_timeout_ms: None,
        operation_timeout_ms: None,
    }
}

#[test]
fn absent_mode_is_disabled_without_loading_production_components() {
    let config = RecallV2ComponentConfig::from_values(RecallV2ConfigValues::default())
        .expect("absent mode is deterministically disabled");

    assert_eq!(config.mode(), RecallV2RuntimeMode::Disabled);
    assert!(config.enforced().is_none());
}

#[test]
fn enforced_mode_loads_only_explicitly_pinned_active_and_retired_keys() {
    let active_key = public_key_hex(0x31);
    let retired_key = public_key_hex(0x32);
    let config = RecallV2ComponentConfig::from_values(enforced_values(Some(trusted_keys_json(
        &active_key,
        &retired_key,
    ))))
    .expect("valid enforced configuration");
    let enforced = config.enforced().expect("enforced config");
    let trusted = enforced
        .trusted_key_provider()
        .load()
        .expect("pinned key provider");

    assert_eq!(config.mode(), RecallV2RuntimeMode::Enforced);
    assert_eq!(trusted.len(), 2);
    assert_eq!(trusted.active_key_ids(), &["aeon-active-2026-07"]);
    assert_eq!(trusted.retired_key_ids(), &["aeon-retired-2026-06"]);
    assert!(trusted.contains_key("aeon-active-2026-07"));
    assert!(trusted.contains_key("aeon-retired-2026-06"));
    assert!(!trusted.contains_key("response-discovered-key"));
}

#[test]
fn enforced_mode_requires_trusted_keys_and_replay_database() {
    let missing_keys = RecallV2ComponentConfig::from_values(enforced_values(None))
        .expect_err("enforced mode must require pinned keys");
    assert!(matches!(
        missing_keys,
        RecallV2ComponentConfigError::MissingTrustedKeys
    ));

    let mut missing_database = enforced_values(Some(trusted_keys_json(
        &public_key_hex(0x33),
        &public_key_hex(0x34),
    )));
    missing_database.replay_database_url = None;
    let error = RecallV2ComponentConfig::from_values(missing_database)
        .expect_err("enforced mode must require PostgreSQL");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::MissingReplayDatabaseUrl
    ));
}

#[test]
fn key_document_is_strict_and_requires_an_active_rotation_root() {
    let only_retired = json!({
        "version": 1,
        "keys": [{
            "key_id": "retired-only",
            "public_key_hex": public_key_hex(0x35),
            "state": "retired"
        }]
    })
    .to_string();
    let error = RecallV2ComponentConfig::from_values(enforced_values(Some(only_retired)))
        .expect_err("retired-only trust must fail closed");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::TrustedKeys(TrustedAeonKeyProviderError::MissingActiveKey)
    ));

    let unknown_field = json!({
        "version": 1,
        "keys": [{
            "key_id": "active",
            "public_key_hex": public_key_hex(0x36),
            "state": "active",
            "discovered_from_response": true
        }]
    })
    .to_string();
    let error = RecallV2ComponentConfig::from_values(enforced_values(Some(unknown_field)))
        .expect_err("unknown key fields must fail strict parsing");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::TrustedKeys(TrustedAeonKeyProviderError::InvalidDocument)
    ));
}

#[test]
fn duplicate_ids_or_physical_keys_and_noncanonical_hex_are_rejected() {
    let public_key = public_key_hex(0x37);
    let duplicate_id = json!({
        "version": 1,
        "keys": [
            {"key_id": "duplicate", "public_key_hex": public_key, "state": "active"},
            {"key_id": "duplicate", "public_key_hex": public_key_hex(0x38), "state": "retired"}
        ]
    })
    .to_string();
    let error = RecallV2ComponentConfig::from_values(enforced_values(Some(duplicate_id)))
        .expect_err("duplicate key ids must fail");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::TrustedKeys(TrustedAeonKeyProviderError::DuplicateKeyId(_))
    ));

    let duplicate_physical_key = json!({
        "version": 1,
        "keys": [
            {"key_id": "active-alias", "public_key_hex": public_key, "state": "active"},
            {"key_id": "retired-alias", "public_key_hex": public_key, "state": "retired"}
        ]
    })
    .to_string();
    let error = RecallV2ComponentConfig::from_values(enforced_values(Some(duplicate_physical_key)))
        .expect_err("one physical key must not have conflicting lifecycle aliases");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::TrustedKeys(TrustedAeonKeyProviderError::DuplicatePublicKey)
    ));

    let uppercase = json!({
        "version": 1,
        "keys": [{
            "key_id": "uppercase",
            "public_key_hex": public_key_hex(0x39).to_uppercase(),
            "state": "active"
        }]
    })
    .to_string();
    let error = RecallV2ComponentConfig::from_values(enforced_values(Some(uppercase)))
        .expect_err("public keys must use canonical lowercase hex");
    assert!(matches!(
        error,
        RecallV2ComponentConfigError::TrustedKeys(
            TrustedAeonKeyProviderError::InvalidPublicKeyHex { .. }
        )
    ));
}

#[test]
fn pool_and_timeout_configuration_is_deterministic_and_nonzero() {
    let mut values = enforced_values(Some(trusted_keys_json(
        &public_key_hex(0x3a),
        &public_key_hex(0x3b),
    )));
    values.pool_max_connections = Some("7".to_owned());
    values.connect_timeout_ms = Some("2500".to_owned());
    values.operation_timeout_ms = Some("3000".to_owned());
    let config =
        RecallV2ComponentConfig::from_values(values).expect("explicit settings are accepted");
    let enforced = config.enforced().expect("enforced config");

    assert_eq!(enforced.pool_max_connections(), 7);
    assert_eq!(enforced.connect_timeout(), Duration::from_millis(2_500));
    assert_eq!(enforced.operation_timeout(), Duration::from_millis(3_000));

    for field in [
        "pool_max_connections",
        "connect_timeout_ms",
        "operation_timeout_ms",
    ] {
        let mut invalid = enforced_values(Some(trusted_keys_json(
            &public_key_hex(0x3c),
            &public_key_hex(0x3d),
        )));
        match field {
            "pool_max_connections" => invalid.pool_max_connections = Some("0".to_owned()),
            "connect_timeout_ms" => invalid.connect_timeout_ms = Some("0".to_owned()),
            "operation_timeout_ms" => invalid.operation_timeout_ms = Some("0".to_owned()),
            _ => unreachable!(),
        }
        assert!(
            RecallV2ComponentConfig::from_values(invalid).is_err(),
            "{field}=0 must fail closed"
        );
    }
}

#[test]
fn database_credentials_are_redacted_from_configuration_debug_output() {
    let values = enforced_values(Some(trusted_keys_json(
        &public_key_hex(0x3e),
        &public_key_hex(0x3f),
    )));
    let values_debug = format!("{values:?}");
    let config = RecallV2ComponentConfig::from_values(values).expect("valid config");
    let config_debug = format!("{config:?}");

    for rendered in [values_debug, config_debug] {
        assert!(!rendered.contains("sensitive-password"));
        assert!(!rendered.contains(DATABASE_URL));
        assert!(rendered.contains("[REDACTED]"));
    }
}
