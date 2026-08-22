use std::collections::BTreeMap;
use std::fs;

use tempfile::TempDir;

use super::*;

const FIXTURE_RECEIPT_DIGEST: &str =
    "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
const FIXTURE_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const FIXTURE_RUNNER_ARTIFACT_DIGEST: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const FIXTURE_RUNNER_CONFIGURATION_DIGEST: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const FIXTURE_TARGET_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
const FIXTURE_GENESIS_KEY_BRIDGE_DIGEST: &str =
    "e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592";

fn deployment_scope() -> FleetScope {
    FleetScope::new(
        Uuid::from_u128(1),
        "physical-project",
        "deployment-agent",
        None,
        PrivacyTier::T1Project,
    )
    .expect("scope")
}

fn model_bundle() -> TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::write(directory.path().join("config.json"), b"config").expect("config");
    fs::write(directory.path().join("model.safetensors"), b"weights").expect("weights");
    fs::write(directory.path().join("tokenizer.json"), b"tokenizer").expect("tokenizer");
    directory
}

#[test]
fn model_bundle_digest_is_stable_and_content_addressed() {
    let first = model_bundle();
    let second = model_bundle();
    let digest = model_bundle_sha256(first.path()).expect("digest");

    assert_eq!(digest, model_bundle_sha256(first.path()).expect("digest"));
    assert_eq!(digest, model_bundle_sha256(second.path()).expect("digest"));

    fs::write(second.path().join("config.json"), b"different").expect("mutate");
    assert_ne!(digest, model_bundle_sha256(second.path()).expect("digest"));
}

#[test]
fn configured_digest_and_registry_identity_are_verified() {
    let bundle = model_bundle();
    let digest = model_bundle_sha256(bundle.path()).expect("digest");
    let config = FleetConfig {
        database_url: "postgresql://example.invalid/defaultdb".into(),
        database_ssl_policy: PrivatePostgresSslPolicy::VerifyFull,
        default_scope: FleetScope::new(
            Uuid::from_u128(1),
            "project",
            "agent",
            None,
            PrivacyTier::T1Project,
        )
        .expect("scope"),
        max_connections: 1,
        embedding_model: "logical/model".into(),
        embedding_model_path: bundle.path().into(),
        embedding_model_sha256: digest.clone(),
        writer_authority: None,
    };

    assert!(config.verify_embedding_model_bundle().is_ok());
    assert_eq!(
        config.embedding_model_identity(),
        format!("logical/model@sha256:{digest}")
    );

    let mut mismatched = config;
    mismatched.embedding_model_sha256 = "0".repeat(64);
    assert!(mismatched.verify_embedding_model_bundle().is_err());
}

#[test]
fn model_bundle_requires_every_runtime_file() {
    let bundle = model_bundle();
    fs::remove_file(bundle.path().join("tokenizer.json")).expect("remove");

    let error = model_bundle_sha256(bundle.path()).expect_err("missing file must fail");
    assert!(error.to_string().contains("tokenizer.json"));
}

#[test]
fn debug_never_exposes_database_credentials() {
    let bundle = model_bundle();
    let config = FleetConfig {
        database_url:
            "postgresql://operator:super-secret@example.invalid/defaultdb?sslmode=verify-full"
                .into(),
        database_ssl_policy: PrivatePostgresSslPolicy::VerifyFull,
        default_scope: FleetScope::new(
            Uuid::from_u128(1),
            "project",
            "agent",
            None,
            PrivacyTier::T1Project,
        )
        .expect("scope"),
        max_connections: 1,
        embedding_model: "logical/model".into(),
        embedding_model_path: bundle.path().into(),
        embedding_model_sha256: "0".repeat(64),
        writer_authority: None,
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("super-secret"));
    assert!(!debug.contains("operator:"));
    assert!(debug.contains("<redacted>"));
}

fn serving_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "FLEET_RECALL_TENANT_ID",
            "0198a849-f6ae-7d61-9800-000000000001".into(),
        ),
        ("FLEET_RECALL_PROJECT", "physical-project".into()),
        ("FLEET_RECALL_AGENT", "deployment-agent".into()),
        ("FLEET_RECALL_MAX_CONNECTIONS", "4".into()),
        (
            "FLEET_RECALL_EMBEDDING_MODEL",
            "logical/publication-model".into(),
        ),
        (
            "FLEET_RECALL_EMBEDDING_MODEL_PATH",
            "/opt/fleet-recall/model".into(),
        ),
        ("FLEET_RECALL_EMBEDDING_MODEL_SHA256", "a".repeat(64)),
    ])
}

#[test]
fn publication_config_uses_only_its_dedicated_database_identity() {
    let mut values = serving_values();
    values.insert(
        "FLEET_RECALL_PUBLICATION_DATABASE_URL",
        "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );

    let config = PublicationConfig::from_lookup(|name| values.get(name).cloned())
        .expect("publication config");

    assert_eq!(
        config.database_url(),
        "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
    );
    assert_eq!(
        config.database_ssl_policy(),
        PrivatePostgresSslPolicy::VerifyFull
    );
    assert_eq!(config.runtime.database_url, config.database_url);
    let debug = format!("{config:?}");
    assert!(!debug.contains("reader-secret"));
    assert!(!debug.contains("fleet_publication:"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn publication_config_rejects_writer_cross_wiring_without_reflection() {
    for forbidden_name in PUBLICATION_FORBIDDEN_DATABASE_URL_ENV_NAMES {
        let mut values = serving_values();
        values.insert(
            "FLEET_RECALL_PUBLICATION_DATABASE_URL",
            "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        );
        values.insert(
            forbidden_name,
            "postgresql://private:private-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        );

        let error = PublicationConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("private URL presence must fail closed")
            .to_string();

        assert!(error.contains(forbidden_name));
        assert!(error.contains("value is redacted"));
        for secret in ["private-secret", "reader-secret"] {
            assert!(!error.contains(secret));
        }
    }
}

#[test]
fn writer_config_never_falls_back_to_publication_url() {
    let mut values = serving_values();
    values.insert(
        "FLEET_RECALL_PUBLICATION_DATABASE_URL",
        "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );

    let error = FleetConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("private runtime must require the writer URL")
        .to_string();
    assert_eq!(
        error,
        "configuration error: FLEET_RECALL_DATABASE_URL is required"
    );

    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://fleet_writer:writer-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );
    let config = FleetConfig::from_lookup(|name| values.get(name).cloned()).expect("writer config");
    assert!(config.database_url.contains("fleet_writer:writer-secret"));
    assert!(!config.database_url.contains("reader-secret"));
    assert_eq!(
        config.database_ssl_policy,
        PrivatePostgresSslPolicy::VerifyFull
    );
}

#[test]
fn writer_and_migrator_configs_require_distinct_decoded_users() {
    let mut writer_values = serving_values();
    writer_values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://%66leet_writer:writer-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );
    let writer = FleetConfig::from_lookup(|name| writer_values.get(name).cloned())
        .expect("decoded canonical writer config");
    assert_eq!(
        writer.database_ssl_policy,
        PrivatePostgresSslPolicy::VerifyFull
    );

    let mut migrator_values = serving_values();
    migrator_values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://%66leet_migrator:migrator-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );
    let migrator = FleetConfig::from_migrator_lookup(|name| migrator_values.get(name).cloned())
        .expect("decoded canonical migrator config");
    assert_eq!(
        migrator.database_ssl_policy,
        PrivatePostgresSslPolicy::VerifyFull
    );

    for (database_url, expected_user, supplied_user, supplied_password, migrator_mode) in [
        (
            "postgresql://fleet_migrator:cross-secret-1@cluster.example:26257/fleet_recall?sslmode=verify-full",
            WRITER_POSTGRES_USER,
            MIGRATOR_POSTGRES_USER,
            "cross-secret-1",
            false,
        ),
        (
            "postgresql://fleet_writer:cross-secret-2@cluster.example:26257/fleet_recall?sslmode=verify-full",
            MIGRATOR_POSTGRES_USER,
            WRITER_POSTGRES_USER,
            "cross-secret-2",
            true,
        ),
    ] {
        let mut values = serving_values();
        values.insert("FLEET_RECALL_DATABASE_URL", database_url.into());
        let result = if migrator_mode {
            FleetConfig::from_migrator_lookup(|name| values.get(name).cloned())
        } else {
            FleetConfig::from_lookup(|name| values.get(name).cloned())
        };
        let error = result
            .expect_err("cross-wired runtime identity must fail closed")
            .to_string();
        assert!(error.contains(expected_user));
        assert!(error.contains("value is redacted"));
        assert!(!error.contains(database_url));
        assert!(!error.contains(supplied_user));
        assert!(!error.contains(supplied_password));
    }
}

#[test]
fn private_runtime_config_rejects_alternate_database_and_implicit_local_tls() {
    let mut values = serving_values();
    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://fleet_writer:database-secret-42@cluster.example:26257/other?sslmode=verify-full"
            .into(),
    );
    let error = FleetConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("alternate database must fail closed")
        .to_string();
    assert!(error.contains(PRIVATE_RUNTIME_POSTGRES_DATABASE));
    assert!(error.contains("value is redacted"));
    assert!(!error.contains("database-secret-42"));

    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://fleet_writer:local-secret@127.0.0.1:26257/fleet_recall".into(),
    );
    values.insert("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE", "1".into());
    let error = FleetConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("local escape must state sslmode explicitly")
        .to_string();
    assert!(error.contains("explicit supported sslmode"));
    assert!(!error.contains("local-secret"));

    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://fleet_writer:local-secret@127.0.0.1:26257/fleet_recall?sslmode=disable"
            .into(),
    );
    let config = FleetConfig::from_lookup(|name| values.get(name).cloned())
        .expect("explicit local writer config");
    assert_eq!(
        config.database_ssl_policy,
        PrivatePostgresSslPolicy::Disable
    );

    let malformed = "postgresql://fleet_writer:malformed-secret-42@cluster.example:notaport/fleet_recall?sslmode=verify-full";
    values.insert("FLEET_RECALL_DATABASE_URL", malformed.into());
    let error = FleetConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("malformed private URL must fail closed")
        .to_string();
    assert!(error.contains("value is redacted"));
    assert!(!error.contains(malformed));
    assert!(!error.contains("malformed-secret-42"));
}

#[test]
fn publication_url_is_canonical_explicit_and_redacted() {
    let accepted = "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
    assert_eq!(
        validate_publication_database_url(accepted, false).expect("cloud publication URL"),
        PrivatePostgresSslPolicy::VerifyFull
    );
    assert_eq!(
        validate_publication_database_url(
            "postgresql://%66leet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            false,
        )
        .expect("decoded canonical publication user"),
        PrivatePostgresSslPolicy::VerifyFull
    );

    for rejected in [
        "postgresql://fleet_publication:secret@cluster.example:26257/other?sslmode=verify-full",
        "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall",
        "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=require",
        "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker",
        "postgresql://fleet_publication:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full",
    ] {
        let error = validate_publication_database_url(rejected, false)
            .expect_err("closed publication URL must reject alternate authority")
            .to_string();
        assert!(!error.contains("fleet_publication:secret"));
    }

    let local =
        "postgresql://fleet_publication:secret@127.0.0.1:26257/fleet_recall?sslmode=disable";
    assert!(validate_publication_database_url(local, false).is_err());
    assert_eq!(
        validate_publication_database_url(local, true).expect("explicit local escape"),
        PrivatePostgresSslPolicy::Disable
    );
    assert!(
        validate_publication_database_url(
            "postgresql://fleet_publication:secret@127.0.0.1:26257/fleet_recall",
            true,
        )
        .is_err(),
        "even the local escape must state sslmode explicitly"
    );
}

#[test]
fn publication_url_rejects_wrong_decoded_user_without_reflection() {
    for (database_url, supplied_user, supplied_password) in [
        (
            "postgresql://writer_identity_42:wrong-user-secret-42@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "writer_identity_42",
            "wrong-user-secret-42",
        ),
        (
            "postgresql://%66leet_writer_43:encoded-wrong-secret-43@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "fleet_writer_43",
            "encoded-wrong-secret-43",
        ),
    ] {
        let error = validate_publication_database_url(database_url, false)
            .expect_err("wrong decoded publication user must fail closed")
            .to_string();

        assert!(error.contains(PUBLICATION_POSTGRES_USER));
        assert!(error.contains("value is redacted"));
        assert!(!error.contains(database_url));
        assert!(!error.contains(supplied_user));
        assert!(!error.contains(supplied_password));
    }
}

#[test]
fn cloud_database_urls_require_full_tls_verification() {
    assert!(
        validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full",
            "TEST_DATABASE_URL",
        )
        .is_ok()
    );
    assert!(
        validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=require",
            "TEST_DATABASE_URL",
        )
        .is_err()
    );
    assert!(
        validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=disable",
            "TEST_DATABASE_URL",
        )
        .is_err()
    );
}

#[test]
fn database_url_query_parameters_are_closed() {
    assert!(
        validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem",
            "TEST_DATABASE_URL",
        )
        .is_ok()
    );

    for parameter in [
        "ssl-mode=disable",
        "ssl-mode=verify-full",
        "ssl-root-cert=/tmp/ca.pem",
        "ssl-ca=/tmp/ca.pem",
        "host=attacker.example",
        "hostaddr=127.0.0.1",
        "port=5432",
        "dbname=other",
        "user=other",
        "password=other",
        "options=-csearch_path%3Dattacker",
        "options[search_path]=attacker",
        "application_name=other",
        "statement-cache-capacity=0",
        "unknown=value",
    ] {
        let url = format!(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&{parameter}"
        );
        assert!(
            validate_database_url(&url, "TEST_DATABASE_URL").is_err(),
            "accepted {parameter}"
        );
    }

    let error = validate_database_url(
        "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&forged%0Alog-line=secret-value",
        "TEST_DATABASE_URL",
    )
    .expect_err("decoded control characters in query names must fail closed")
    .to_string();
    assert!(error.contains("name and value are redacted"));
    for reflected in ["forged", "log-line", "secret-value", "\n"] {
        assert!(!error.contains(reflected), "error reflected {reflected:?}");
    }

    for query in [
        "sslmode=verify-full&sslmode=disable",
        "sslrootcert=/tmp/one.pem&sslrootcert=/tmp/two.pem&sslmode=verify-full",
        "sslmode=verify-full&sslrootcert=relative.pem",
    ] {
        let url = format!("postgresql://user:secret@cluster.example:26257/defaultdb?{query}");
        assert!(
            validate_database_url(&url, "TEST_DATABASE_URL").is_err(),
            "accepted {query}"
        );
    }

    assert!(
        validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full#ignored",
            "TEST_DATABASE_URL",
        )
        .is_err()
    );
}

#[test]
fn control_bootstrap_authority_is_explicit_and_scope_bound() {
    let config = control_bootstrap_config(
        &deployment_scope(),
        "tenant.authority",
        "project.authority",
        FIXTURE_RECEIPT_DIGEST,
    )
    .expect("control config");

    assert_eq!(config.trusted_scope().project(), "physical-project");
    assert_eq!(
        config
            .trusted_scope()
            .semantic_scope()
            .tenant_namespace
            .as_str(),
        "tenant.authority"
    );
    assert_eq!(
        config
            .trusted_scope()
            .semantic_scope()
            .project_namespace
            .as_str(),
        "project.authority"
    );
    assert_eq!(
        config.receipt_digest().digest().to_string(),
        FIXTURE_RECEIPT_DIGEST
    );
    let debug = format!("{config:?}");
    assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn control_bootstrap_authority_rejects_noncanonical_values() {
    assert!(
        control_bootstrap_config(
            &deployment_scope(),
            "Tenant.Invalid",
            "project.authority",
            FIXTURE_RECEIPT_DIGEST,
        )
        .is_err()
    );
    assert!(
        control_bootstrap_config(
            &deployment_scope(),
            "tenant.authority",
            "project.authority",
            &FIXTURE_RECEIPT_DIGEST.to_ascii_uppercase(),
        )
        .is_err()
    );

    let mut invalid_physical = deployment_scope();
    invalid_physical.project = " project ".into();
    assert!(
        control_bootstrap_config(
            &invalid_physical,
            "tenant.authority",
            "project.authority",
            FIXTURE_RECEIPT_DIGEST,
        )
        .is_err()
    );
}

#[test]
fn private_bootstrap_runtime_config_has_no_model_or_agent_dependency() {
    let config = control_bootstrap_runtime_config(
        "postgresql://bootstrap:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "0198a849-f6ae-7d61-9800-000000000001",
        "physical-project",
        "tenant.authority",
        "project.authority",
        FIXTURE_RECEIPT_DIGEST,
    )
    .expect("private bootstrap runtime config");

    assert_eq!(
        config.authority().trusted_scope().project(),
        "physical-project"
    );
    assert_eq!(
        config
            .authority()
            .trusted_scope()
            .semantic_scope()
            .project_namespace
            .as_str(),
        "project.authority"
    );
    assert_eq!(
        config.database_ssl_policy(),
        PrivatePostgresSslPolicy::VerifyFull
    );
    let debug = format!("{config:?}");
    assert!(!debug.contains("bootstrap:secret"));
    assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn private_control_database_requires_explicit_connection_identity() {
    for database_url in [
        "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://bootstrap@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://bootstrap:@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://bootstrap:secret@cluster.example/fleet_recall?sslmode=verify-full",
        "postgresql://bootstrap:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
        "postgresql://bootstrap:secret@cluster.example:26257?sslmode=verify-full",
        "postgresql://bootstrap:secret@cluster.example:26257///?sslmode=verify-full",
    ] {
        assert!(
            control_bootstrap_runtime_config(
                database_url,
                "0198a849-f6ae-7d61-9800-000000000001",
                "physical-project",
                "tenant.authority",
                "project.authority",
                FIXTURE_RECEIPT_DIGEST,
            )
            .is_err(),
            "accepted incomplete control database identity"
        );
    }
}

fn registry_activation_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "FLEET_RECALL_REGISTRY_DATABASE_URL",
            "postgresql://activation:registry-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_TENANT_ID",
            "0198a849-f6ae-7d61-9800-000000000001".into(),
        ),
        ("FLEET_RECALL_REGISTRY_PROJECT", "physical-project".into()),
        (
            "FLEET_RECALL_REGISTRY_TENANT_NAMESPACE",
            "tenant.authority".into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_PROJECT_NAMESPACE",
            "project.authority".into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_BOOTSTRAP_RECEIPT_DIGEST",
            FIXTURE_RECEIPT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST",
            FIXTURE_TEST_RESULT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_TEST_RUNNER_ARTIFACT_DIGEST",
            FIXTURE_RUNNER_ARTIFACT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_TEST_RUNNER_CONFIGURATION_DIGEST",
            FIXTURE_RUNNER_CONFIGURATION_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID",
            "principal.operator".into(),
        ),
        (
            "FLEET_RECALL_REGISTRY_PACKAGE_AUTHOR_PRINCIPAL_ID",
            "principal.author".into(),
        ),
    ])
}

#[test]
fn private_registry_activation_config_is_fully_bound_and_redacted() {
    let values = registry_activation_values();
    let config = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect("private registry activation config");

    assert_eq!(
        config.authority().trusted_scope().tenant_id(),
        Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
    );
    assert_eq!(
        config.authority().trusted_scope().project(),
        "physical-project"
    );
    assert_eq!(
        config
            .authority()
            .trusted_scope()
            .semantic_scope()
            .tenant_namespace
            .as_str(),
        "tenant.authority"
    );
    assert_eq!(
        config.authority().bootstrap_receipt_digest().to_string(),
        FIXTURE_RECEIPT_DIGEST
    );

    let debug = format!("{config:?}");
    for secret in [
        "registry-secret",
        FIXTURE_RECEIPT_DIGEST,
        FIXTURE_TEST_RESULT_DIGEST,
        FIXTURE_RUNNER_ARTIFACT_DIGEST,
        FIXTURE_RUNNER_CONFIGURATION_DIGEST,
        "principal.operator",
        "principal.author",
    ] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("<redacted>"));
}

#[test]
fn registry_activation_database_has_no_serving_or_bootstrap_fallback() {
    let mut values = registry_activation_values();
    values.remove("FLEET_RECALL_REGISTRY_DATABASE_URL");
    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://serving:wrong@cluster.example/fleet?sslmode=verify-full".into(),
    );
    values.insert(
        "FLEET_RECALL_CONTROL_DATABASE_URL",
        "postgresql://bootstrap:wrong@cluster.example/fleet?sslmode=verify-full".into(),
    );

    let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("dedicated registry database URL must be required");
    assert!(
        error
            .to_string()
            .contains("FLEET_RECALL_REGISTRY_DATABASE_URL is required")
    );
}

#[test]
fn registry_activation_database_never_inherits_the_serving_tls_escape() {
    let mut values = registry_activation_values();
    values.insert(
        "FLEET_RECALL_REGISTRY_DATABASE_URL",
        "postgresql://activation:secret@127.0.0.1:26257/fleet_recall?sslmode=disable".into(),
    );

    let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("private activation must require full TLS even on loopback");
    assert!(
        error
            .to_string()
            .contains("FLEET_RECALL_REGISTRY_DATABASE_URL must set exactly sslmode=verify-full")
    );
}

#[test]
fn private_registry_database_requires_explicit_connection_identity() {
    for database_url in [
        "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://activation@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://activation:@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://activation:secret@cluster.example/fleet_recall?sslmode=verify-full",
        "postgresql://activation:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
        "postgresql://activation:secret@cluster.example:26257?sslmode=verify-full",
        "postgresql://activation:secret@cluster.example:26257///?sslmode=verify-full",
    ] {
        let mut values = registry_activation_values();
        values.insert("FLEET_RECALL_REGISTRY_DATABASE_URL", database_url.into());
        assert!(
            RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_err(),
            "accepted incomplete registry database identity"
        );
    }
}

#[test]
fn registry_activation_rejects_encoded_unix_socket_host_before_tls_acceptance() {
    let mut values = registry_activation_values();
    values.insert(
        "FLEET_RECALL_REGISTRY_DATABASE_URL",
        "postgresql://activation:secret@%2Fvar%2Frun%2Fpostgres/fleet_recall?sslmode=verify-full"
            .into(),
    );

    let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err("encoded Unix-socket routing must not satisfy strict TLS policy");
    assert!(matches!(&error, FleetError::Configuration(_)));
    assert!(
        error.to_string().contains("encoded or Unix-socket host"),
        "wrong encoded-host error: {error}"
    );
}

#[test]
fn registry_activation_authority_rejects_noncanonical_pins_and_ids() {
    let mut values = registry_activation_values();
    values.insert(
        "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST",
        FIXTURE_TEST_RESULT_DIGEST.to_ascii_uppercase(),
    );
    assert!(
        RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_err()
    );

    let mut values = registry_activation_values();
    values.insert(
        "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID",
        "Principal.Invalid".into(),
    );
    assert!(
        RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_err()
    );
}

const SUCCESSOR_VARIABLES: [&str; 17] = [
    "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
    "FLEET_RECALL_SUCCESSOR_TENANT_ID",
    "FLEET_RECALL_SUCCESSOR_PROJECT",
    "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
    "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
    "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
    "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
    "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
    "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
    "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
    "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
    "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
    "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
    "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
    "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
    "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
    "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
];

fn successor_activation_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
            "postgresql://successor:successor-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_TENANT_ID",
            "0198a849-f6ae-7d61-9800-000000000001".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_PROJECT",
            "physical-project".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
            "tenant.authority".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
            "project.authority".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
            FIXTURE_RECEIPT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
            FIXTURE_TEST_RESULT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
            FIXTURE_RUNNER_ARTIFACT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
            FIXTURE_RUNNER_CONFIGURATION_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
            FIXTURE_TARGET_TEST_RESULT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
            FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
            FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
            FIXTURE_GENESIS_KEY_BRIDGE_DIGEST.into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
            "principal.genesis_operator".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
            "principal.genesis_author".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
            "principal.successor_operator".into(),
        ),
        (
            "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
            "principal.successor_author".into(),
        ),
    ])
}

fn successor_configuration_error(
    values: &BTreeMap<&'static str, String>,
    context: &str,
) -> FleetError {
    let error = SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect_err(context);
    assert!(
        matches!(&error, FleetError::Configuration(_)),
        "successor environment ingestion returned a non-configuration error: {error:?}"
    );
    error
}

#[test]
fn private_successor_activation_config_is_fully_bound() {
    let values = successor_activation_values();
    let config = SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect("private successor activation config");
    let authority = config.authority();

    assert_eq!(
        authority.trusted_scope().tenant_id(),
        Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
    );
    assert_eq!(authority.trusted_scope().project(), "physical-project");
    assert_eq!(
        authority
            .trusted_scope()
            .semantic_scope()
            .tenant_namespace
            .as_str(),
        "tenant.authority"
    );
    assert_eq!(
        authority
            .trusted_scope()
            .semantic_scope()
            .project_namespace
            .as_str(),
        "project.authority"
    );
    assert_eq!(
        authority.bootstrap_receipt_digest().to_string(),
        FIXTURE_RECEIPT_DIGEST
    );
    assert_eq!(
        authority.bootstrap_pin(),
        BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
            parse_digest(FIXTURE_RECEIPT_DIGEST, "fixture").unwrap(),
        ))
    );
    assert_eq!(
        authority.genesis_test_runner_pin(),
        RegistryTestRunnerPin::from_trusted_config(
            parse_digest(FIXTURE_RUNNER_ARTIFACT_DIGEST, "fixture").unwrap(),
            parse_digest(FIXTURE_RUNNER_CONFIGURATION_DIGEST, "fixture").unwrap(),
            RegistryTestResultDigest::from_digest(
                parse_digest(FIXTURE_TEST_RESULT_DIGEST, "fixture").unwrap(),
            ),
        )
    );
    assert_eq!(
        authority.target_test_runner_pin(),
        SuccessorRegistryTestRunnerPin::from_trusted_config(
            parse_digest(FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST, "fixture").unwrap(),
            parse_digest(FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST, "fixture",).unwrap(),
            RegistryTestResultDigest::from_digest(
                parse_digest(FIXTURE_TARGET_TEST_RESULT_DIGEST, "fixture").unwrap(),
            ),
        )
    );
    assert_eq!(
        authority.genesis_key_bridge_digest().to_string(),
        FIXTURE_GENESIS_KEY_BRIDGE_DIGEST
    );
    assert_eq!(
        authority.genesis_key_bridge_pin(),
        GenesisSuccessorKeyBridgePin::from_trusted_config(
            GenesisSuccessorKeyBridgeDigest::from_digest(
                parse_digest(FIXTURE_GENESIS_KEY_BRIDGE_DIGEST, "fixture").unwrap(),
            ),
        )
    );
    assert_eq!(
        authority.genesis_principal_binding(),
        GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.genesis_operator").unwrap(),
            ContractId::new("principal.genesis_author").unwrap(),
        )
    );
    assert_eq!(
        authority.successor_principal_binding(),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.successor_operator").unwrap(),
            ContractId::new("principal.successor_author").unwrap(),
        )
    );
    assert!(config.database_url().contains("successor-secret"));
}

#[test]
fn successor_activation_debug_redacts_credentials_pins_and_principals() {
    let values = successor_activation_values();
    let config =
        SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).unwrap();
    let debug = format!("{config:?}");
    for secret in [
        config.database_url(),
        "successor",
        "successor-secret",
        "cluster.example",
        "fleet_recall",
        FIXTURE_RECEIPT_DIGEST,
        FIXTURE_TEST_RESULT_DIGEST,
        FIXTURE_RUNNER_ARTIFACT_DIGEST,
        FIXTURE_RUNNER_CONFIGURATION_DIGEST,
        FIXTURE_TARGET_TEST_RESULT_DIGEST,
        FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST,
        FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST,
        FIXTURE_GENESIS_KEY_BRIDGE_DIGEST,
        "principal.genesis_operator",
        "principal.genesis_author",
        "principal.successor_operator",
        "principal.successor_author",
    ] {
        assert!(!debug.contains(secret), "debug exposed {secret}");
    }
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("<bound>"));
}

#[test]
fn successor_activation_requires_every_exact_namespaced_variable() {
    for missing in SUCCESSOR_VARIABLES {
        let mut values = successor_activation_values();
        values.remove(missing);
        let error = successor_configuration_error(
            &values,
            "every exact successor variable must be required",
        );
        assert!(
            error
                .to_string()
                .contains(&format!("{missing} is required")),
            "wrong error for {missing}: {error}"
        );
    }

    let values = successor_activation_values();
    let mut requested = Vec::new();
    SuccessorActivationRuntimeConfig::from_lookup(|name| {
        assert!(
            SUCCESSOR_VARIABLES.contains(&name),
            "looked up an unrelated or fallback variable {name}"
        );
        requested.push(name.to_owned());
        values.get(name).cloned()
    })
    .unwrap();
    assert_eq!(requested, SUCCESSOR_VARIABLES);
    assert!(
        requested
            .iter()
            .all(|name| name.starts_with("FLEET_RECALL_SUCCESSOR_"))
    );
}

#[test]
fn successor_activation_has_no_legacy_or_generic_fallbacks() {
    let mut values = successor_activation_values();
    values.remove("FLEET_RECALL_SUCCESSOR_DATABASE_URL");
    values.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://serving:wrong@cluster.example/fleet?sslmode=verify-full".into(),
    );
    values.insert(
        "FLEET_RECALL_CONTROL_DATABASE_URL",
        "postgresql://bootstrap:wrong@cluster.example/fleet?sslmode=verify-full".into(),
    );
    values.insert(
        "FLEET_RECALL_REGISTRY_DATABASE_URL",
        "postgresql://genesis:wrong@cluster.example/fleet?sslmode=verify-full".into(),
    );
    let error = successor_configuration_error(&values, "successor database must never fall back");
    assert!(
        error
            .to_string()
            .contains("FLEET_RECALL_SUCCESSOR_DATABASE_URL is required")
    );

    let mut values = successor_activation_values();
    values.remove("FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST");
    values.insert(
        "FLEET_RECALL_SUCCESSOR_BRIDGE_DIGEST",
        FIXTURE_GENESIS_KEY_BRIDGE_DIGEST.into(),
    );
    let error =
        successor_configuration_error(&values, "generic bridge alias must not supply authority");
    assert!(
        error
            .to_string()
            .contains("FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST is required")
    );
}

#[test]
fn successor_activation_rejects_noncanonical_digests_ids_and_scope() {
    for name in [
        "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
    ] {
        let mut values = successor_activation_values();
        let noncanonical = values.get(name).unwrap().to_ascii_uppercase();
        values.insert(name, noncanonical);
        successor_configuration_error(&values, &format!("accepted noncanonical {name}"));
    }

    for name in [
        "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
        "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
        "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
    ] {
        let mut values = successor_activation_values();
        values.insert(name, "Principal.Invalid".into());
        successor_configuration_error(&values, &format!("accepted noncanonical {name}"));
    }

    for (name, value) in [
        ("FLEET_RECALL_SUCCESSOR_TENANT_ID", "not-a-uuid"),
        (
            "FLEET_RECALL_SUCCESSOR_TENANT_ID",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("FLEET_RECALL_SUCCESSOR_PROJECT", " physical-project "),
    ] {
        let mut values = successor_activation_values();
        values.insert(name, value.into());
        successor_configuration_error(&values, &format!("accepted invalid physical scope {name}"));
    }
}

#[test]
fn successor_activation_database_url_accepts_only_strict_tls_parameters() {
    let mut values = successor_activation_values();
    values.insert(
        "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem".into(),
    );
    assert!(
        SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_ok()
    );

    for url in [
        "https://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "cockroachdb://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql:///fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=require",
        "postgresql://successor:secret@127.0.0.1:26257/fleet_recall?sslmode=disable",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?ssl-mode=verify-full",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&ssl-root-cert=/tmp/ca.pem",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslmode=disable",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=/tmp/one.pem&sslrootcert=/tmp/two.pem",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=relative.pem",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&host=attacker.example",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&hostaddr=127.0.0.1",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&user=other",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&port=5432",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&application_name=other",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&unknown=value",
        "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full#ignored",
    ] {
        let mut values = successor_activation_values();
        values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
        successor_configuration_error(&values, &format!("accepted unsafe successor URL {url}"));
    }
}

#[test]
fn successor_activation_database_url_requires_explicit_connection_identity() {
    for url in [
        "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:@cluster.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:26257?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:26257/?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:26257//?sslmode=verify-full",
        "postgresql://successor:secret@cluster.example:26257///?sslmode=verify-full",
    ] {
        let mut values = successor_activation_values();
        values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
        successor_configuration_error(
            &values,
            &format!("accepted URL with implicit connection identity {url}"),
        );
    }
}

#[test]
fn successor_activation_database_name_is_exact_and_canonical() {
    for database_path in [
        "fleet",
        "defaultdb",
        "fleet_recall/",
        "fleet_recall/other",
        "%66leet_recall",
        "fleet%5Frecall",
    ] {
        let mut values = successor_activation_values();
        values.insert(
            "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
            format!(
                "postgresql://successor:secret@cluster.example:26257/{database_path}?sslmode=verify-full"
            ),
        );
        let error = successor_configuration_error(
            &values,
            &format!("accepted noncanonical successor database path {database_path}"),
        );
        assert!(
            error
                .to_string()
                .contains("must select exactly the fleet_recall database"),
            "wrong database-name error for {database_path}: {error}"
        );
    }
}

#[test]
fn successor_activation_rejects_encoded_unix_socket_and_non_dns_hosts() {
    for url in [
        "postgresql://successor:secret@%2Fvar%2Frun%2Fpostgres/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@%2fvar%2frun%2fpostgres:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@%252Fvar%252Frun%252Fpostgres:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@%5C%5Cserver%5Csocket:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@bad_host.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@-bad.example:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@bad..example:26257/fleet_recall?sslmode=verify-full",
    ] {
        let mut values = successor_activation_values();
        values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
        let error = successor_configuration_error(
            &values,
            &format!("accepted encoded, socket, or non-DNS host {url}"),
        );
        assert!(
            error.to_string().contains("ordinary DNS or IP hostname")
                || error.to_string().contains("encoded or Unix-socket host"),
            "wrong closed-host error for {url}: {error}"
        );
    }
}

#[test]
fn successor_activation_allows_network_ips_only_with_verify_full() {
    for url in [
        "postgresql://successor:secret@127.0.0.1:26257/fleet_recall?sslmode=verify-full",
        "postgresql://successor:secret@[::1]:26257/fleet_recall?sslmode=verify-full",
    ] {
        let mut values = successor_activation_values();
        values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
        SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .unwrap_or_else(|error| panic!("rejected strict-TLS network IP {url}: {error}"));
    }
}

const RECONCILIATION_VARIABLES: [&str; 3] = [
    "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
    "FLEET_RECALL_RECONCILIATION_TENANT_ID",
    "FLEET_RECALL_RECONCILIATION_PROJECT",
];

fn reconciliation_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
            "postgresql://reconciler:reconciliation-secret@cluster.example:26257/fleet_recall?sslmode=verify-full".into(),
        ),
        (
            "FLEET_RECALL_RECONCILIATION_TENANT_ID",
            "0198a849-f6ae-7d61-9800-000000000001".into(),
        ),
        (
            "FLEET_RECALL_RECONCILIATION_PROJECT",
            "physical-project".into(),
        ),
    ])
}

#[test]
fn reconciliation_runtime_config_is_scope_bound_and_redacted() {
    let values = reconciliation_values();
    let config = ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
        .expect("private conflict-reconciliation config");

    assert_eq!(
        config.trusted_scope().tenant_id,
        Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
    );
    assert_eq!(config.trusted_scope().project, "physical-project");
    assert_eq!(
        config.trusted_scope().agent,
        "private-conflict-reconciliation"
    );
    assert_eq!(config.trusted_scope().session_id, None);
    assert_eq!(config.trusted_scope().privacy_tier, PrivacyTier::T1Project);

    let debug = format!("{config:?}");
    for secret in [
        config.database_url(),
        "reconciler",
        "reconciliation-secret",
        "cluster.example",
        "physical-project",
        "0198a849-f6ae-7d61-9800-000000000001",
    ] {
        assert!(!debug.contains(secret), "debug exposed {secret}");
    }
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("<bound>"));
}

#[test]
fn reconciliation_uses_only_its_exact_dedicated_variables() {
    let values = reconciliation_values();
    let mut requested = Vec::new();
    ConflictReconciliationRuntimeConfig::from_lookup(|name| {
        assert!(
            RECONCILIATION_VARIABLES.contains(&name),
            "looked up unrelated or fallback variable {name}"
        );
        requested.push(name.to_owned());
        values.get(name).cloned()
    })
    .expect("dedicated reconciliation variables");
    assert_eq!(requested, RECONCILIATION_VARIABLES);

    for missing in RECONCILIATION_VARIABLES {
        let mut values = reconciliation_values();
        values.remove(missing);
        values.insert(
            "FLEET_RECALL_DATABASE_URL",
            "postgresql://serving:wrong@cluster.example:26257/fleet?sslmode=verify-full".into(),
        );
        values.insert("FLEET_RECALL_TENANT_ID", Uuid::now_v7().to_string());
        values.insert("FLEET_RECALL_PROJECT", "serving-project".into());
        let error =
            ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .expect_err("generic serving variables must not supply reconciliation authority");
        assert!(
            error
                .to_string()
                .contains(&format!("{missing} is required")),
            "wrong error for {missing}: {error}"
        );
    }
}

#[test]
fn reconciliation_database_requires_strict_tls_and_explicit_identity() {
    for url in [
        "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@127.0.0.1:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@[::1]:26257/fleet?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem",
    ] {
        let mut values = reconciliation_values();
        values.insert("FLEET_RECALL_RECONCILIATION_DATABASE_URL", url.into());
        ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .unwrap_or_else(|error| panic!("rejected closed reconciliation URL {url}: {error}"));
    }

    for url in [
        "https://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@cluster.example:26257/fleet",
        "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=disable",
        "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=require",
        "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full&options=-csearch_path%3Dattacker",
        "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full&sslmode=disable",
        "postgresql://:secret@cluster.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler@cluster.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:@cluster.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@cluster.example/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@cluster.example:0/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@cluster.example:26257/?sslmode=verify-full",
        "postgresql://reconciler:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@bad_host.example:26257/fleet?sslmode=verify-full",
        "postgresql://reconciler:secret@-bad.example:26257/fleet?sslmode=verify-full",
    ] {
        let mut values = reconciliation_values();
        values.insert("FLEET_RECALL_RECONCILIATION_DATABASE_URL", url.into());
        assert!(
            ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .is_err(),
            "accepted unsafe reconciliation URL {url}"
        );
    }
}

fn writer_authority_values() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE",
            "tenant.acme".into(),
        ),
        (
            "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE",
            "project.recall".into(),
        ),
        (
            "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST",
            FIXTURE_RECEIPT_DIGEST.into(),
        ),
    ])
}

#[test]
fn writer_authority_pins_are_bound_and_redacted() {
    let values = writer_authority_values();
    let config = WriterAuthorityConfig::from_lookup(|name| values.get(name).cloned())
        .expect("writer authority config")
        .expect("writer authority pins are present");

    assert_eq!(
        config.semantic_scope().tenant_namespace.as_str(),
        "tenant.acme"
    );
    assert_eq!(
        config.semantic_scope().project_namespace.as_str(),
        "project.recall"
    );
    assert_eq!(
        config.bootstrap_receipt_digest().digest(),
        parse_digest(FIXTURE_RECEIPT_DIGEST, "fixture").expect("fixture digest")
    );
    assert_eq!(config.expected_activation_id(), None);
    let debug = format!("{config:?}");
    assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn writer_authority_pins_are_absent_or_complete_but_never_partial() {
    assert!(
        WriterAuthorityConfig::from_lookup(|_| None)
            .expect("absent pin group")
            .is_none()
    );

    for omitted in WRITER_AUTHORITY_PIN_ENV_NAMES {
        let mut values = writer_authority_values();
        values.remove(omitted);
        let error = WriterAuthorityConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("partial writer authority pin set must fail closed");
        assert!(
            format!("{error}").contains(omitted),
            "partial pin error must name the missing variable {omitted}"
        );
    }
}

#[test]
fn writer_authority_break_glass_requires_the_complete_pin_set() {
    let mut values = writer_authority_values();
    values.insert(
        "FLEET_RECALL_EXPECTED_ACTIVATION_ID",
        FIXTURE_TEST_RESULT_DIGEST.into(),
    );
    let config = WriterAuthorityConfig::from_lookup(|name| values.get(name).cloned())
        .expect("writer authority config")
        .expect("writer authority pins are present");
    assert_eq!(
        config.expected_activation_id(),
        Some(parse_digest(FIXTURE_TEST_RESULT_DIGEST, "fixture").expect("fixture digest"))
    );

    let orphan = BTreeMap::from([(
        "FLEET_RECALL_EXPECTED_ACTIVATION_ID",
        FIXTURE_TEST_RESULT_DIGEST.to_owned(),
    )]);
    assert!(
        WriterAuthorityConfig::from_lookup(|name| orphan.get(name).cloned()).is_err(),
        "a break-glass activation ID without the pin group must fail closed"
    );
}

#[test]
fn writer_authority_rejects_noncanonical_pins() {
    for (name, value) in [
        ("FLEET_RECALL_CONTRACT_TENANT_NAMESPACE", " tenant.acme"),
        ("FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE", "Project.Recall"),
        ("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST", "not-a-digest"),
        (
            "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST",
            &FIXTURE_RECEIPT_DIGEST.to_ascii_uppercase(),
        ),
        ("FLEET_RECALL_EXPECTED_ACTIVATION_ID", "0123"),
    ] {
        let mut values = writer_authority_values();
        values.insert(name, value.into());
        assert!(
            WriterAuthorityConfig::from_lookup(|name| values.get(name).cloned()).is_err(),
            "accepted non-canonical writer authority pin {name}"
        );
    }
}

/// ADR 0002 D4 wiring. The pin group only protects a deployment if the
/// process configuration actually reads it, so all three states are
/// asserted through `FleetConfig` itself and not only through
/// `WriterAuthorityConfig`: absent leaves every existing runtime
/// assertion untouched, complete is carried, and partial fails the
/// configuration load that every runtime entry point performs.
#[test]
fn fleet_config_carries_the_writer_authority_pin_group_or_fails_closed() {
    let mut absent = serving_values();
    absent.insert(
        "FLEET_RECALL_DATABASE_URL",
        "postgresql://fleet_writer:writer-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
            .into(),
    );

    let config = FleetConfig::from_lookup(|name| absent.get(name).cloned())
        .expect("an absent pin group must leave the runtime configuration loadable");
    assert!(
        config.writer_authority.is_none(),
        "an absent pin group must leave the event-first path disabled"
    );
    assert_eq!(config.max_connections, 4);
    assert_eq!(config.default_scope.project, "physical-project");
    assert_eq!(config.embedding_model, "logical/publication-model");

    let mut complete = absent.clone();
    complete.extend(writer_authority_values());
    let config = FleetConfig::from_lookup(|name| complete.get(name).cloned())
        .expect("a complete pin group must load");
    let pins = config
        .writer_authority
        .as_ref()
        .expect("a complete pin group must reach the runtime configuration");
    assert_eq!(
        pins.semantic_scope().tenant_namespace.as_str(),
        "tenant.acme"
    );
    assert_eq!(
        pins.semantic_scope().project_namespace.as_str(),
        "project.recall"
    );
    assert_eq!(
        pins.bootstrap_receipt_digest().digest(),
        parse_digest(FIXTURE_RECEIPT_DIGEST, "fixture").expect("fixture digest")
    );
    let debug = format!("{config:?}");
    assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
    assert!(!debug.contains("writer-secret"));

    for omitted in WRITER_AUTHORITY_PIN_ENV_NAMES {
        let mut partial = complete.clone();
        partial.remove(omitted);
        let error = FleetConfig::from_lookup(|name| partial.get(name).cloned())
            .expect_err("a partial pin group must fail the runtime configuration load");
        assert!(
            format!("{error}").contains(omitted),
            "the partial pin error must name the missing variable {omitted}"
        );
        let error = FleetConfig::from_migrator_lookup(|name| {
            if name == "FLEET_RECALL_DATABASE_URL" {
                return Some(
                    "postgresql://fleet_migrator:migrator-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                        .to_owned(),
                );
            }
            partial.get(name).cloned()
        })
        .expect_err("the migrator entry point must fail closed on the same partial set");
        assert!(format!("{error}").contains(omitted));
    }
}

#[test]
fn reconciliation_rejects_invalid_physical_scope() {
    for (name, value) in [
        ("FLEET_RECALL_RECONCILIATION_TENANT_ID", "not-a-uuid"),
        (
            "FLEET_RECALL_RECONCILIATION_TENANT_ID",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("FLEET_RECALL_RECONCILIATION_PROJECT", " physical-project "),
    ] {
        let mut values = reconciliation_values();
        values.insert(name, value.into());
        assert!(
            ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .is_err(),
            "accepted invalid reconciliation scope {name}"
        );
    }
}
