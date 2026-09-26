//! Unit tests for the redactor: every detector positive and negative, and every
//! fail-closed path as an ordinary test.

use super::*;

fn staged(text: &str) -> String {
    match redact(text).disposition {
        RedactionDispositionV1::Stage { text } => text,
        RedactionDispositionV1::Withhold { class } => {
            panic!(
                "expected a stageable body, got a withhold on {}",
                class.as_str()
            )
        }
    }
}

fn classes(text: &str) -> Vec<SecretClassV1> {
    redact(text).classes
}

#[test]
fn clean_text_passes_through_byte_identical() {
    let text = "let me check the deploy log for the failing auth test";
    let outcome = redact(text);
    assert_eq!(outcome.redacted_ranges, 0);
    assert!(outcome.classes.is_empty());
    assert_eq!(staged(text), text);
}

#[test]
fn an_aws_access_key_id_is_detected_and_replaced() {
    let text = "creds are AKIAIOSFODNN7EXAMPLE for the bucket";
    assert_eq!(classes(text), vec![SecretClassV1::AwsAccessKeyId]);
    let redacted = staged(text);
    assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    assert_eq!(redacted, "creds are [REDACTED] for the bucket");
}

#[test]
fn a_short_akia_lookalike_is_not_a_finding() {
    // Fewer than the 16 required tail characters: a real negative.
    assert!(scan_secrets("AKIASHORT").is_empty());
    // The tail must be uppercase alphanumeric only.
    assert!(scan_secrets("AKIAiosfodnn7example").is_empty());
}

#[test]
fn a_bearer_token_is_detected_case_insensitively() {
    let text = "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz01";
    assert!(classes(text).contains(&SecretClassV1::BearerToken));
    let redacted = staged(text);
    assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz01"));
}

#[test]
fn a_short_bearer_value_is_not_a_finding() {
    assert!(scan_secrets("bearer short").is_empty());
}

#[test]
fn an_api_key_assignment_is_detected_in_both_json_and_env_form() {
    for text in [
        r#"{"api_key": "abcdefghijklmnopqrstuvwx"}"#,
        "API_KEY=abcdefghijklmnopqrstuvwx",
        "apikey: abcdefghijklmnopqrstuvwx",
        "SLACK_TOKEN=xoxb-abcdefghijklmnop",
    ] {
        assert!(
            classes(text).contains(&SecretClassV1::ApiKeyAssignment),
            "expected an api-key finding in {text}"
        );
        assert!(!staged(text).contains("abcdefghijklmnop"));
    }
}

#[test]
fn a_short_api_key_value_is_not_a_finding() {
    // Below the minimum assigned-secret length: a real negative, so ordinary
    // prose mentioning a key name is not redacted into uselessness.
    assert!(scan_secrets("api_key=short").is_empty());
    assert!(scan_secrets("the token is unset").is_empty());
}

#[test]
fn a_password_assignment_is_detected_at_a_shorter_length() {
    let text = "PGPASSWORD=hunter22";
    assert!(classes(text).contains(&SecretClassV1::PasswordAssignment));
    assert!(!staged(text).contains("hunter22"));
}

#[test]
fn a_url_embedded_credential_is_detected() {
    let text = "postgres://admin:s3cr3tpass@db.internal:26257/fleet";
    assert!(classes(text).contains(&SecretClassV1::UrlEmbeddedCredential));
    let redacted = staged(text);
    assert!(!redacted.contains("s3cr3tpass"));
    assert!(!redacted.contains("admin:s3cr3tpass"));
}

#[test]
fn a_credential_free_url_is_not_a_finding() {
    assert!(scan_secrets("https://example.com/path?q=1").is_empty());
    assert!(scan_secrets("postgres://db.internal:26257/fleet").is_empty());
}

#[test]
fn a_private_key_block_withholds_the_whole_turn() {
    // The unredactable class: no body is produced at all, so there is nothing
    // for a later stage to leak even a fragment of.
    let text = "here it is\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\ndone";
    let outcome = redact(text);
    assert_eq!(
        outcome.disposition,
        RedactionDispositionV1::Withhold {
            class: SecretClassV1::PrivateKeyBlock
        }
    );
    assert_eq!(outcome.staged_text(), None);
    assert!(outcome.classes.contains(&SecretClassV1::PrivateKeyBlock));
}

#[test]
fn a_truncated_private_key_block_also_withholds() {
    // The exact case the unredactable rule exists for: no reliable footer, so
    // no reliable end of the key material.
    let text = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIB";
    assert!(matches!(
        redact(text).disposition,
        RedactionDispositionV1::Withhold {
            class: SecretClassV1::PrivateKeyBlock
        }
    ));
}

#[test]
fn one_unredactable_class_withholds_a_turn_that_also_has_redactable_ones() {
    // A mixed turn is not partially salvaged: the strongest disposition wins.
    let text = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
    let outcome = redact(text);
    assert_eq!(outcome.staged_text(), None);
    assert!(outcome.classes.contains(&SecretClassV1::AwsAccessKeyId));
    assert!(outcome.classes.contains(&SecretClassV1::PrivateKeyBlock));
}

#[test]
fn exactly_one_secret_class_is_unredactable() {
    // Pins the policy so widening or narrowing it is a deliberate edit.
    let unredactable: Vec<SecretClassV1> = [
        SecretClassV1::PrivateKeyBlock,
        SecretClassV1::AwsAccessKeyId,
        SecretClassV1::BearerToken,
        SecretClassV1::ApiKeyAssignment,
        SecretClassV1::PasswordAssignment,
        SecretClassV1::UrlEmbeddedCredential,
    ]
    .into_iter()
    .filter(|class| !class.is_redactable())
    .collect();
    assert_eq!(unredactable, vec![SecretClassV1::PrivateKeyBlock]);
}

#[test]
fn a_public_key_header_is_not_a_private_key_finding() {
    let text = "-----BEGIN PUBLIC KEY-----\nMFkwEw\n-----END PUBLIC KEY-----";
    assert!(
        !classes(text).contains(&SecretClassV1::PrivateKeyBlock),
        "a public key block is not a private key"
    );
}

#[test]
fn overlapping_detections_collapse_into_one_replacement() {
    // The URL credential range and the password assignment inside it overlap.
    let text = "db=postgres://u:passwordvaluehere@h/x";
    let outcome = redact(text);
    let RedactionDispositionV1::Stage { text: redacted } = &outcome.disposition else {
        panic!("expected a stageable body");
    };
    assert_eq!(redacted.matches(REDACTION_PLACEHOLDER).count(), 1);
    assert!(!redacted.contains("passwordvaluehere"));
}

#[test]
fn the_placeholder_does_not_retrigger_any_detector() {
    // If it did, every redaction would cascade into a withhold and the runtime
    // would be useless. This is the fixed point the second scan depends on.
    assert!(scan_secrets(REDACTION_PLACEHOLDER).is_empty());
    assert!(scan_secrets(&format!("api_key={REDACTION_PLACEHOLDER}")).is_empty());
    assert!(scan_secrets(&format!("{REDACTION_PLACEHOLDER}{REDACTION_PLACEHOLDER}")).is_empty());
}

#[test]
fn multiple_secrets_in_one_turn_are_all_replaced() {
    let text = "AKIAIOSFODNN7EXAMPLE and PGPASSWORD=hunter22 and bearer sk-abcdefghijklmnopqr";
    let outcome = redact(text);
    let RedactionDispositionV1::Stage { text: redacted } = &outcome.disposition else {
        panic!("expected a stageable body");
    };
    assert_eq!(outcome.redacted_ranges, 3);
    assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!redacted.contains("hunter22"));
    assert!(!redacted.contains("sk-abcdefghijklmnopqr"));
    assert_eq!(
        outcome.classes,
        {
            let mut expected = vec![
                SecretClassV1::AwsAccessKeyId,
                SecretClassV1::BearerToken,
                SecretClassV1::PasswordAssignment,
            ];
            expected.sort_unstable();
            expected
        },
        "classes are reported sorted and deduplicated"
    );
}

#[test]
fn redaction_is_idempotent_over_its_own_output() {
    let text = "AKIAIOSFODNN7EXAMPLE and PGPASSWORD=hunter22";
    let once = staged(text);
    assert_eq!(staged(&once), once);
}

#[test]
fn every_secret_class_has_a_distinct_stable_label() {
    let classes = [
        SecretClassV1::PrivateKeyBlock,
        SecretClassV1::AwsAccessKeyId,
        SecretClassV1::BearerToken,
        SecretClassV1::ApiKeyAssignment,
        SecretClassV1::PasswordAssignment,
        SecretClassV1::UrlEmbeddedCredential,
    ];
    let mut labels: Vec<&str> = classes.iter().map(|class| class.as_str()).collect();
    labels.sort_unstable();
    let count = labels.len();
    labels.dedup();
    assert_eq!(labels.len(), count);
}

#[test]
fn a_multibyte_body_around_a_secret_survives_redaction_intact() {
    let text = "配置は AKIAIOSFODNN7EXAMPLE です ✅";
    let redacted = staged(text);
    assert_eq!(redacted, "配置は [REDACTED] です ✅");
}
