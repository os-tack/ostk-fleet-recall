//! The collector redactor: a guarantee-bound view of the crate's one
//! redactor. The matchers themselves are tested in
//! `crate::redaction::provider_shapes_tests` and
//! `crate::redaction::credential_shapes_tests`; this file checks the view.

use super::*;
use crate::collectors::test_support::{provider_placeholders, redactor};

fn staged(text: &str) -> String {
    match redactor().redact(text).disposition {
        CollectorDispositionV1::Stage { text } => text,
        CollectorDispositionV1::Withhold { class } => {
            panic!(
                "expected a stageable text, got a withhold on {}",
                class.as_str()
            )
        }
    }
}

#[test]
fn every_provider_placeholder_is_redacted_through_the_collector_view() {
    for (class, credential) in provider_placeholders() {
        let text = format!("before {credential} after");
        let outcome = redactor().redact(&text);
        assert!(
            outcome
                .classes
                .contains(&CollectedSecretClassV1::Provider(class)),
            "{} was not detected",
            class.as_str()
        );
        assert!(!staged(&text).contains(credential));
        assert_eq!(redactor().scan(&text), scan_collected_secrets(&text));
    }
}

#[test]
fn the_shared_classes_still_apply() {
    let text = "creds are AKIAIOSFODNN7EXAMPLE for the bucket";
    let outcome = redactor().redact(text);
    assert_eq!(
        outcome.classes,
        vec![CollectedSecretClassV1::Shared(
            SecretClassV1::AwsAccessKeyId
        )]
    );
    assert_eq!(staged(text), "creds are [REDACTED] for the bucket");
}

#[test]
fn a_private_key_block_withholds_the_text_whole() {
    let text = "-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----";
    let outcome = redactor().redact(text);
    assert!(matches!(
        outcome.disposition,
        CollectorDispositionV1::Withhold {
            class: CollectedSecretClassV1::Shared(SecretClassV1::PrivateKeyBlock)
        }
    ));
}

#[test]
fn the_redactor_requires_the_active_packages_guarantee() {
    let redactor = redactor();
    assert_eq!(
        redactor.profile_version(),
        COLLECTOR_REDACTION_PROFILE_VERSION
    );
    assert_eq!(COLLECTOR_REDACTION_PROFILE_VERSION, 3);
    assert_eq!(
        redactor.guarantee().policy_id().as_str(),
        "redaction.default"
    );
}
