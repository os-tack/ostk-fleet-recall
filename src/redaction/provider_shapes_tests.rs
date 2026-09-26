//! The provider shapes: every class positive, negative, and replaced; the
//! shared classes still apply beside them; a residual withholds; a redacted
//! text is a fixed point.
//!
//! Every credential here is a placeholder from
//! `crate::collectors::test_support::PLACEHOLDERS`, which proves none of them
//! matches a push-protection pattern.

use super::*;
use crate::collectors::test_support::{STRIPE_PLACEHOLDER, provider_placeholders};
use crate::redaction::{
    REDACTION_PLACEHOLDER, RedactionDispositionV1, SecretClassV1, redact, replace_and_verify,
    scan_secrets,
};

fn provider_classes(text: &str) -> Vec<ProviderSecretClassV1> {
    redact(text)
        .classes
        .into_iter()
        .filter_map(|class| match class {
            CollectedSecretClassV1::Provider(class) => Some(class),
            CollectedSecretClassV1::Shared(_) => None,
        })
        .collect()
}

fn staged(text: &str) -> String {
    match redact(text).disposition {
        RedactionDispositionV1::Stage { text } => text,
        RedactionDispositionV1::Withhold { class } => {
            panic!(
                "expected a stageable text, got a withhold on {}",
                class.as_str()
            )
        }
    }
}

#[test]
fn every_provider_class_is_detected_and_replaced() {
    for (class, credential) in provider_placeholders() {
        let text = format!("before {credential} after");
        assert!(
            provider_classes(&text).contains(&class),
            "{} was not detected in a planted credential",
            class.as_str()
        );
        let redacted = staged(&text);
        assert!(
            !redacted.contains(credential),
            "{} survived redaction",
            class.as_str()
        );
        assert!(redacted.starts_with("before ") && redacted.ends_with(" after"));
        assert!(redacted.contains(REDACTION_PLACEHOLDER));
    }
}

#[test]
fn a_stripe_key_is_detected_under_every_prefix() {
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        let text = format!("charge with {prefix}EXAMPLENOTAKEY00 now");
        assert_eq!(
            provider_classes(&text),
            vec![ProviderSecretClassV1::StripeKey],
            "{prefix}"
        );
        assert_eq!(staged(&text), "charge with [REDACTED] now");
    }
    assert_eq!(
        redact(STRIPE_PLACEHOLDER).classes,
        vec![CollectedSecretClassV1::Provider(
            ProviderSecretClassV1::StripeKey
        )]
    );
}

#[test]
fn look_alikes_are_not_findings() {
    for text in [
        // Prefixes alone, or followed by too little to be a credential.
        "tokens look like xoxb-... in the docs",
        "the xapp- prefix",
        "lin_api_ is the key prefix",
        "lin_wh_ is the webhook secret prefix, lin_wh_short is not one",
        "session tokens start xoxc- or xoxd- and xoxd-short is not one",
        "grn_short",
        "whsec_ is a prefix",
        "ghp_short and github_pat_short",
        "AIzaShort",
        "sk-ant-short",
        // A Stripe prefix in prose, and one whose body stops short of the
        // bound or carries a byte the alphabet rejects.
        "rotate the sk_live_ key before Friday",
        "sk_test_short and sk_live_EXAMPLE-NOT-A-KEY",
        "the field is named risk_live_EXAMPLENOTAKEY00",
        // A word that merely contains a prefix is not at a word boundary.
        "the taskforce-ABCdefghij0123456789 and mask-ABCdefghij0123456789xyz",
        // A long all-lowercase `sk-` identifier is prose, not a generated key.
        "we pinned sk-learn-compatible-estimators-for-the-pipeline",
        // One base64 JSON object is a cursor, not a signed token.
        "cursor eyJvZmZzZXQiOjJ9 continues",
        // A webhook host without a secret path.
        "post to https://hooks.slack.com/services/ once configured",
    ] {
        assert!(
            provider_classes(text).is_empty(),
            "a look-alike was flagged in {text:?}: {:?}",
            provider_classes(text)
        );
        assert_eq!(staged(text), text);
    }
}

#[test]
fn a_webhook_url_and_a_file_link_keep_their_host_and_lose_their_secret() {
    let hook = "https://hooks.slack.com/services/EXAMPLE/NOT/A-REAL-WEBHOOK";
    assert_eq!(staged(hook), "https://hooks.slack.com/services/[REDACTED]");
    let file = "https://files.slack.com/f/x.md?t=xoxe-EXAMPLE-NOT-A-TOKEN";
    assert_eq!(staged(file), "https://files.slack.com/f/x.md?t=[REDACTED]");
}

#[test]
fn the_shared_classes_still_apply_beside_the_provider_set() {
    let text = "creds are AKIAIOSFODNN7EXAMPLE and xoxb-EXAMPLE-NOT-A-TOKEN";
    let outcome = redact(text);
    assert_eq!(
        outcome.classes,
        vec![
            CollectedSecretClassV1::Shared(SecretClassV1::AwsAccessKeyId),
            CollectedSecretClassV1::Provider(ProviderSecretClassV1::SlackToken),
        ]
    );
    assert_eq!(staged(text), "creds are [REDACTED] and [REDACTED]");
}

#[test]
fn a_private_key_block_withholds_a_text_that_also_carries_provider_shapes() {
    let text = "xoxb-EXAMPLE-NOT-A-TOKEN\n-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----";
    let outcome = redact(text);
    assert!(matches!(
        outcome.disposition,
        RedactionDispositionV1::Withhold {
            class: CollectedSecretClassV1::Shared(SecretClassV1::PrivateKeyBlock)
        }
    ));
    assert!(outcome.classes.contains(&CollectedSecretClassV1::Provider(
        ProviderSecretClassV1::SlackToken
    )));
}

#[test]
fn a_match_that_remains_after_replacement_withholds_every_class() {
    // The re-scan is the last word: hand the replace step findings that miss
    // the credential (here, a range over the word before it) and the
    // credential that remains must withhold the text, class by class.
    for (class, credential) in provider_placeholders() {
        let text = format!("before {credential} after");
        let missed = [CollectedSecretFindingV1 {
            class: CollectedSecretClassV1::Provider(class),
            byte_start: 0,
            byte_end: "before".len(),
        }];
        let outcome = replace_and_verify(&text, &missed, Vec::new());
        assert!(
            matches!(outcome.disposition, RedactionDispositionV1::Withhold { .. }),
            "a remaining {} was staged",
            class.as_str()
        );
    }
}

#[test]
fn a_redacted_text_is_a_fixed_point() {
    for (_, credential) in provider_placeholders() {
        let once = staged(&format!("key {credential}"));
        assert!(scan_secrets(&once).is_empty());
        assert_eq!(staged(&once), once);
    }
}

#[test]
fn classes_and_counts_are_metadata_only() {
    let slack = "xoxb-EXAMPLE-NOT-A-TOKEN";
    let linear = "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL";
    let outcome = redact(&format!("{slack} and {linear} and {STRIPE_PLACEHOLDER}"));
    assert_eq!(outcome.redacted_ranges, 3);
    let labels: Vec<&str> = outcome.classes.iter().map(|class| class.as_str()).collect();
    assert_eq!(labels, vec!["slack_token", "linear_api_key", "stripe_key"]);
    let debug = format!("{:?}", outcome.disposition);
    assert!(!debug.contains("REDACTED") && !debug.contains(slack));
    assert_eq!(
        serde_json::to_string(&outcome.classes).unwrap(),
        r#"["slack_token","linear_api_key","stripe_key"]"#
    );
}

#[test]
fn every_provider_class_has_a_distinct_stable_label() {
    let mut labels: Vec<&str> = ProviderSecretClassV1::ALL
        .iter()
        .map(|class| class.as_str())
        .collect();
    labels.sort_unstable();
    let count = labels.len();
    labels.dedup();
    assert_eq!(labels.len(), count);
}
