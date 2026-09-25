//! The collector redactor: every provider class positive, negative, and
//! replaced; the shared classes still apply; a residual withholds.

use super::*;
use crate::collectors::test_support::{fake_credential, joined, redactor};

fn provider_classes(text: &str) -> Vec<ProviderSecretClassV1> {
    redactor()
        .redact(text)
        .classes
        .into_iter()
        .filter_map(|class| match class {
            CollectedSecretClassV1::Provider(class) => Some(class),
            CollectedSecretClassV1::Shared(_) => None,
        })
        .collect()
}

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

/// One positive credential per provider class, built at runtime.
fn positives() -> Vec<(ProviderSecretClassV1, String)> {
    vec![
        (
            ProviderSecretClassV1::SlackToken,
            fake_credential(&joined(&["xo", "xb-"]), 40),
        ),
        (
            ProviderSecretClassV1::SlackToken,
            fake_credential(&joined(&["xo", "xp-"]), 40),
        ),
        (
            ProviderSecretClassV1::SlackAppToken,
            fake_credential(&joined(&["xa", "pp-"]), 40),
        ),
        (
            ProviderSecretClassV1::SlackWebhookUrl,
            joined(&[
                "https://hooks.slack",
                ".com/services/",
                &fake_credential("T0/B0/", 24),
            ]),
        ),
        (
            ProviderSecretClassV1::SlackFileToken,
            joined(&[
                "https://files.slack.com/f/x.md?t=",
                &fake_credential(&joined(&["xo", "xe-"]), 30),
            ]),
        ),
        (
            ProviderSecretClassV1::LinearApiKey,
            fake_credential(&joined(&["lin", "_api_"]), 40),
        ),
        (
            ProviderSecretClassV1::LinearOauthToken,
            fake_credential(&joined(&["lin", "_oauth_"]), 40),
        ),
        (
            ProviderSecretClassV1::GranolaApiKey,
            fake_credential(&joined(&["gr", "n_"]), 32),
        ),
        (
            ProviderSecretClassV1::WebhookSigningSecret,
            fake_credential(&joined(&["wh", "sec_"]), 44),
        ),
        (
            ProviderSecretClassV1::GithubToken,
            fake_credential(&joined(&["gh", "p_"]), 36),
        ),
        (
            ProviderSecretClassV1::GithubToken,
            fake_credential(&joined(&["gh", "s_"]), 36),
        ),
        (
            ProviderSecretClassV1::GithubToken,
            fake_credential(&joined(&["github", "_pat_"]), 60),
        ),
        (
            ProviderSecretClassV1::GoogleApiKey,
            fake_credential(&joined(&["AI", "za"]), 35),
        ),
        (
            ProviderSecretClassV1::AnthropicApiKey,
            fake_credential(&joined(&["sk-", "ant-"]), 60),
        ),
        (
            ProviderSecretClassV1::OpenaiApiKey,
            fake_credential(&joined(&["sk-", "proj-"]), 60),
        ),
        (
            ProviderSecretClassV1::OpenaiApiKey,
            fake_credential("sk-", 48),
        ),
        (
            ProviderSecretClassV1::JsonWebToken,
            joined(&[
                "eyJhbGciOiJIUzI1NiJ9",
                ".",
                "eyJzdWIiOiJib2IifQ",
                ".",
                &fake_credential("s", 30),
            ]),
        ),
    ]
}

#[test]
fn every_provider_class_is_detected_and_replaced() {
    for (class, credential) in positives() {
        let text = format!("before {credential} after");
        assert!(
            provider_classes(&text).contains(&class),
            "{} was not detected in a planted credential",
            class.as_str()
        );
        let redacted = staged(&text);
        assert!(
            !redacted.contains(&credential),
            "{} survived redaction",
            class.as_str()
        );
        assert!(redacted.starts_with("before ") && redacted.ends_with(" after"));
        assert!(redacted.contains(REDACTION_PLACEHOLDER));
    }
}

#[test]
fn look_alikes_are_not_findings() {
    for text in [
        // Prefixes alone, or followed by too little to be a credential.
        "tokens look like xoxb-... in the docs",
        "the xapp- prefix",
        "lin_api_ is the key prefix",
        "grn_short",
        "whsec_ is a prefix",
        "ghp_short and github_pat_short",
        "AIzaShort",
        "sk-ant-short",
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
    let hook = joined(&[
        "https://hooks.slack",
        ".com/services/",
        &fake_credential("T0/B0/", 24),
    ]);
    assert_eq!(staged(&hook), "https://hooks.slack.com/services/[REDACTED]");
    let file_token = fake_credential(&joined(&["xo", "xe-"]), 30);
    let file = format!("https://files.slack.com/f/x.md?t={file_token}");
    assert_eq!(staged(&file), "https://files.slack.com/f/x.md?t=[REDACTED]");
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
    let text = joined(&[
        "-----BEGIN RSA ",
        "PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
    ]);
    let outcome = redactor().redact(&text);
    assert!(matches!(
        outcome.disposition,
        CollectorDispositionV1::Withhold {
            class: CollectedSecretClassV1::Shared(SecretClassV1::PrivateKeyBlock)
        }
    ));
}

#[test]
fn a_match_that_remains_after_replacement_withholds_every_class() {
    // The re-scan is the last word: hand the replace step findings that miss
    // the credential (here, a range over the word before it) and the
    // credential that remains must withhold the text, class by class.
    for (class, credential) in positives() {
        let text = format!("before {credential} after");
        let missed = [CollectedSecretFindingV1 {
            class: CollectedSecretClassV1::Provider(class),
            byte_start: 0,
            byte_end: "before".len(),
        }];
        let outcome = replace_and_verify(&text, &missed, Vec::new());
        assert!(
            matches!(outcome.disposition, CollectorDispositionV1::Withhold { .. }),
            "a remaining {} was staged",
            class.as_str()
        );
    }
}

#[test]
fn a_redacted_text_is_a_fixed_point() {
    for (_, credential) in positives() {
        let once = staged(&format!("key {credential}"));
        assert!(scan_collected_secrets(&once).is_empty());
        assert_eq!(staged(&once), once);
    }
}

#[test]
fn classes_and_counts_are_metadata_only() {
    let slack = fake_credential(&joined(&["xo", "xb-"]), 40);
    let linear = fake_credential(&joined(&["lin", "_api_"]), 40);
    let outcome = redactor().redact(&format!("{slack} and {linear}"));
    assert_eq!(outcome.redacted_ranges, 2);
    let labels: Vec<&str> = outcome.classes.iter().map(|class| class.as_str()).collect();
    assert_eq!(labels, vec!["slack_token", "linear_api_key"]);
    let debug = format!("{:?}", outcome.disposition);
    assert!(!debug.contains("REDACTED") && !debug.contains(&slack));
}

#[test]
fn the_redactor_requires_the_active_packages_guarantee() {
    let redactor = redactor();
    assert_eq!(
        redactor.profile_version(),
        COLLECTOR_REDACTION_PROFILE_VERSION
    );
    assert_eq!(
        redactor.guarantee().policy_id().as_str(),
        "redaction.default"
    );
}
