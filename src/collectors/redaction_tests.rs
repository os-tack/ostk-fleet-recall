//! The collector redactor: every provider class positive, negative, and
//! replaced; the shared classes still apply; a residual withholds.

use super::*;
use crate::collectors::test_support::redactor;

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

/// One positive credential per Slack class: an obvious placeholder in the
/// detector's shape, never a realistic token.
fn slack_positives() -> Vec<(ProviderSecretClassV1, &'static str)> {
    vec![
        (
            ProviderSecretClassV1::SlackToken,
            "xoxb-EXAMPLE-NOT-A-TOKEN",
        ),
        (
            ProviderSecretClassV1::SlackToken,
            "xoxp-EXAMPLE-NOT-A-TOKEN",
        ),
        (
            ProviderSecretClassV1::SlackAppToken,
            "xapp-EXAMPLE-NOT-A-TOKEN",
        ),
        (
            ProviderSecretClassV1::SlackWebhookUrl,
            "https://hooks.slack.com/services/EXAMPLE/NOT/A-REAL-WEBHOOK",
        ),
        (
            ProviderSecretClassV1::SlackFileToken,
            "https://files.slack.com/f/x.md?t=xoxe-EXAMPLE-NOT-A-TOKEN",
        ),
        (
            ProviderSecretClassV1::SlackToken,
            "xoxc-EXAMPLE-NOT-A-TOKEN",
        ),
        (
            ProviderSecretClassV1::SlackToken,
            "xoxd-EXAMPLE%2FNOT%2FA%2FCOOKIE%3D",
        ),
    ]
}

/// One positive credential per provider class: an obvious placeholder in the
/// detector's shape, never a realistic token.
fn positives() -> Vec<(ProviderSecretClassV1, &'static str)> {
    let mut positives = slack_positives();
    positives.extend([
        (
            ProviderSecretClassV1::LinearApiKey,
            "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL",
        ),
        (
            ProviderSecretClassV1::LinearOauthToken,
            "lin_oauth_EXAMPLENOTAREALKEYEXAMPLE",
        ),
        (
            ProviderSecretClassV1::LinearWebhookSecret,
            "lin_wh_EXAMPLENOTAREALKEYEXAMPLENOTAREAL",
        ),
        (
            ProviderSecretClassV1::GranolaApiKey,
            "grn_EXAMPLE_NOT_A_KEY",
        ),
        (
            ProviderSecretClassV1::WebhookSigningSecret,
            "whsec_EXAMPLENOTASECRET",
        ),
        (
            ProviderSecretClassV1::GithubToken,
            "ghp_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL",
        ),
        (
            ProviderSecretClassV1::GithubToken,
            "ghs_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL",
        ),
        (
            ProviderSecretClassV1::GithubToken,
            "github_pat_EXAMPLE_NOT_A_REAL_TOKEN_EXAMPLE",
        ),
        (
            ProviderSecretClassV1::GoogleApiKey,
            "AIzaEXAMPLE_NOT_A_REAL_KEY_EXAMPLE_NOT",
        ),
        (
            ProviderSecretClassV1::AnthropicApiKey,
            "sk-ant-EXAMPLE-NOT-A-REAL-KEY",
        ),
        (
            ProviderSecretClassV1::OpenaiApiKey,
            "sk-proj-EXAMPLE-NOT-A-REAL-KEY",
        ),
        // The bare `sk-` shape needs upper case, lower case, and a digit.
        (
            ProviderSecretClassV1::OpenaiApiKey,
            "sk-EXAMPLEnotArealKEY0000",
        ),
        (
            ProviderSecretClassV1::JsonWebToken,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.EXAMPLE-NOT-A-SIGNATURE",
        ),
    ]);
    positives
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
            !redacted.contains(credential),
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
        "lin_wh_ is the webhook secret prefix, lin_wh_short is not one",
        "session tokens start xoxc- or xoxd- and xoxd-short is not one",
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
    let hook = "https://hooks.slack.com/services/EXAMPLE/NOT/A-REAL-WEBHOOK";
    assert_eq!(staged(hook), "https://hooks.slack.com/services/[REDACTED]");
    let file = "https://files.slack.com/f/x.md?t=xoxe-EXAMPLE-NOT-A-TOKEN";
    assert_eq!(staged(file), "https://files.slack.com/f/x.md?t=[REDACTED]");
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
    let slack = "xoxb-EXAMPLE-NOT-A-TOKEN";
    let linear = "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL";
    let outcome = redactor().redact(&format!("{slack} and {linear}"));
    assert_eq!(outcome.redacted_ranges, 2);
    let labels: Vec<&str> = outcome.classes.iter().map(|class| class.as_str()).collect();
    assert_eq!(labels, vec!["slack_token", "linear_api_key"]);
    let debug = format!("{:?}", outcome.disposition);
    assert!(!debug.contains("REDACTED") && !debug.contains(slack));
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
