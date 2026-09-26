//! Shared unit-test fixtures: a generation-3 head bound to one collected
//! connector, the redactor under it, and the placeholder credentials every
//! redaction test plants.
//!
//! # The placeholder rule
//!
//! A redaction test needs a credential in each detector's shape, and a
//! credential-shaped literal in a public repository is exactly what GitHub's
//! push protection blocks. An earlier attempt at the ingress redaction fix
//! was blocked because its Stripe literal was a real-looking key: GitHub's
//! pattern needs only 24 alphanumerics after `sk_live_`. Every placeholder
//! therefore follows one rule, and [`PLACEHOLDERS`] proves it:
//!
//! 1. the REAL prefix, so the crate's detector fires;
//! 2. the body contains `EXAMPLE` or `NOT-A` (or `NOTA`), so a reader knows
//!    at sight it is not a token;
//! 3. the body is SHORTER than GitHub's documented minimum for that provider,
//!    or contains a byte class GitHub's pattern rejects (a `-` in an
//!    alphanumeric body, letters where digits are required), so push
//!    protection never matches it;
//! 4. it is one literal, never assembled from fragments at runtime, so a
//!    scanner reading the source sees the same string a test plants.
//!
//! `AKIAIOSFODNN7EXAMPLE` is the one documented exception: it is AWS's own
//! published example access key, and GitHub's pattern (`AKIA` + 16) matches
//! it by construction.

use crate::evidence_ledger::{
    ActiveStage4Package, WriterAuthoritySnapshot, WriterAuthorityWitness, partition_algorithm_label,
};
use crate::memory_contracts::bootstrap::BootstrapReceiptV1;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::collected_item::CollectionModeV1;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::registry::RegistryHeadV1;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::redaction::{CollectedSecretClassV1, ProviderSecretClassV1, SecretClassV1};

use super::redaction::CollectorRedactorV1;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn synthetic_head(package_digest: Sha256Digest) -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                b"collected-items-activation",
            ),
            package_digest,
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryActivationStatement,
                b"collected-items-activation-policy",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-09-25T00:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn witness_for(head: &RegistryHeadBindingV1) -> WriterAuthorityWitness {
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let genesis_epoch = receipt.statement.genesis_epoch.clone();
    let scope = receipt.statement.scope;
    let recipe = genesis_epoch.partition_recipe.clone();
    WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
        head_state: "active".to_owned(),
        generation: 3,
        activation_id: head.head.activation_id,
        package_digest: head.head.package_digest,
        activation_policy_digest: head.head.activation_policy_digest,
        log_epoch_id: genesis_epoch.epoch_id().unwrap(),
        partition_recipe_id: recipe.recipe_id.as_str().to_owned(),
        partition_recipe_version: recipe.recipe_version,
        partition_algorithm: partition_algorithm_label(recipe.algorithm).to_owned(),
        partition_seed: recipe.seed,
        log_shard_count: recipe.shard_count,
        head_scope: scope.clone(),
        bootstrap_scope: scope,
        genesis_epoch,
    })
    .expect("the frozen bootstrap receipt must yield a consistent witness")
}

fn bind(package: SemanticallyClosedSuccessorPackage, connector: &str) -> ActiveStage4Package {
    let head = synthetic_head(package.package_digest());
    let witness = witness_for(&head);
    ActiveStage4Package::bind_connector(
        package,
        &ContractId::new(connector).unwrap(),
        head,
        &witness,
    )
    .expect("the package must bind to the head that activated it")
}

/// A generation-3 head bound to the connector `mode` admits under.
pub fn generation_three_active(mode: CollectionModeV1) -> ActiveStage4Package {
    let package = crate::registry_witness::compiled_generation_three_package()
        .expect("the compiled generation-3 package closes");
    bind((*package).clone(), mode.connector_schema_id())
}

/// A generation-2 head bound to its git connector: it carries no collected
/// connector at all.
pub fn generation_two_git_active() -> ActiveStage4Package {
    let package = crate::registry_witness::compiled_generation_two_package()
        .expect("the compiled generation-2 package closes");
    bind(
        (*package).clone(),
        crate::memory_contracts::generation2_registry::GIT_CONNECTOR.connector_schema,
    )
}

/// The redactor under the generation-3 head's own redaction guarantee.
pub fn redactor() -> CollectorRedactorV1 {
    CollectorRedactorV1::from_active_package(&generation_three_active(CollectionModeV1::Pull))
        .expect("generation 3 carries generation 1's redaction guarantee")
}

// ---------------------------------------------------------------------------
// Placeholder credentials and the push-protection proof.
// ---------------------------------------------------------------------------

/// AWS's published example access key id: the one placeholder GitHub's
/// pattern matches by construction, and the one push protection lets through.
pub const AWS_DOCUMENTED_EXAMPLE_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// The Stripe placeholder: a 16-character body, eight short of GitHub's
/// 24-alphanumeric minimum and exactly the crate's `min_body`.
pub const STRIPE_PLACEHOLDER: &str = "sk_live_EXAMPLENOTAKEY00";

/// A hand-written encoding of one push-protection pattern GitHub documents:
/// whether the text holds a token of that documented shape.
pub type PushProtectionPattern = fn(&str) -> bool;

/// One planted credential: the class it must be detected as, the literal, and
/// the hand-written encoding of the push-protection pattern GitHub documents
/// for that provider (`false` for every literal but the documented exception).
pub struct Placeholder {
    pub class: CollectedSecretClassV1,
    pub literal: &'static str,
    pub push_protected: PushProtectionPattern,
}

const fn shared(class: SecretClassV1) -> CollectedSecretClassV1 {
    CollectedSecretClassV1::Shared(class)
}

const fn provider(class: ProviderSecretClassV1) -> CollectedSecretClassV1 {
    CollectedSecretClassV1::Provider(class)
}

/// One placeholder per detector shape, several for the shapes with more than
/// one prefix. Every redaction test draws its credentials from here.
pub const PLACEHOLDERS: &[Placeholder] = &[
    // Shared shapes.
    Placeholder {
        class: shared(SecretClassV1::PrivateKeyBlock),
        literal: "-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----",
        push_protected: pem_private_key,
    },
    Placeholder {
        class: shared(SecretClassV1::AwsAccessKeyId),
        literal: AWS_DOCUMENTED_EXAMPLE_KEY,
        push_protected: aws_access_key_id,
    },
    Placeholder {
        class: shared(SecretClassV1::BearerToken),
        literal: "Authorization: Bearer EXAMPLE-NOT-A-TOKEN",
        push_protected: http_authorization,
    },
    Placeholder {
        class: shared(SecretClassV1::ApiKeyAssignment),
        literal: "api_key=EXAMPLE-NOT-A-KEY",
        push_protected: never_documented,
    },
    Placeholder {
        class: shared(SecretClassV1::PasswordAssignment),
        literal: "password=EXAMPLE-NOT-A-PASSWORD",
        push_protected: never_documented,
    },
    Placeholder {
        class: shared(SecretClassV1::UrlEmbeddedCredential),
        literal: "postgres://example:NOT-A-PASSWORD@db.example.test/fleet",
        push_protected: never_documented,
    },
    // Slack.
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackToken),
        literal: "xoxb-EXAMPLE-NOT-A-TOKEN",
        push_protected: slack_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackToken),
        literal: "xoxp-EXAMPLE-NOT-A-TOKEN",
        push_protected: slack_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackToken),
        literal: "xoxc-EXAMPLE-NOT-A-TOKEN",
        push_protected: slack_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackToken),
        literal: "xoxd-EXAMPLE%2FNOT%2FA%2FCOOKIE%3D",
        push_protected: slack_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackAppToken),
        literal: "xapp-EXAMPLE-NOT-A-TOKEN",
        push_protected: slack_app_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackWebhookUrl),
        literal: "https://hooks.slack.com/services/EXAMPLE/NOT/A-REAL-WEBHOOK",
        push_protected: slack_incoming_webhook,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::SlackFileToken),
        literal: "https://files.slack.com/f/x.md?t=xoxe-EXAMPLE-NOT-A-TOKEN",
        push_protected: slack_token,
    },
    // Linear.
    Placeholder {
        class: provider(ProviderSecretClassV1::LinearApiKey),
        literal: "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL",
        push_protected: linear_key,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::LinearOauthToken),
        literal: "lin_oauth_EXAMPLENOTAREALKEYEXAMPLE",
        push_protected: linear_key,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::LinearWebhookSecret),
        literal: "lin_wh_EXAMPLENOTAREALKEYEXAMPLENOTAREAL",
        push_protected: linear_key,
    },
    // Granola and webhook signing.
    Placeholder {
        class: provider(ProviderSecretClassV1::GranolaApiKey),
        literal: "grn_EXAMPLE_NOT_A_KEY",
        push_protected: never_documented,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::WebhookSigningSecret),
        literal: "whsec_EXAMPLENOTASECRET",
        push_protected: stripe_webhook_signing,
    },
    // GitHub.
    Placeholder {
        class: provider(ProviderSecretClassV1::GithubToken),
        literal: "ghp_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL",
        push_protected: github_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::GithubToken),
        literal: "ghs_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL",
        push_protected: github_token,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::GithubToken),
        literal: "github_pat_EXAMPLE_NOT_A_REAL_TOKEN_EXAMPLE",
        push_protected: github_fine_grained_token,
    },
    // Google, Anthropic, OpenAI.
    Placeholder {
        class: provider(ProviderSecretClassV1::GoogleApiKey),
        literal: "AIzaEXAMPLE_NOT_A_REAL_KEY_EXAMPLE_NOT",
        push_protected: google_api_key,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::AnthropicApiKey),
        literal: "sk-ant-EXAMPLE-NOT-A-REAL-KEY",
        push_protected: anthropic_api_key,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::OpenaiApiKey),
        literal: "sk-proj-EXAMPLE-NOT-A-REAL-KEY",
        push_protected: openai_api_key,
    },
    // The bare `sk-` shape needs upper case, lower case, and a digit.
    Placeholder {
        class: provider(ProviderSecretClassV1::OpenaiApiKey),
        literal: "sk-EXAMPLEnotArealKEY0000",
        push_protected: openai_api_key,
    },
    // Stripe (profile 3).
    Placeholder {
        class: provider(ProviderSecretClassV1::StripeKey),
        literal: STRIPE_PLACEHOLDER,
        push_protected: stripe_key,
    },
    Placeholder {
        class: provider(ProviderSecretClassV1::StripeKey),
        literal: "rk_test_EXAMPLENOTAKEY00",
        push_protected: stripe_key,
    },
    // A signed JWT: header and payload are JSON objects, the signature is
    // prose.
    Placeholder {
        class: provider(ProviderSecretClassV1::JsonWebToken),
        literal: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.EXAMPLE-NOT-A-SIGNATURE",
        push_protected: never_documented,
    },
];

/// The provider placeholders alone, as `(class, literal)` pairs.
pub fn provider_placeholders() -> Vec<(ProviderSecretClassV1, &'static str)> {
    PLACEHOLDERS
        .iter()
        .filter_map(|placeholder| match placeholder.class {
            CollectedSecretClassV1::Provider(class) => Some((class, placeholder.literal)),
            CollectedSecretClassV1::Shared(_) => None,
        })
        .collect()
}

// --- Hand-written encodings of GitHub's documented push-protection patterns.
//
// Each is a conservative reading of the pattern GitHub publishes for the
// provider (secret scanning "supported patterns"), written as a small scan
// rather than a regex because the crate takes no regex dependency. They are
// deliberately at least as permissive as the documented pattern where the
// documentation leaves a bound open, so a placeholder that passes here has
// margin.

fn alphanumeric_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count()
}

fn digit_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
}

fn base64url_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        .count()
}

fn base64_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .count()
}

/// Every offset at which one of `prefixes` starts.
fn after_prefix<'t>(
    text: &'t str,
    prefixes: &'static [&'static str],
) -> impl Iterator<Item = &'t [u8]> {
    let bytes = text.as_bytes();
    (0..bytes.len()).flat_map(move |index| {
        prefixes
            .iter()
            .filter_map(move |prefix| bytes[index..].strip_prefix(prefix.as_bytes()))
    })
}

/// A shape GitHub documents no push-protection pattern for.
fn never_documented(_text: &str) -> bool {
    false
}

/// `-----BEGIN … PRIVATE KEY-----` with a base64 body of at least 64 bytes
/// before its `-----END`: a real key. A marker around a short placeholder is
/// not one.
fn pem_private_key(text: &str) -> bool {
    let Some(start) = text.find("PRIVATE KEY-----") else {
        return false;
    };
    let body = &text[start + "PRIVATE KEY-----".len()..];
    let body_end = body.find("-----END").unwrap_or(body.len());
    body[..body_end]
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .count()
        >= 64
}

/// `AKIA` + 16 uppercase alphanumerics.
fn aws_access_key_id(text: &str) -> bool {
    after_prefix(text, &["AKIA"]).any(|rest| {
        rest.len() >= 16
            && rest[..16]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

/// `Bearer`/`Basic` followed by a credential of at least 32 token bytes.
fn http_authorization(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    after_prefix(&lower, &["bearer ", "basic "]).any(|rest| {
        rest.iter()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'/' | b'=')
            })
            .count()
            >= 32
    })
}

/// `xox[baprs]-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,34}`, plus the session
/// forms with any digit run after the prefix.
fn slack_token(text: &str) -> bool {
    after_prefix(
        text,
        &[
            "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-", "xoxc-", "xoxd-", "xoxo-",
        ],
    )
    .any(|rest| {
        let first = digit_run(rest);
        if !(10..=13).contains(&first) || rest.get(first) != Some(&b'-') {
            return false;
        }
        let rest = &rest[first + 1..];
        let second = digit_run(rest);
        if !(10..=13).contains(&second) || rest.get(second) != Some(&b'-') {
            return false;
        }
        (24..=34).contains(&alphanumeric_run(&rest[second + 1..]))
    })
}

/// `xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{64}`.
fn slack_app_token(text: &str) -> bool {
    after_prefix(text, &["xapp-"]).any(|rest| {
        let level = digit_run(rest);
        if level == 0 || rest.get(level) != Some(&b'-') {
            return false;
        }
        let rest = &rest[level + 1..];
        let app = alphanumeric_run(rest);
        if app == 0 || rest.get(app) != Some(&b'-') {
            return false;
        }
        let rest = &rest[app + 1..];
        let stamp = digit_run(rest);
        if stamp == 0 || rest.get(stamp) != Some(&b'-') {
            return false;
        }
        rest[stamp + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count()
            >= 64
    })
}

/// `hooks.slack.com/services/T…/B…/[A-Za-z0-9]{24}`.
fn slack_incoming_webhook(text: &str) -> bool {
    after_prefix(text, &["hooks.slack.com/services/"]).any(|rest| {
        let team = alphanumeric_run(rest);
        if !rest.starts_with(b"T") || team < 8 || rest.get(team) != Some(&b'/') {
            return false;
        }
        let rest = &rest[team + 1..];
        let bot = alphanumeric_run(rest);
        if !rest.starts_with(b"B") || bot < 8 || rest.get(bot) != Some(&b'/') {
            return false;
        }
        alphanumeric_run(&rest[bot + 1..]) >= 24
    })
}

/// `lin_api_[A-Za-z0-9]{40}` and `lin_oauth_[A-Za-z0-9]{40}`.
fn linear_key(text: &str) -> bool {
    after_prefix(text, &["lin_api_", "lin_oauth_", "lin_wh_"])
        .any(|rest| alphanumeric_run(rest) >= 40)
}

/// `whsec_[A-Za-z0-9]{32}`.
fn stripe_webhook_signing(text: &str) -> bool {
    after_prefix(text, &["whsec_"]).any(|rest| alphanumeric_run(rest) >= 32)
}

/// `gh[posur]_[A-Za-z0-9]{36}`.
fn github_token(text: &str) -> bool {
    after_prefix(text, &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
        .any(|rest| alphanumeric_run(rest) >= 36)
}

/// `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`.
fn github_fine_grained_token(text: &str) -> bool {
    after_prefix(text, &["github_pat_"]).any(|rest| {
        let id = alphanumeric_run(rest);
        id == 22 && rest.get(id) == Some(&b'_') && alphanumeric_run(&rest[id + 1..]) >= 59
    })
}

/// `AIza[0-9A-Za-z\-_]{35}`.
fn google_api_key(text: &str) -> bool {
    after_prefix(text, &["AIza"]).any(|rest| base64url_run(rest) >= 35)
}

/// `sk-ant-api03-[A-Za-z0-9\-_]{93}AA`.
fn anthropic_api_key(text: &str) -> bool {
    after_prefix(text, &["sk-ant-api03-"]).any(|rest| base64url_run(rest) >= 95)
}

/// `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}` and the `proj-` form.
fn openai_api_key(text: &str) -> bool {
    after_prefix(text, &["sk-", "sk-proj-"]).any(|rest| {
        let run = base64_run(rest);
        run >= 48
            && rest[..run]
                .windows("T3BlbkFJ".len())
                .any(|window| window == b"T3BlbkFJ")
    })
}

/// `(sk|rk)_(live|test)_[A-Za-z0-9]{24,}`.
fn stripe_key(text: &str) -> bool {
    after_prefix(text, &["sk_live_", "sk_test_", "rk_live_", "rk_test_"])
        .any(|rest| alphanumeric_run(rest) >= 24)
}

/// Every pattern above, so a literal is checked against all of them and not
/// only the one written for its own provider.
const PUSH_PROTECTION_PATTERNS: &[(&str, PushProtectionPattern)] = &[
    ("pem_private_key", pem_private_key),
    ("aws_access_key_id", aws_access_key_id),
    ("http_authorization", http_authorization),
    ("slack_token", slack_token),
    ("slack_app_token", slack_app_token),
    ("slack_incoming_webhook", slack_incoming_webhook),
    ("linear_key", linear_key),
    ("stripe_webhook_signing", stripe_webhook_signing),
    ("github_token", github_token),
    ("github_fine_grained_token", github_fine_grained_token),
    ("google_api_key", google_api_key),
    ("anthropic_api_key", anthropic_api_key),
    ("openai_api_key", openai_api_key),
    ("stripe_key", stripe_key),
];

/// The guard against a repeat of the push-protection block: no placeholder
/// in the table matches any hand-encoded GitHub pattern, except AWS's own
/// documented example key.
#[test]
fn no_placeholder_matches_a_push_protection_pattern() {
    for placeholder in PLACEHOLDERS {
        if placeholder.literal == AWS_DOCUMENTED_EXAMPLE_KEY {
            assert!(
                (placeholder.push_protected)(placeholder.literal),
                "the documented exception is expected to match its own pattern"
            );
            continue;
        }
        assert!(
            !(placeholder.push_protected)(placeholder.literal),
            "{} matches its provider's push-protection pattern",
            placeholder.class.as_str()
        );
        for (name, pattern) in PUSH_PROTECTION_PATTERNS {
            assert!(
                !pattern(placeholder.literal),
                "the {} placeholder matches the {name} pattern",
                placeholder.class.as_str()
            );
        }
        assert!(
            placeholder.literal.contains("EXAMPLE") || placeholder.literal.contains("NOT-A"),
            "{} placeholder does not read as a placeholder",
            placeholder.class.as_str()
        );
    }
}

/// The patterns are not vacuous: a token of each documented shape, built
/// here from runs of a repeated byte (never a literal), does match.
#[test]
fn the_push_protection_patterns_match_their_documented_shapes() {
    let run = |byte: char, count: usize| byte.to_string().repeat(count);
    let cases: Vec<(&str, String)> = vec![
        (
            "pem_private_key",
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
                run('M', 64)
            ),
        ),
        ("aws_access_key_id", format!("AKIA{}", run('A', 16))),
        ("http_authorization", format!("Bearer {}", run('a', 32))),
        (
            "slack_token",
            format!("xoxb-{}-{}-{}", run('1', 10), run('2', 12), run('a', 24)),
        ),
        (
            "slack_app_token",
            format!("xapp-1-{}-{}-{}", run('A', 9), run('3', 13), run('f', 64)),
        ),
        (
            "slack_incoming_webhook",
            format!(
                "https://hooks.slack.com/services/T{}/B{}/{}",
                run('0', 8),
                run('0', 8),
                run('x', 24)
            ),
        ),
        ("linear_key", format!("lin_api_{}", run('a', 40))),
        ("stripe_webhook_signing", format!("whsec_{}", run('a', 32))),
        ("github_token", format!("ghp_{}", run('a', 36))),
        (
            "github_fine_grained_token",
            format!("github_pat_{}_{}", run('a', 22), run('b', 59)),
        ),
        ("google_api_key", format!("AIza{}", run('a', 35))),
        (
            "anthropic_api_key",
            format!("sk-ant-api03-{}AA", run('a', 93)),
        ),
        (
            "openai_api_key",
            format!("sk-{}T3BlbkFJ{}", run('a', 20), run('b', 20)),
        ),
        ("stripe_key", format!("sk_live_{}", run('a', 24))),
    ];
    for (name, token) in &cases {
        let (_, pattern) = PUSH_PROTECTION_PATTERNS
            .iter()
            .find(|(candidate, _)| candidate == name)
            .unwrap_or_else(|| panic!("no pattern named {name}"));
        assert!(pattern(token), "{name} does not match its documented shape");
    }
    assert_eq!(cases.len(), PUSH_PROTECTION_PATTERNS.len());
}

/// Every placeholder is a positive for the crate: the placeholder rule keeps
/// push protection out without weakening the detectors.
#[test]
fn every_placeholder_is_detected_by_the_crate() {
    for placeholder in PLACEHOLDERS {
        // The classes a redaction reports come from the unmerged findings, so
        // a file-link token is reported even though its range merges into the
        // Slack token range it also is.
        let outcome = crate::redaction::redact(placeholder.literal);
        assert!(
            outcome.classes.contains(&placeholder.class),
            "{} placeholder is not detected: {:?}",
            placeholder.class.as_str(),
            outcome.classes
        );
        if placeholder.class.is_redactable() {
            let staged = outcome.staged_text().unwrap_or_else(|| {
                panic!("{} placeholder was withheld", placeholder.class.as_str())
            });
            assert!(
                staged.contains(crate::redaction::REDACTION_PLACEHOLDER),
                "{} placeholder was not replaced",
                placeholder.class.as_str()
            );
        }
    }
    // And the table covers every provider class, so a new class cannot ship
    // without a placeholder that obeys the rule.
    for class in ProviderSecretClassV1::ALL {
        assert!(
            provider_placeholders()
                .iter()
                .any(|(planted, _)| *planted == class),
            "{} has no placeholder",
            class.as_str()
        );
    }
}
