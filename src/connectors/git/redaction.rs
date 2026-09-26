//! Redacting a git fact's text fields at ingress, before an ingress candidate
//! is built (EVID-05, PRED-03).
//!
//! A commit message, an author or committer name or email, and a tree-entry
//! path are verbatim provider bytes carried as [`HexBytes`]. Carried that way
//! they are invisible to a scanner reading the fact, and visible the moment
//! the lexical projector decodes them for search; the trial found Slack,
//! GitHub, Linear, Granola, and Stripe tokens quoted in commit messages
//! stored raw and served. [`redact_git_fact`] runs the crate's one redactor
//! ([`crate::redaction`], under the active package's
//! [`RedactionGuaranteeV1`]) over each of those fields and returns the fact
//! that admission will render, so the governed body carries the placeholder
//! and not the token.
//!
//! Per field:
//!
//! * a UTF-8 field is redacted like any text: a finding's range is replaced
//!   with [`REDACTION_PLACEHOLDER`]; a text the redactor withholds (a private
//!   key block, or a residual after replacement) becomes the placeholder
//!   ALONE, because a field that cannot be made safe carries no provider text
//!   at all rather than a partial redaction;
//! * a field that is not UTF-8 is scanned through a lossy decoding; a finding
//!   anywhere in it makes the whole field the placeholder alone, since no
//!   byte range of undecodable text can be trusted to be the credential's
//!   extent; no finding leaves the bytes exactly as they were;
//! * a replaced field that would exceed its declared bound (the placeholder
//!   can be longer than what it replaces) becomes the placeholder alone.
//!
//! The fact is never dropped: a commit is still evidence that a commit was
//! made. What changes is its rendering, and with it the content digest and
//! the accepted-event identity of a fact whose text was redacted. A fact
//! admitted before this redactor ran keeps its raw body at rest; when the
//! worker re-walks it (a ref move re-walks from the root) it now re-presents
//! with a different payload under the same source-fact identity and the
//! ledger quarantines it as a preimage disagreement — a one-time, visible
//! `quarantined` count, not a silent rewrite (ADR 0006 D9).

use crate::memory_contracts::common::HexBytes;
use crate::redaction::{
    CollectedSecretClassV1, REDACTION_PLACEHOLDER, RedactionDispositionV1, RedactionGuaranteeV1,
    scan_secrets,
};

use super::error::GitFactResult;
use super::fact::{
    GitBlobSourceFactV1, GitCommitFactV1, GitFactV1, GitIdentityV1, MAX_GIT_IDENTITY_BYTES,
    MAX_GIT_MESSAGE_BYTES, MAX_GIT_PATH_BYTES,
};

/// What redacting one fact did. Metadata only: never the matched bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitFactRedactionV1 {
    /// Fields in which secret-shaped ranges were replaced and the rest of the
    /// text kept.
    pub fields_redacted: u32,
    /// Fields that became the placeholder alone: withheld by the redactor,
    /// not decodable around a finding, or over their bound after replacement.
    pub fields_withheld: u32,
    /// Classes detected across the fact's fields, sorted and deduplicated.
    pub classes: Vec<CollectedSecretClassV1>,
}

impl GitFactRedactionV1 {
    /// Whether any field of the fact changed.
    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.fields_redacted > 0 || self.fields_withheld > 0
    }

    fn note(&mut self, classes: &[CollectedSecretClassV1]) {
        for class in classes {
            if !self.classes.contains(class) {
                self.classes.push(*class);
            }
        }
    }
}

/// One field's outcome: the bytes to store when they changed.
enum FieldOutcome {
    Clean,
    Replaced(HexBytes),
    Withheld(HexBytes),
}

fn placeholder_alone(bound: usize) -> GitFactResult<HexBytes> {
    Ok(HexBytes::new_bounded(
        REDACTION_PLACEHOLDER.as_bytes().to_vec(),
        bound,
    )?)
}

/// Redact one byte field under `bound`.
fn redact_field(
    guarantee: &RedactionGuaranteeV1,
    field: &HexBytes,
    bound: usize,
    report: &mut GitFactRedactionV1,
) -> GitFactResult<FieldOutcome> {
    let bytes = field.as_bytes();
    let Ok(text) = std::str::from_utf8(bytes) else {
        // Undecodable provider bytes: a finding in the lossy decoding is
        // enough to withhold the field, and only an exact absence of one
        // leaves the bytes as they are.
        let lossy = String::from_utf8_lossy(bytes);
        let findings = scan_secrets(&lossy);
        if findings.is_empty() {
            return Ok(FieldOutcome::Clean);
        }
        let classes: Vec<CollectedSecretClassV1> =
            findings.iter().map(|finding| finding.class).collect();
        report.note(&classes);
        return Ok(FieldOutcome::Withheld(placeholder_alone(bound)?));
    };
    let outcome = guarantee.apply(text);
    report.note(&outcome.classes);
    match outcome.disposition {
        RedactionDispositionV1::Stage { .. } if outcome.redacted_ranges == 0 => {
            Ok(FieldOutcome::Clean)
        }
        RedactionDispositionV1::Stage { text } => {
            match HexBytes::new_bounded(text.into_bytes(), bound) {
                Ok(replaced) => Ok(FieldOutcome::Replaced(replaced)),
                // The placeholder is longer than some of what it replaces; a
                // field that no longer fits its bound is withheld rather than
                // truncated, because a truncated rendering could end inside
                // the next credential.
                Err(_) => Ok(FieldOutcome::Withheld(placeholder_alone(bound)?)),
            }
        }
        RedactionDispositionV1::Withhold { .. } => {
            Ok(FieldOutcome::Withheld(placeholder_alone(bound)?))
        }
    }
}

/// Apply one field outcome in place, counting it.
fn apply(field: &mut HexBytes, outcome: FieldOutcome, report: &mut GitFactRedactionV1) {
    match outcome {
        FieldOutcome::Clean => {}
        FieldOutcome::Replaced(replaced) => {
            *field = replaced;
            report.fields_redacted = report.fields_redacted.saturating_add(1);
        }
        FieldOutcome::Withheld(placeholder) => {
            *field = placeholder;
            report.fields_withheld = report.fields_withheld.saturating_add(1);
        }
    }
}

fn redact_identity(
    guarantee: &RedactionGuaranteeV1,
    identity: &mut GitIdentityV1,
    report: &mut GitFactRedactionV1,
) -> GitFactResult<()> {
    let name = redact_field(guarantee, &identity.name, MAX_GIT_IDENTITY_BYTES, report)?;
    apply(&mut identity.name, name, report);
    let email = redact_field(guarantee, &identity.email, MAX_GIT_IDENTITY_BYTES, report)?;
    apply(&mut identity.email, email, report);
    Ok(())
}

fn redact_commit(
    guarantee: &RedactionGuaranteeV1,
    commit: &mut GitCommitFactV1,
    report: &mut GitFactRedactionV1,
) -> GitFactResult<()> {
    let message = redact_field(guarantee, &commit.message, MAX_GIT_MESSAGE_BYTES, report)?;
    apply(&mut commit.message, message, report);
    redact_identity(guarantee, &mut commit.author, report)?;
    redact_identity(guarantee, &mut commit.committer, report)
}

fn redact_blob(
    guarantee: &RedactionGuaranteeV1,
    blob: &mut GitBlobSourceFactV1,
    report: &mut GitFactRedactionV1,
) -> GitFactResult<()> {
    let path = redact_field(guarantee, &blob.path, MAX_GIT_PATH_BYTES, report)?;
    apply(&mut blob.path, path, report);
    Ok(())
}

/// The fact admission will render: every text field redacted under
/// `guarantee`, re-validated, with what changed.
///
/// A ref observation carries no provider text and comes back unchanged.
///
/// # Errors
///
/// [`super::GitFactError`] when the redacted fact no longer validates, which
/// the bound handling above makes unreachable for a fact that validated
/// before; it is an error rather than a fallback so a rendering the schema
/// refuses is never admitted.
pub fn redact_git_fact(
    guarantee: &RedactionGuaranteeV1,
    fact: &GitFactV1,
) -> GitFactResult<(GitFactV1, GitFactRedactionV1)> {
    let mut report = GitFactRedactionV1::default();
    let mut redacted = fact.clone();
    match &mut redacted {
        GitFactV1::Commit(commit) => redact_commit(guarantee, commit, &mut report)?,
        GitFactV1::BlobSource(blob) => redact_blob(guarantee, blob, &mut report)?,
        GitFactV1::RefObservation(_) => {}
    }
    report.classes.sort_unstable();
    if report.redacted() {
        redacted.validate()?;
    } else {
        debug_assert_eq!(&redacted, fact, "a clean fact is returned byte-identical");
    }
    Ok((redacted, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::test_support::{PLACEHOLDERS, generation_two_git_active};
    use crate::connectors::git::fact::{
        GIT_FACT_SCHEMA_VERSION, GitAncestryClaimV1, GitFileModeV1, GitObjectId, GitRefName,
        GitRefObservationFactV1, GitRepositoryIdV1,
    };
    use crate::connectors::git::ingress::{GitConnectorBindingV1, GitIngressClocksV1};
    use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, ContractId};
    use crate::redaction::{ProviderSecretClassV1, SecretClassV1};

    fn guarantee() -> RedactionGuaranteeV1 {
        RedactionGuaranteeV1::from_active_package(&generation_two_git_active())
            .expect("generation 2 carries the redaction guarantee")
    }

    fn repository() -> GitRepositoryIdV1 {
        GitRepositoryIdV1::from_trusted_config(ContractId::new("git.repo.fixture").unwrap(), 7)
            .unwrap()
    }

    fn oid(seed: u8) -> GitObjectId {
        GitObjectId::parse_hex(&hex::encode([seed; 20])).unwrap()
    }

    fn stamp() -> CanonicalTimestamp {
        CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap()
    }

    fn identity(name: &[u8], email: &[u8]) -> GitIdentityV1 {
        GitIdentityV1 {
            name: HexBytes::new(name.to_vec()).unwrap(),
            email: HexBytes::new(email.to_vec()).unwrap(),
            at: stamp(),
            utc_offset_minutes: 0,
        }
    }

    fn commit(message: &[u8], author: GitIdentityV1) -> GitFactV1 {
        GitFactV1::Commit(GitCommitFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            commit_id: oid(0x11),
            tree_id: oid(0x22),
            parents: vec![oid(0x33)],
            author: author.clone(),
            committer: author,
            message: HexBytes::new_bounded(message.to_vec(), MAX_GIT_MESSAGE_BYTES).unwrap(),
            ancestry: GitAncestryClaimV1::RecordedParents,
            declared_links: Vec::new(),
        })
    }

    fn blob(path: &[u8]) -> GitFactV1 {
        GitFactV1::BlobSource(GitBlobSourceFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            commit_id: oid(0x11),
            tree_id: oid(0x22),
            path: HexBytes::new(path.to_vec()).unwrap(),
            mode: GitFileModeV1::Regular,
            blob_id: oid(0x44),
            byte_length: CanonicalDecimal::parse("3").unwrap(),
            committed_at: stamp(),
        })
    }

    fn ada() -> GitIdentityV1 {
        identity(b"Ada Lovelace", b"ada@example.test")
    }

    fn message_of(fact: &GitFactV1) -> &[u8] {
        match fact {
            GitFactV1::Commit(commit) => commit.message.as_bytes(),
            _ => panic!("not a commit"),
        }
    }

    fn redact(fact: &GitFactV1) -> (GitFactV1, GitFactRedactionV1) {
        redact_git_fact(&guarantee(), fact).unwrap()
    }

    #[test]
    fn a_clean_commit_comes_back_byte_identical_with_nothing_reported() {
        let fact = commit(b"fix(recall): fold the query\n", ada());
        let (redacted, report) = redact(&fact);
        assert_eq!(redacted, fact);
        assert_eq!(report, GitFactRedactionV1::default());
        assert!(!report.redacted());
    }

    #[test]
    fn a_provider_token_in_the_message_is_replaced_and_the_commit_id_is_stable() {
        let fact = commit(
            b"ops: rotate xoxb-EXAMPLE-NOT-A-TOKEN before the release\n",
            ada(),
        );
        let (redacted, report) = redact(&fact);
        assert_eq!(
            message_of(&redacted),
            b"ops: rotate [REDACTED] before the release\n"
        );
        assert_eq!(report.fields_redacted, 1);
        assert_eq!(report.fields_withheld, 0);
        assert_eq!(
            report.classes,
            vec![CollectedSecretClassV1::Provider(
                ProviderSecretClassV1::SlackToken
            )]
        );
        // The revision IS the object id: redaction changes the rendering, not
        // which commit this is.
        assert_eq!(
            redacted.immutable_revision().unwrap(),
            fact.immutable_revision().unwrap()
        );
        assert_eq!(
            redacted.provider_object_id().unwrap(),
            fact.provider_object_id().unwrap()
        );
        assert_ne!(
            redacted.canonical_payload().unwrap(),
            fact.canonical_payload().unwrap(),
            "the governed rendering differs, which is what the ledger sees"
        );
    }

    #[test]
    fn every_redactable_placeholder_is_replaced_in_a_message() {
        for placeholder in PLACEHOLDERS
            .iter()
            .filter(|placeholder| placeholder.class.is_redactable())
        {
            let message = format!("rotate {} before merge\n", placeholder.literal);
            let (redacted, report) = redact(&commit(message.as_bytes(), ada()));
            let rendered = String::from_utf8(message_of(&redacted).to_vec()).unwrap();
            assert!(
                !rendered.contains(placeholder.literal),
                "{} survived in a commit message",
                placeholder.class.as_str()
            );
            assert!(rendered.contains(REDACTION_PLACEHOLDER));
            assert!(
                report.classes.contains(&placeholder.class),
                "{} not reported",
                placeholder.class.as_str()
            );
            assert!(report.redacted());
            redacted.validate().unwrap();
        }
    }

    #[test]
    fn an_author_name_and_email_are_redacted_too() {
        let author = identity(
            b"Ada sk_live_EXAMPLENOTAKEY00",
            b"postgres://ada:NOT-A-PASSWORD@db.example.test/x",
        );
        let (redacted, report) = redact(&commit(b"clean\n", author));
        let GitFactV1::Commit(commit) = &redacted else {
            panic!("not a commit");
        };
        assert_eq!(commit.author.name.as_bytes(), b"Ada [REDACTED]");
        assert!(
            !commit
                .author
                .email
                .as_bytes()
                .windows(b"NOT-A-PASSWORD".len())
                .any(|window| window == b"NOT-A-PASSWORD")
        );
        assert_eq!(commit.message.as_bytes(), b"clean\n");
        // author and committer are the same identity, so four fields moved.
        assert_eq!(report.fields_redacted, 4);
        assert!(report.classes.contains(&CollectedSecretClassV1::Provider(
            ProviderSecretClassV1::StripeKey
        )));
        assert!(report.classes.contains(&CollectedSecretClassV1::Shared(
            SecretClassV1::UrlEmbeddedCredential
        )));
    }

    #[test]
    fn a_non_utf8_field_without_a_finding_is_unchanged() {
        let raw = b"caf\xe9 au lait\n";
        let (redacted, report) = redact(&commit(raw, ada()));
        assert_eq!(message_of(&redacted), raw);
        assert!(!report.redacted());
    }

    #[test]
    fn a_non_utf8_field_with_a_finding_becomes_the_placeholder_alone() {
        let raw = b"\xff token AKIAIOSFODNN7EXAMPLE here\n";
        let (redacted, report) = redact(&commit(raw, ada()));
        assert_eq!(message_of(&redacted), REDACTION_PLACEHOLDER.as_bytes());
        assert_eq!(report.fields_withheld, 1);
        assert_eq!(
            report.classes,
            vec![CollectedSecretClassV1::Shared(
                SecretClassV1::AwsAccessKeyId
            )]
        );
    }

    #[test]
    fn a_private_key_block_withholds_the_whole_field_and_keeps_the_fact() {
        let message =
            b"here\n-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----\n";
        let (redacted, report) = redact(&commit(message, ada()));
        assert_eq!(message_of(&redacted), REDACTION_PLACEHOLDER.as_bytes());
        assert_eq!(report.fields_withheld, 1);
        assert_eq!(report.fields_redacted, 0);
        assert!(report.classes.contains(&CollectedSecretClassV1::Shared(
            SecretClassV1::PrivateKeyBlock
        )));
        // The fact still exists: the commit was made, only its text is gone.
        assert!(matches!(redacted, GitFactV1::Commit(_)));
        redacted.validate().unwrap();
    }

    #[test]
    fn a_blob_path_is_redacted_and_a_ref_observation_is_untouched() {
        let (redacted, report) = redact(&blob(b"secrets/xoxb-EXAMPLE-NOT-A-TOKEN.txt"));
        let GitFactV1::BlobSource(blob) = &redacted else {
            panic!("not a blob");
        };
        assert_eq!(blob.path.as_bytes(), b"secrets/[REDACTED].txt");
        assert_eq!(report.fields_redacted, 1);

        let observation = GitFactV1::RefObservation(GitRefObservationFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            ref_name: GitRefName::parse("refs/heads/main").unwrap(),
            target: oid(0xaa),
            observation_seq: 1,
            observed_at: stamp(),
            previous_target: None,
            observer: ContractId::new("connector.git.instance-1").unwrap(),
        });
        let (unchanged, report) = redact(&observation);
        assert_eq!(unchanged, observation);
        assert!(!report.redacted());
    }

    #[test]
    fn a_redacted_fact_builds_an_ingress_that_validates() {
        let active = generation_two_git_active();
        let binding = GitConnectorBindingV1::resolve(
            &active,
            ContractId::new("connector.git").unwrap(),
            ContractId::new("connector.git.instance-1").unwrap(),
            7,
        )
        .unwrap();
        let fact = commit(b"rotate ghp_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL\n", ada());
        let (redacted, report) = redact(&fact);
        assert!(report.redacted());
        let clocks = GitIngressClocksV1 {
            received_at: CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap(),
        };
        let ingress = binding.build_ingress(&redacted, &clocks, 1).unwrap();
        let payload = String::from_utf8(ingress.canonical_payload).unwrap();
        assert!(!payload.contains(&hex::encode("ghp_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL")));
        assert!(payload.contains(&hex::encode("rotate [REDACTED]\n")));
        assert_eq!(
            ingress.candidate.source_fact.immutable_revision,
            fact.immutable_revision().unwrap()
        );
    }
}
