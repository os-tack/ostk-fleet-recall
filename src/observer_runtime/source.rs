//! Binding one observer run to an exact git commit and blob (W3-OBSRT).
//!
//! # Why every coordinate is a pin
//!
//! An observation that says "I read the source" is worth nothing; an
//! observation that says "I read blob `4f2a…` at path `src/service.rs` in
//! commit `bf34dc1…`, and here is the digest of the bytes" is a claim someone
//! else can check. So [`ObserverSourcePinV1`] carries all four coordinates as
//! inputs the caller must already know, and this module's whole job is to
//! refuse when the object store disagrees with any of them.
//!
//! Three separate disagreements, three separate refusals:
//!
//! * **`ls-tree` resolves the path to a different blob.** This is the
//!   adversarial case the definition of done names: the same claimed commit,
//!   a different
//!   blob. [`ObserverRuntimeError::BlobIdMismatch`].
//! * **The bytes do not hash to the object id they were read under.** A store
//!   that answers a request for blob B with other bytes is lying about the
//!   only thing git's content addressing is supposed to guarantee.
//!   [`ObserverRuntimeError::BlobObjectIntegrity`].
//! * **The bytes do not reproduce the pinned content digest.** The pin is an
//!   OSTK-domain digest the caller computed independently, so satisfying it
//!   requires the actual bytes and not merely a store that echoes object ids
//!   back consistently. [`ObserverRuntimeError::ContentDigestMismatch`].
//!
//! The second check is the reason this module recomputes a SHA-1 git object
//! id rather than trusting `cat-file`. SHA-1 is used here for exactly one
//! thing — reproducing git's own object-name function for a SHA-1 repository —
//! and never as a security digest; every identity this crate mints is SHA-256
//! under a separated domain. A SHA-256 repository names objects with 64 hex
//! characters, and this check is skipped for those (with the pinned content
//! digest still enforced) rather than computed under the wrong function.
//!
//! # A commit id, never a revision expression
//!
//! [`bind_observed_source`] takes a [`GitObjectId`]. `HEAD`, `main@{1}` and
//! `v2^{}` would each let the repository decide at read time which source the
//! observation is about, which is precisely the ambiguity the receipt exists
//! to remove.

use std::str::FromStr as _;

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

use crate::connectors::git::{
    GIT_FACT_SCHEMA_VERSION, GitBlobSourceFactV1, GitFactV1, GitObjectId, GitRepositoryIdV1,
    GitRepositoryReader,
};
use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, HexBytes};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::identity::ResourceUri;

use super::error::{ObserverRuntimeError, ObserverRuntimeResult};

/// Hex length of a SHA-1 git object id.
const SHA1_OBJECT_ID_HEX_LEN: usize = 40;

/// Every coordinate of the source one run is pinned to.
///
/// All four are inputs, not discoveries. A field this runtime filled in for
/// itself would hash into the run's input identity exactly like a pinned one
/// and become indistinguishable from a checked coordinate downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverSourcePinV1 {
    /// The exact commit object the observation is about.
    pub commit_id: GitObjectId,
    /// The exact path inside that commit's tree.
    pub path: Vec<u8>,
    /// The exact blob object the path must resolve to.
    pub blob_id: GitObjectId,
    /// The exact `ostk-observer-source-blob-v1` digest of the blob's bytes.
    pub content_digest: Sha256Digest,
}

/// One source blob, proven to be the pinned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSourceV1 {
    fact: GitBlobSourceFactV1,
    bytes: Vec<u8>,
    content_digest: Sha256Digest,
}

impl ObservedSourceV1 {
    /// The provider fact naming the exact commit, tree, path, mode, and blob
    /// this run read.
    ///
    /// This is a W2-GIT fact, byte-identical to the one a scan of the same
    /// commit would produce, so the accepted event a drain minted for it is
    /// the event a run receipt cites.
    #[must_use]
    pub const fn fact(&self) -> &GitBlobSourceFactV1 {
        &self.fact
    }

    /// The observed fact wrapped for the W2-GIT identity derivations.
    #[must_use]
    pub fn git_fact(&self) -> GitFactV1 {
        GitFactV1::BlobSource(self.fact.clone())
    }

    /// The blob's exact bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The blob's bytes as source text.
    pub fn source_text(&self) -> ObserverRuntimeResult<&str> {
        std::str::from_utf8(&self.bytes).map_err(|_| ObserverRuntimeError::SourceNotUtf8)
    }

    /// The `ostk-observer-source-blob-v1` digest of the bytes.
    #[must_use]
    pub const fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }

    /// Exact input identity of a run over this source.
    ///
    /// Frames the repository, commit, path, blob object id, and blob content
    /// digest. Two runs whose input digests agree read the same bytes of the
    /// same object at the same coordinates; two that disagree read something
    /// different, whatever their receipts say in prose.
    #[must_use]
    pub fn input_digest(&self) -> Sha256Digest {
        framed_digest(
            DigestDomain::ObserverRunInputV1,
            &[
                self.fact.repository.repository_id.as_str().as_bytes(),
                self.fact.commit_id.as_bytes(),
                self.fact.path.as_bytes(),
                self.fact.blob_id.as_bytes(),
                self.content_digest.as_bytes(),
            ],
        )
    }
}

/// The `ostk-observer-source-blob-v1` digest of one blob's bytes.
#[must_use]
pub fn source_content_digest(bytes: &[u8]) -> Sha256Digest {
    framed_digest(DigestDomain::ObserverSourceBlobV1, &[bytes])
}

/// Resource kind of an observed source revision.
const OBSERVED_REVISION_RESOURCE_KIND: &str = "commit";

impl ObservedSourceV1 {
    /// The version-form resource URI naming exactly what this run read.
    ///
    /// This is deliberately NOT derived through an activated identity recipe,
    /// and the reason is worth stating rather than assuming. The frozen
    /// package's only version-form recipe, `identity.github.commit`, hashes
    /// `commit_oid` alone: a URI derived under it names the COMMIT, which is
    /// exactly the "the source at that revision" ambiguity a run receipt
    /// exists to remove — two different files at one commit would share one
    /// identity, and a store answering with a different object in the same
    /// commit's tree would be indistinguishable. (That recipe also has no
    /// entity-parent recipe inside its own authority namespace in the frozen
    /// package, so it cannot mint a version URI there at all.)
    ///
    /// So the observed revision is content-addressed over the whole pinned
    /// coordinate set — repository, commit, path, blob object id, and blob
    /// content digest — through [`Self::input_digest`]. Change any one of them
    /// and this URI changes, which is the property the receipt actually needs.
    pub fn observed_revision_uri(&self) -> ObserverRuntimeResult<ResourceUri> {
        Ok(ResourceUri::from_str(&format!(
            "urn:ostk:version:v1:{OBSERVED_REVISION_RESOURCE_KIND}:sha256:{}",
            self.input_digest()
        ))?)
    }
}

/// Read the pinned blob, and refuse unless every pinned coordinate holds.
///
/// `max_bytes` bounds the blob this runtime will read into memory; a blob over
/// the bound is refused rather than truncated, because a truncated read of a
/// source file is exactly the kind of partial coverage that must never look
/// like a complete one.
pub fn bind_observed_source(
    reader: &GitRepositoryReader,
    pin: &ObserverSourcePinV1,
    max_bytes: usize,
) -> ObserverRuntimeResult<ObservedSourceV1> {
    let entry = reader.resolve_path_blob(&pin.commit_id, &pin.path)?;
    if entry.blob_id != pin.blob_id {
        return Err(ObserverRuntimeError::BlobIdMismatch {
            expected: pin.blob_id.to_hex(),
            found: entry.blob_id.to_hex(),
        });
    }

    let bytes = reader.read_blob(&pin.blob_id)?;
    if bytes.len() > max_bytes {
        return Err(ObserverRuntimeError::SourceTooLarge {
            actual: bytes.len(),
            bound: max_bytes,
        });
    }
    require_git_object_integrity(&pin.blob_id, &bytes)?;

    let content_digest = source_content_digest(&bytes);
    if content_digest != pin.content_digest {
        return Err(ObserverRuntimeError::ContentDigestMismatch {
            expected: pin.content_digest,
            found: content_digest,
        });
    }

    let commit = reader.read_commit_fact(&pin.commit_id)?;
    let fact = GitBlobSourceFactV1 {
        schema_version: GIT_FACT_SCHEMA_VERSION,
        repository: reader.repository().clone(),
        commit_id: pin.commit_id.clone(),
        tree_id: commit.tree_id.clone(),
        path: entry.path,
        mode: entry.mode,
        // Taken from the bytes actually held, not from a size field git was
        // asked to report separately: one value, so there is nothing for the
        // two to disagree about.
        byte_length: CanonicalDecimal::parse(bytes.len().to_string())?,
        blob_id: pin.blob_id.clone(),
        committed_at: commit.committer.at,
    };
    GitFactV1::BlobSource(fact.clone()).validate()?;
    Ok(ObservedSourceV1 {
        fact,
        bytes,
        content_digest,
    })
}

/// Reproduce git's own object name for `bytes` and require it to be `blob_id`.
///
/// SHA-1 here is git's object-name function, not a security digest: it is the
/// only way to ask "are these the bytes git says are under this name?" without
/// trusting the process that just answered. A SHA-256 repository names objects
/// with a different function, so for those ids this check is skipped and the
/// pinned `ostk-observer-source-blob-v1` content digest — which is enforced
/// unconditionally — carries the integrity claim alone.
fn require_git_object_integrity(blob_id: &GitObjectId, bytes: &[u8]) -> ObserverRuntimeResult<()> {
    let hex = blob_id.to_hex();
    if hex.len() != SHA1_OBJECT_ID_HEX_LEN {
        return Ok(());
    }
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(b"blob ");
    context.update(bytes.len().to_string().as_bytes());
    context.update(&[0]);
    context.update(bytes);
    if hex::encode(context.finish().as_ref()) == hex {
        return Ok(());
    }
    Err(ObserverRuntimeError::BlobObjectIntegrity { blob_id: hex })
}

/// The instant one observation is stamped with.
///
/// Deliberately the observed commit's own instant, exactly as the git
/// connector does it: a wall clock inside the accepted-event preimage would
/// make two runs over the same pins two different events, and the ledger would
/// quarantine the second as an integrity collision instead of recognising a
/// replay (REPLAY-01).
#[must_use]
pub fn observation_instant(source: &ObservedSourceV1) -> CanonicalTimestamp {
    source.fact.committed_at.clone()
}

/// The pinned path as contract bytes.
pub fn pinned_path(pin: &ObserverSourcePinV1) -> ObserverRuntimeResult<HexBytes> {
    Ok(HexBytes::new(pin.path.clone())?)
}

/// The repository the pins are read from.
#[must_use]
pub fn pinned_repository(reader: &GitRepositoryReader) -> GitRepositoryIdV1 {
    reader.repository().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::common::ContractId;
    use crate::memory_contracts::identity::IdentityForm;

    fn blob_id_of(bytes: &[u8]) -> String {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(b"blob ");
        context.update(bytes.len().to_string().as_bytes());
        context.update(&[0]);
        context.update(bytes);
        hex::encode(context.finish().as_ref())
    }

    #[test]
    fn the_git_object_name_this_module_reproduces_is_the_one_git_mints() {
        // `git hash-object` of the empty blob and of "hello\n" are the two
        // most widely published git object ids there are, so they pin the
        // framing (`blob <len>\0`) without needing a repository.
        assert_eq!(blob_id_of(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(
            blob_id_of(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }

    #[test]
    fn bytes_that_do_not_hash_to_the_object_id_are_refused() {
        let honest = GitObjectId::parse_hex(&blob_id_of(b"hello\n")).unwrap();
        require_git_object_integrity(&honest, b"hello\n").unwrap();
        let error = require_git_object_integrity(&honest, b"goodbye\n").unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::BlobObjectIntegrity { .. }
        ));
    }

    #[test]
    fn a_sha256_object_id_skips_the_sha1_check_rather_than_running_the_wrong_one() {
        let sha256_id = GitObjectId::parse_hex(&hex::encode([0x11_u8; 32])).unwrap();
        require_git_object_integrity(&sha256_id, b"anything").unwrap();
    }

    #[test]
    fn the_observed_revision_uri_is_version_form_and_names_the_whole_pin() {
        let repository =
            GitRepositoryIdV1::from_trusted_config(ContractId::new("git.repo.t").unwrap(), 7)
                .unwrap();
        let build = |blob_seed: u8, content: &[u8]| ObservedSourceV1 {
            fact: GitBlobSourceFactV1 {
                schema_version: GIT_FACT_SCHEMA_VERSION,
                repository: repository.clone(),
                commit_id: GitObjectId::parse_hex(&hex::encode([0x11_u8; 20])).unwrap(),
                tree_id: GitObjectId::parse_hex(&hex::encode([0x22_u8; 20])).unwrap(),
                path: HexBytes::new(b"service.rs".to_vec()).unwrap(),
                mode: crate::connectors::git::GitFileModeV1::Regular,
                byte_length: CanonicalDecimal::parse(content.len().to_string()).unwrap(),
                blob_id: GitObjectId::parse_hex(&hex::encode([blob_seed; 20])).unwrap(),
                committed_at: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
            },
            bytes: content.to_vec(),
            content_digest: source_content_digest(content),
        };
        let one = build(0x33, b"a");
        assert_eq!(
            one.observed_revision_uri().unwrap().identity_form(),
            IdentityForm::Version
        );
        // A different blob at the same commit is a different revision, and so
        // is the same blob id carrying different bytes.
        assert_ne!(
            one.observed_revision_uri().unwrap(),
            build(0x44, b"a").observed_revision_uri().unwrap()
        );
        assert_ne!(
            one.observed_revision_uri().unwrap(),
            build(0x33, b"b").observed_revision_uri().unwrap()
        );
        assert_eq!(
            one.observed_revision_uri().unwrap(),
            build(0x33, b"a").observed_revision_uri().unwrap()
        );
    }

    #[test]
    fn the_content_digest_is_domain_separated_and_byte_exact() {
        assert_ne!(source_content_digest(b"a"), source_content_digest(b"a\n"));
        assert_eq!(source_content_digest(b"a"), source_content_digest(b"a"));
        assert_ne!(
            source_content_digest(b"a"),
            framed_digest(DigestDomain::ObserverRunInputV1, &[b"a"])
        );
    }
}
