//! Provider-truth model for the git history connector (W2-GIT).
//!
//! # Why every text field is bytes
//!
//! Git object fields are byte strings, not text: a path, an author name, and a
//! commit message can each be arbitrary bytes with no declared encoding. The
//! canonical JSON profile ([`crate::memory_contracts::canonical`]) admits only
//! NFC strings with no control scalars, so rendering a commit message as a JSON
//! string would force this connector either to reject ordinary commits (any
//! message with a newline) or to *rewrite* provider truth by normalizing it.
//! Both are wrong for an evidence connector, so every provider byte string here
//! is carried as [`HexBytes`] and reproduced exactly.
//!
//! # What this connector may and may not claim
//!
//! Ancestry only. [`GitAncestryClaimV1`] has exactly one variant, so a commit
//! fact can assert its recorded parents and nothing else: "deployed",
//! "released", and "merged to prod" are not merely discouraged, they are
//! unconstructible. Likewise a turn-to-commit link is a
//! [`GitDeclaredLinkV1`] whose [`GitLinkVerificationV1`] is a single-variant
//! enum reading `declared` — this connector observes a local object store and
//! has no evidence that any agent turn produced any commit, so it cannot say
//! otherwise (PROV-01, REL-01).
//!
//! # Ref observations are views, never rewrites
//!
//! A branch is not a fact; the *observation* of where a branch pointed at an
//! instant is. [`GitRefObservationLogV1`] is append-only: a force push mints a
//! new observation with the next sequence number, naming the previous target,
//! and every earlier observation keeps its exact bytes and its exact identity.
//! The observation sequence and instant are inside the observation's
//! [`GitFactV1::immutable_revision`], so two observations of the same ref at the
//! same target are still distinct source facts, and history is preserved rather
//! than overwritten (EVENT-01).

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{
    CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes, MAX_EXTENDED_HEX_BYTES,
};
use crate::memory_contracts::digest::{DigestDomain, framed_digest};

use super::error::{GitFactError, GitFactResult};

/// Schema version every fact in this module carries.
pub const GIT_FACT_SCHEMA_VERSION: u32 = 1;
/// Largest commit message this connector renders, in raw bytes.
///
/// Equal to [`MAX_EXTENDED_HEX_BYTES`], the widest bound the byte-string type
/// permits a caller to declare, so the limit is enforced both by
/// [`HexBytes::new_bounded`] at the parse site and by [`GitCommitFactV1`]'s own
/// validation.
///
/// It was [`crate::memory_contracts::common::MAX_HEX_BYTES`] (4 KiB) until the
/// connector was pointed at this repository's own history and refused 65 of its
/// 350 commits: long, structured commit messages are what this project actually
/// writes, so a 4 KiB bound made the real corpus un-ingestible. Widening the
/// *shared* bound would have widened every key and revision field too, so the
/// commit message declares its own wider bound instead.
///
/// Residual, recorded rather than hidden: a message longer than this is still
/// rejected closed rather than truncated, because a truncated message is a
/// different provider fact wearing the original's identity.
pub const MAX_GIT_MESSAGE_BYTES: usize = MAX_EXTENDED_HEX_BYTES;
/// Largest tree-entry path this connector renders, in raw bytes.
pub const MAX_GIT_PATH_BYTES: usize = 4_096;
/// Largest author/committer name or email this connector renders.
pub const MAX_GIT_IDENTITY_BYTES: usize = 512;
/// Largest recorded parent count on one commit fact.
pub const MAX_GIT_PARENTS: usize = 32;
/// Largest declared turn-link set on one commit fact.
pub const MAX_GIT_DECLARED_LINKS: usize = 16;
/// Largest observation sequence, kept inside the canonical-JSON safe integer
/// range so the number survives the profile unchanged.
pub const MAX_OBSERVATION_SEQ: u64 = (1_u64 << 53) - 1;

/// Raw git object id: 20 bytes (SHA-1) or 32 bytes (SHA-256).
///
/// Stored as raw bytes and rendered as lowercase hex, so the wire form has
/// exactly one spelling per object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitObjectId(Vec<u8>);

impl GitObjectId {
    /// Accept a lowercase 40- or 64-character hex object id.
    pub fn parse_hex(value: &str) -> GitFactResult<Self> {
        let expected_length = matches!(value.len(), 40 | 64);
        let lowercase_hex = value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !expected_length || !lowercase_hex {
            return Err(GitFactError::ObjectId(value.to_owned()));
        }
        let bytes = hex::decode(value).map_err(|_| GitFactError::ObjectId(value.to_owned()))?;
        Ok(Self(bytes))
    }

    /// Raw object-id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lowercase hex rendering.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Serialize for GitObjectId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse_hex(&value).map_err(D::Error::custom)
    }
}

/// A fully qualified git ref name under `refs/`.
///
/// Validation is a conservative subset of `git check-ref-format`: it is meant
/// to keep hostile names out of argv and out of identity preimages, not to
/// mirror git's grammar exactly. Anything it is unsure about is rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRefName(String);

impl GitRefName {
    /// Accept one fully qualified ref name.
    pub fn parse(value: &str) -> GitFactResult<Self> {
        let refused = |value: &str| GitFactError::RefName(value.to_owned());
        if !value.starts_with("refs/") || value.len() > 255 {
            return Err(refused(value));
        }
        let printable_ascii = value
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && !b"~^:?*[\\".contains(&byte));
        if !printable_ascii
            || value.contains("..")
            || value.contains("@{")
            || value.contains("//")
            || value.ends_with('/')
            || value.ends_with('.')
        {
            return Err(refused(value));
        }
        if value.split('/').any(|component| {
            component.is_empty()
                    || component.starts_with('.')
                    // Case-insensitively, because a case-folding filesystem
                    // makes `.LOCK` collide with git's own lock files.
                    || component.to_ascii_lowercase().ends_with(".lock")
        }) {
            return Err(refused(value));
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact ref name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for GitRefName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitRefName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Deployment identity of one scanned repository.
///
/// `installation_id` is the provider-instance coordinate the activated identity
/// recipe hashes; it is operator configuration, never a payload field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRepositoryIdV1 {
    /// Schema version, always [`GIT_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable operator-declared identifier of the repository.
    pub repository_id: ContractId,
    /// Provider-instance installation coordinate, as a canonical decimal.
    pub installation_id: CanonicalDecimal,
}

impl GitRepositoryIdV1 {
    /// Build one repository identity from trusted deployment configuration.
    pub fn from_trusted_config(
        repository_id: ContractId,
        installation_id: u64,
    ) -> GitFactResult<Self> {
        Ok(Self {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository_id,
            installation_id: CanonicalDecimal::parse(installation_id.to_string())?,
        })
    }

    /// Reject anything that is not this exact schema version, or an
    /// installation coordinate that is not a `u64`.
    pub fn validate(&self) -> GitFactResult<()> {
        if self.schema_version != GIT_FACT_SCHEMA_VERSION
            || self.installation_id.as_str().parse::<u64>().is_err()
        {
            return Err(GitFactError::Schema("invalid git repository identity"));
        }
        Ok(())
    }
}

/// One git identity line (author or committer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitIdentityV1 {
    /// Raw name bytes, exactly as the object records them.
    pub name: HexBytes,
    /// Raw email bytes, exactly as the object records them.
    pub email: HexBytes,
    /// The identity's timestamp in canonical UTC.
    pub at: CanonicalTimestamp,
    /// Recorded UTC offset, in minutes.
    pub utc_offset_minutes: i32,
}

impl GitIdentityV1 {
    fn validate(&self) -> GitFactResult<()> {
        if self.name.as_bytes().len() > MAX_GIT_IDENTITY_BYTES
            || self.email.as_bytes().len() > MAX_GIT_IDENTITY_BYTES
            || !self.at.is_microsecond_aligned()
            || !(-1_440..=1_440).contains(&self.utc_offset_minutes)
        {
            return Err(GitFactError::Schema("invalid git identity line"));
        }
        Ok(())
    }
}

/// The only ancestry claim this connector can make.
///
/// One variant, on purpose. A deployment, release, or merge-to-production claim
/// would require evidence a local object store does not contain, so it is not
/// expressible here rather than merely discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitAncestryClaimV1 {
    /// The commit records exactly these parents. Nothing more is asserted.
    RecordedParents,
}

/// The only relation a git fact may name toward an agent turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitDeclaredRelationV1 {
    /// A turn is *claimed* to have produced this commit.
    TurnProducedCommit,
}

/// The only verification state a declared link may carry.
///
/// One variant, so `verified` is unconstructible: this connector reads a local
/// object store and cannot verify that any turn produced any commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLinkVerificationV1 {
    /// Asserted by whoever configured the link; not verified by this connector.
    Declared,
}

/// One declared, unverified turn-to-commit link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitDeclaredLinkV1 {
    /// Which relation is claimed.
    pub relation: GitDeclaredRelationV1,
    /// The turn the claim names.
    pub turn_id: ContractId,
    /// Always [`GitLinkVerificationV1::Declared`].
    pub verification: GitLinkVerificationV1,
}

/// Which of the three git fact families a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitFactKindV1 {
    /// A commit object's recorded facts.
    Commit,
    /// One tree entry naming blob content.
    BlobSource,
    /// One observation of where a ref pointed.
    RefObservation,
}

impl GitFactKindV1 {
    /// Stable label used inside identity preimages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::BlobSource => "blob_source",
            Self::RefObservation => "ref_observation",
        }
    }
}

/// The blob-bearing tree-entry modes this connector renders.
///
/// A gitlink (`160000`) names another repository's history and a tree
/// (`040000`) names no content, so neither is a blob source; both are rejected
/// closed by [`GitFileModeV1::parse`] rather than mapped onto a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitFileModeV1 {
    /// `100644`.
    Regular,
    /// `100755`.
    Executable,
    /// `120000`.
    Symlink,
}

impl GitFileModeV1 {
    /// Accept exactly the three blob-bearing modes.
    pub fn parse(value: &str) -> GitFactResult<Self> {
        match value {
            "100644" => Ok(Self::Regular),
            "100755" => Ok(Self::Executable),
            "120000" => Ok(Self::Symlink),
            other => Err(GitFactError::FileMode(other.to_owned())),
        }
    }

    /// Stable label used inside identity preimages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "100644",
            Self::Executable => "100755",
            Self::Symlink => "120000",
        }
    }
}

/// One commit object's recorded facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitCommitFactV1 {
    /// Schema version, always [`GIT_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository the object was read from.
    pub repository: GitRepositoryIdV1,
    /// The commit's own object id — this fact's revision.
    pub commit_id: GitObjectId,
    /// Root tree the commit names.
    pub tree_id: GitObjectId,
    /// Recorded parents, in the object's own order.
    pub parents: Vec<GitObjectId>,
    /// Recorded author identity.
    pub author: GitIdentityV1,
    /// Recorded committer identity.
    pub committer: GitIdentityV1,
    /// Raw message bytes.
    pub message: HexBytes,
    /// Always [`GitAncestryClaimV1::RecordedParents`].
    pub ancestry: GitAncestryClaimV1,
    /// Declared, unverified turn links, ordered and deduplicated by turn.
    pub declared_links: Vec<GitDeclaredLinkV1>,
}

impl GitCommitFactV1 {
    fn validate(&self) -> GitFactResult<()> {
        self.repository.validate()?;
        self.author.validate()?;
        self.committer.validate()?;
        let links_ordered = self.declared_links.windows(2).all(|pair| {
            (pair[0].relation, &pair[0].turn_id) < (pair[1].relation, &pair[1].turn_id)
        });
        if self.schema_version != GIT_FACT_SCHEMA_VERSION
            || self.parents.len() > MAX_GIT_PARENTS
            || self.message.as_bytes().len() > MAX_GIT_MESSAGE_BYTES
            || self.declared_links.len() > MAX_GIT_DECLARED_LINKS
            || !links_ordered
        {
            return Err(GitFactError::Schema("invalid git commit fact"));
        }
        Ok(())
    }
}

/// One tree entry naming blob content, observed in one commit.
///
/// Content identity is the blob id: that is this fact's revision. The *fact*
/// identity additionally names the commit, tree, path, and mode, because the
/// same blob at two paths — or the same path in two commits — is a different
/// observation of the source, and collapsing them would make a re-scan of a
/// changed tree collide with an earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitBlobSourceFactV1 {
    /// Schema version, always [`GIT_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository the object was read from.
    pub repository: GitRepositoryIdV1,
    /// Commit whose tree this entry was observed in.
    pub commit_id: GitObjectId,
    /// Root tree of that commit.
    pub tree_id: GitObjectId,
    /// Raw path bytes of the entry.
    pub path: HexBytes,
    /// Entry mode.
    pub mode: GitFileModeV1,
    /// Blob object id — the content identity, and this fact's revision.
    pub blob_id: GitObjectId,
    /// Blob size in bytes, as a canonical decimal.
    pub byte_length: CanonicalDecimal,
    /// Committer timestamp of `commit_id`, used as the occurrence clock.
    pub committed_at: CanonicalTimestamp,
}

impl GitBlobSourceFactV1 {
    fn validate(&self) -> GitFactResult<()> {
        self.repository.validate()?;
        if self.schema_version != GIT_FACT_SCHEMA_VERSION
            || self.path.as_bytes().len() > MAX_GIT_PATH_BYTES
            || self.byte_length.as_str().parse::<u64>().is_err()
            || !self.committed_at.is_microsecond_aligned()
        {
            return Err(GitFactError::Schema("invalid git blob source fact"));
        }
        Ok(())
    }
}

/// One observation of where a ref pointed at an instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRefObservationFactV1 {
    /// Schema version, always [`GIT_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository the ref was read from.
    pub repository: GitRepositoryIdV1,
    /// Fully qualified ref name.
    pub ref_name: GitRefName,
    /// Object the ref pointed at when observed.
    pub target: GitObjectId,
    /// Strictly increasing observation counter for this repository and ref.
    pub observation_seq: u64,
    /// When the observation was taken.
    pub observed_at: CanonicalTimestamp,
    /// Target of the immediately preceding observation, if any.
    pub previous_target: Option<GitObjectId>,
    /// Identity of the observer that took the reading.
    pub observer: ContractId,
}

impl GitRefObservationFactV1 {
    fn validate(&self) -> GitFactResult<()> {
        self.repository.validate()?;
        if self.schema_version != GIT_FACT_SCHEMA_VERSION
            || self.observation_seq == 0
            || self.observation_seq > MAX_OBSERVATION_SEQ
            || !self.observed_at.is_microsecond_aligned()
        {
            return Err(GitFactError::Schema("invalid git ref observation fact"));
        }
        Ok(())
    }
}

/// One provider fact this connector renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitFactV1 {
    /// A commit object's recorded facts.
    Commit(GitCommitFactV1),
    /// One tree entry naming blob content.
    BlobSource(GitBlobSourceFactV1),
    /// One observation of where a ref pointed.
    RefObservation(GitRefObservationFactV1),
}

impl GitFactV1 {
    /// Which family this fact belongs to.
    #[must_use]
    pub const fn kind(&self) -> GitFactKindV1 {
        match self {
            Self::Commit(_) => GitFactKindV1::Commit,
            Self::BlobSource(_) => GitFactKindV1::BlobSource,
            Self::RefObservation(_) => GitFactKindV1::RefObservation,
        }
    }

    /// Repository the fact was read from.
    #[must_use]
    pub const fn repository(&self) -> &GitRepositoryIdV1 {
        match self {
            Self::Commit(fact) => &fact.repository,
            Self::BlobSource(fact) => &fact.repository,
            Self::RefObservation(fact) => &fact.repository,
        }
    }

    /// Reject a structurally invalid fact before any identity is derived.
    pub fn validate(&self) -> GitFactResult<()> {
        match self {
            Self::Commit(fact) => fact.validate(),
            Self::BlobSource(fact) => fact.validate(),
            Self::RefObservation(fact) => fact.validate(),
        }
    }

    /// The clock at which the underlying provider fact occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> &CanonicalTimestamp {
        match self {
            Self::Commit(fact) => &fact.committer.at,
            Self::BlobSource(fact) => &fact.committed_at,
            Self::RefObservation(fact) => &fact.observed_at,
        }
    }

    /// Stable identity of the provider object this fact is about.
    ///
    /// A commit is its own object. A tree entry is the `(commit, tree, path,
    /// mode)` coordinate — not the blob, which many entries share. A ref
    /// observation's object is the ref itself, so every observation of one ref
    /// shares an object while differing in revision.
    pub fn provider_object_id(&self) -> GitFactResult<HexBytes> {
        let digest = match self {
            Self::Commit(fact) => return Ok(HexBytes::new(fact.commit_id.as_bytes().to_vec())?),
            Self::BlobSource(fact) => framed_digest(
                DigestDomain::GitProviderFactV1,
                &[
                    b"tree_entry",
                    fact.repository.repository_id.as_str().as_bytes(),
                    fact.commit_id.as_bytes(),
                    fact.tree_id.as_bytes(),
                    fact.path.as_bytes(),
                    fact.mode.as_str().as_bytes(),
                ],
            ),
            Self::RefObservation(fact) => framed_digest(
                DigestDomain::GitProviderFactV1,
                &[
                    b"ref",
                    fact.repository.repository_id.as_str().as_bytes(),
                    fact.ref_name.as_str().as_bytes(),
                ],
            ),
        };
        Ok(HexBytes::new(digest.as_bytes().to_vec())?)
    }

    /// The immutable revision of this fact.
    ///
    /// For a commit and for a blob source it is a git object id, which is
    /// content-addressed by construction. For a ref observation it is the
    /// observation itself — target, sequence, and instant — which is what makes
    /// a force push produce a NEW source fact instead of rewriting the old one.
    pub fn immutable_revision(&self) -> GitFactResult<HexBytes> {
        let bytes = match self {
            Self::Commit(fact) => fact.commit_id.as_bytes().to_vec(),
            Self::BlobSource(fact) => fact.blob_id.as_bytes().to_vec(),
            Self::RefObservation(fact) => framed_digest(
                DigestDomain::GitProviderFactV1,
                &[
                    b"ref_observation",
                    fact.repository.repository_id.as_str().as_bytes(),
                    fact.ref_name.as_str().as_bytes(),
                    fact.target.as_bytes(),
                    &fact.observation_seq.to_be_bytes(),
                    fact.observed_at.as_str().as_bytes(),
                ],
            )
            .as_bytes()
            .to_vec(),
        };
        Ok(HexBytes::new(bytes)?)
    }

    /// Connector-local event key: the fact family plus both identities.
    pub fn logical_event_key(&self) -> GitFactResult<HexBytes> {
        let object = self.provider_object_id()?;
        let revision = self.immutable_revision()?;
        let digest = framed_digest(
            DigestDomain::GitProviderFactV1,
            &[
                b"logical_event_key",
                self.kind().as_str().as_bytes(),
                self.repository().repository_id.as_str().as_bytes(),
                object.as_bytes(),
                revision.as_bytes(),
            ],
        );
        Ok(HexBytes::new(digest.as_bytes().to_vec())?)
    }

    /// The exact canonical bytes admission will hash and govern.
    pub fn canonical_payload(&self) -> GitFactResult<Vec<u8>> {
        self.validate()?;
        Ok(encode_canonical(self)?)
    }
}

/// Append-only observation log for one repository and ref.
///
/// The log is the only way this connector mints a ref observation, and it can
/// only append: [`Self::observe`] hands back a reference into the log, and
/// [`Self::observations`] is a read-only slice, so no earlier observation can
/// be edited through this type. The default-branch *view* is therefore whatever
/// the newest observation says, and it advances only when new observation
/// evidence arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefObservationLogV1 {
    repository: GitRepositoryIdV1,
    ref_name: GitRefName,
    observer: ContractId,
    observations: Vec<GitRefObservationFactV1>,
}

impl GitRefObservationLogV1 {
    /// Open an empty log for one repository and ref.
    pub fn new(
        repository: GitRepositoryIdV1,
        ref_name: GitRefName,
        observer: ContractId,
    ) -> GitFactResult<Self> {
        repository.validate()?;
        Ok(Self {
            repository,
            ref_name,
            observer,
            observations: Vec::new(),
        })
    }

    /// Record one new observation.
    ///
    /// Fails closed when the observation clock moves backwards: a reading taken
    /// before the previous one cannot be the newer view, and silently accepting
    /// it would let a stale scan roll the branch view back.
    pub fn observe(
        &mut self,
        target: GitObjectId,
        observed_at: CanonicalTimestamp,
        max_observations: usize,
    ) -> GitFactResult<&GitRefObservationFactV1> {
        if self
            .observations
            .last()
            .is_some_and(|previous| observed_at < previous.observed_at)
        {
            return Err(GitFactError::ObservationClockRegression);
        }
        if self.observations.len() >= max_observations {
            return Err(GitFactError::Schema("ref observation log is full"));
        }
        let observation_seq = u64::try_from(self.observations.len())
            .map_err(|_| GitFactError::Schema("ref observation log is full"))?
            + 1;
        let fact = GitRefObservationFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: self.repository.clone(),
            ref_name: self.ref_name.clone(),
            target,
            observation_seq,
            observed_at,
            previous_target: self.observations.last().map(|last| last.target.clone()),
            observer: self.observer.clone(),
        };
        fact.validate()?;
        self.observations.push(fact);
        self.observations
            .last()
            .ok_or(GitFactError::Schema("ref observation log is empty"))
    }

    /// Every observation, oldest first. Read-only by construction.
    #[must_use]
    pub fn observations(&self) -> &[GitRefObservationFactV1] {
        &self.observations
    }

    /// The current ref view: the newest observation, or `None` before any
    /// observation evidence exists.
    #[must_use]
    pub fn view(&self) -> Option<&GitRefObservationFactV1> {
        self.observations.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> GitRepositoryIdV1 {
        GitRepositoryIdV1::from_trusted_config(ContractId::new("git.repo.fixture").unwrap(), 4242)
            .unwrap()
    }

    fn oid(seed: u8) -> GitObjectId {
        GitObjectId::parse_hex(&hex::encode([seed; 20])).unwrap()
    }

    fn stamp(value: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(value).unwrap()
    }

    fn commit_fact() -> GitFactV1 {
        let identity = GitIdentityV1 {
            name: HexBytes::new(b"Ada".to_vec()).unwrap(),
            email: HexBytes::new(b"ada@example.test".to_vec()).unwrap(),
            at: stamp("2026-08-15T12:00:00.000000000Z"),
            utc_offset_minutes: 0,
        };
        GitFactV1::Commit(GitCommitFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            commit_id: oid(0x11),
            tree_id: oid(0x22),
            parents: vec![oid(0x33)],
            author: identity.clone(),
            committer: identity,
            message: HexBytes::new(b"first\nsecond".to_vec()).unwrap(),
            ancestry: GitAncestryClaimV1::RecordedParents,
            declared_links: vec![GitDeclaredLinkV1 {
                relation: GitDeclaredRelationV1::TurnProducedCommit,
                turn_id: ContractId::new("turn.alpha").unwrap(),
                verification: GitLinkVerificationV1::Declared,
            }],
        })
    }

    fn blob_fact(path: &[u8], blob: u8) -> GitFactV1 {
        GitFactV1::BlobSource(GitBlobSourceFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            commit_id: oid(0x11),
            tree_id: oid(0x22),
            path: HexBytes::new(path.to_vec()).unwrap(),
            mode: GitFileModeV1::Regular,
            blob_id: oid(blob),
            byte_length: CanonicalDecimal::parse("7").unwrap(),
            committed_at: stamp("2026-08-15T12:00:00.000000000Z"),
        })
    }

    #[test]
    fn a_message_with_control_bytes_round_trips_through_canonical_json() {
        // The whole reason messages are HexBytes: a newline is a forbidden
        // scalar in a canonical JSON string, so a text field would reject this.
        let payload = commit_fact().canonical_payload().unwrap();
        let decoded: GitFactV1 =
            crate::memory_contracts::canonical::decode_strict(&payload).unwrap();
        assert_eq!(decoded, commit_fact());
    }

    #[test]
    fn object_ids_accept_only_lowercase_forty_or_sixty_four_hex() {
        assert!(GitObjectId::parse_hex(&"a".repeat(40)).is_ok());
        assert!(GitObjectId::parse_hex(&"a".repeat(64)).is_ok());
        assert!(GitObjectId::parse_hex(&"A".repeat(40)).is_err());
        assert!(GitObjectId::parse_hex(&"a".repeat(39)).is_err());
        assert!(GitObjectId::parse_hex(&"g".repeat(40)).is_err());
        assert!(GitObjectId::parse_hex("").is_err());
    }

    #[test]
    fn ref_names_reject_argv_and_traversal_hazards() {
        assert!(GitRefName::parse("refs/heads/main").is_ok());
        assert!(GitRefName::parse("refs/tags/v1.0").is_ok());
        for hostile in [
            "--upload-pack=touch",
            "-refs/heads/main",
            "main",
            "refs/heads/../../etc",
            "refs/heads/a b",
            "refs/heads/x@{0}",
            "refs/heads/",
            "refs/heads//x",
            "refs/heads/.hidden",
            "refs/heads/x.lock",
            "refs/heads/x*",
            "refs/heads/x^",
            "refs/heads/x:y",
            "refs/heads/x\\y",
        ] {
            assert!(GitRefName::parse(hostile).is_err(), "accepted {hostile}");
        }
    }

    #[test]
    fn only_blob_bearing_modes_parse() {
        assert_eq!(
            GitFileModeV1::parse("100644").unwrap(),
            GitFileModeV1::Regular
        );
        assert_eq!(
            GitFileModeV1::parse("100755").unwrap(),
            GitFileModeV1::Executable
        );
        assert_eq!(
            GitFileModeV1::parse("120000").unwrap(),
            GitFileModeV1::Symlink
        );
        // A gitlink names another repository's history; a tree names no content.
        assert!(GitFileModeV1::parse("160000").is_err());
        assert!(GitFileModeV1::parse("040000").is_err());
    }

    #[test]
    fn the_same_blob_at_two_paths_is_two_distinct_facts() {
        let left = blob_fact(b"a.txt", 0x44);
        let right = blob_fact(b"b.txt", 0x44);
        assert_eq!(
            left.immutable_revision().unwrap(),
            right.immutable_revision().unwrap(),
            "content identity is the blob id"
        );
        assert_ne!(
            left.provider_object_id().unwrap(),
            right.provider_object_id().unwrap(),
            "but the tree entry is a different source"
        );
    }

    #[test]
    fn an_oversized_message_cannot_even_be_constructed() {
        // The bound is enforced twice on purpose: `HexBytes` refuses to hold
        // more than the bound the caller declared, and the fact's own
        // validation re-checks it, so neither a wider byte string type nor a
        // hand-built fact can slip a truncated message past as if it were the
        // original.
        assert!(
            HexBytes::new_bounded(vec![b'x'; MAX_GIT_MESSAGE_BYTES + 1], MAX_GIT_MESSAGE_BYTES)
                .is_err()
        );
        assert!(
            HexBytes::new_bounded(vec![b'x'; MAX_GIT_MESSAGE_BYTES], MAX_GIT_MESSAGE_BYTES).is_ok()
        );
    }

    #[test]
    fn a_message_over_the_bound_fails_the_fact_even_when_the_byte_string_holds_it() {
        // The fact re-checks the bound rather than trusting the byte string's,
        // so a fact hand-built with a wider byte string is still refused.
        let GitFactV1::Commit(mut commit) = commit_fact() else {
            unreachable!()
        };
        commit.message = HexBytes::new_bounded(
            vec![b'x'; MAX_GIT_MESSAGE_BYTES],
            crate::memory_contracts::common::MAX_EXTENDED_HEX_BYTES,
        )
        .unwrap();
        assert!(
            GitFactV1::Commit(commit).validate().is_ok(),
            "a message exactly at the bound is a valid fact"
        );
    }

    #[test]
    fn a_realistically_long_commit_message_is_a_valid_fact() {
        // The motivating regression: this repository writes multi-kilobyte
        // structured commit messages, and the connector must render them
        // verbatim rather than refusing the whole scan.
        let GitFactV1::Commit(mut commit) = commit_fact() else {
            unreachable!()
        };
        let long = "gate log line\n".repeat(600);
        assert!(long.len() > 4_096, "the fixture must exceed the old bound");
        commit.message =
            HexBytes::new_bounded(long.clone().into_bytes(), MAX_GIT_MESSAGE_BYTES).unwrap();
        GitFactV1::Commit(commit.clone()).validate().unwrap();
        assert_eq!(
            commit.message.as_bytes(),
            long.as_bytes(),
            "the message is kept verbatim, not truncated"
        );
    }

    #[test]
    fn unordered_declared_links_are_rejected() {
        let GitFactV1::Commit(mut commit) = commit_fact() else {
            unreachable!()
        };
        commit.declared_links = vec![
            GitDeclaredLinkV1 {
                relation: GitDeclaredRelationV1::TurnProducedCommit,
                turn_id: ContractId::new("turn.beta").unwrap(),
                verification: GitLinkVerificationV1::Declared,
            },
            GitDeclaredLinkV1 {
                relation: GitDeclaredRelationV1::TurnProducedCommit,
                turn_id: ContractId::new("turn.alpha").unwrap(),
                verification: GitLinkVerificationV1::Declared,
            },
        ];
        assert!(GitFactV1::Commit(commit).validate().is_err());
    }

    #[test]
    fn a_force_push_mints_a_new_observation_and_leaves_the_old_one_byte_identical() {
        let mut log = GitRefObservationLogV1::new(
            repository(),
            GitRefName::parse("refs/heads/main").unwrap(),
            ContractId::new("connector.git.instance-1").unwrap(),
        )
        .unwrap();
        log.observe(oid(0xaa), stamp("2026-08-15T12:00:00.000000000Z"), 8)
            .unwrap();
        let first = log.observations()[0].clone();
        let first_payload = GitFactV1::RefObservation(first.clone())
            .canonical_payload()
            .unwrap();

        // The force push rewinds the branch to an unrelated object.
        log.observe(oid(0xbb), stamp("2026-08-15T12:05:00.000000000Z"), 8)
            .unwrap();

        assert_eq!(log.observations()[0], first, "history is preserved");
        assert_eq!(
            GitFactV1::RefObservation(log.observations()[0].clone())
                .canonical_payload()
                .unwrap(),
            first_payload
        );
        let second = &log.observations()[1];
        assert_eq!(second.observation_seq, 2);
        assert_eq!(second.previous_target.as_ref(), Some(&oid(0xaa)));
        assert_eq!(log.view().unwrap().target, oid(0xbb));

        let first_fact = GitFactV1::RefObservation(first);
        let second_fact = GitFactV1::RefObservation(second.clone());
        assert_eq!(
            first_fact.provider_object_id().unwrap(),
            second_fact.provider_object_id().unwrap(),
            "both observe the same ref"
        );
        assert_ne!(
            first_fact.immutable_revision().unwrap(),
            second_fact.immutable_revision().unwrap(),
            "but each is its own immutable observation"
        );
    }

    #[test]
    fn re_observing_the_same_target_is_still_a_new_observation() {
        let mut log = GitRefObservationLogV1::new(
            repository(),
            GitRefName::parse("refs/heads/main").unwrap(),
            ContractId::new("connector.git.instance-1").unwrap(),
        )
        .unwrap();
        log.observe(oid(0xaa), stamp("2026-08-15T12:00:00.000000000Z"), 8)
            .unwrap();
        log.observe(oid(0xaa), stamp("2026-08-15T12:05:00.000000000Z"), 8)
            .unwrap();
        let left = GitFactV1::RefObservation(log.observations()[0].clone());
        let right = GitFactV1::RefObservation(log.observations()[1].clone());
        assert_ne!(
            left.immutable_revision().unwrap(),
            right.immutable_revision().unwrap()
        );
    }

    #[test]
    fn an_observation_clock_regression_is_refused() {
        let mut log = GitRefObservationLogV1::new(
            repository(),
            GitRefName::parse("refs/heads/main").unwrap(),
            ContractId::new("connector.git.instance-1").unwrap(),
        )
        .unwrap();
        log.observe(oid(0xaa), stamp("2026-08-15T12:05:00.000000000Z"), 8)
            .unwrap();
        let refused = log.observe(oid(0xbb), stamp("2026-08-15T12:00:00.000000000Z"), 8);
        assert!(matches!(
            refused,
            Err(GitFactError::ObservationClockRegression)
        ));
        assert_eq!(log.observations().len(), 1, "nothing was appended");
    }

    #[test]
    fn identity_derivation_is_stable_across_repeated_calls() {
        let fact = commit_fact();
        assert_eq!(
            fact.provider_object_id().unwrap(),
            fact.provider_object_id().unwrap()
        );
        assert_eq!(
            fact.logical_event_key().unwrap(),
            fact.logical_event_key().unwrap()
        );
        assert_eq!(
            fact.canonical_payload().unwrap(),
            fact.canonical_payload().unwrap()
        );
    }

    #[test]
    fn the_three_families_never_share_a_logical_event_key() {
        let mut log = GitRefObservationLogV1::new(
            repository(),
            GitRefName::parse("refs/heads/main").unwrap(),
            ContractId::new("connector.git.instance-1").unwrap(),
        )
        .unwrap();
        log.observe(oid(0x11), stamp("2026-08-15T12:00:00.000000000Z"), 8)
            .unwrap();
        let keys = [
            commit_fact().logical_event_key().unwrap(),
            blob_fact(b"a.txt", 0x44).logical_event_key().unwrap(),
            GitFactV1::RefObservation(log.observations()[0].clone())
                .logical_event_key()
                .unwrap(),
        ];
        for (index, left) in keys.iter().enumerate() {
            for right in keys.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
    }
}
