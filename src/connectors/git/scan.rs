//! Reading the LOCAL git object store (W2-GIT).
//!
//! # Why a `git` subprocess rather than a library
//!
//! The alternative considered was the `gix` crate. It was rejected for this
//! wave on one hard constraint and one soft one. The hard constraint: adding
//! `gix` means adding a large new dependency tree to `Cargo.toml`/`Cargo.lock`,
//! which this workstream may not do. The soft one: the plumbing commands used
//! here (`show-ref`, `rev-list`, `cat-file`, `diff-tree`) have a stable,
//! documented, byte-oriented output contract that has not changed in a decade,
//! whereas a library binding would put object-format parsing — including future
//! SHA-256 repositories — inside this crate. `git` already knows how to read
//! both object formats; this module only has to know how to read `git`.
//!
//! # What "reading the local store" is allowed to mean
//!
//! Only reads, and only local ones. Every invocation is given an explicit
//! `--git-dir`, has its configuration sources neutralized, and has interactive
//! prompting and credential helpers disabled, so a scanned repository cannot
//! use its own configuration to make this process fetch, run a hook, or ask a
//! human for a password. Ref names reach argv only after
//! [`GitRefName::parse`](super::fact::GitRefName::parse) has refused anything
//! that could be read as an option, and object ids reach argv only as validated
//! lowercase hex.

use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::DateTime;

use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, HexBytes};

use super::error::{GitScanError, GitScanResult};
use super::fact::{
    GIT_FACT_SCHEMA_VERSION, GitBlobSourceFactV1, GitCommitFactV1, GitFactV1, GitFileModeV1,
    GitIdentityV1, GitObjectId, GitRefName, GitRepositoryIdV1,
};

/// Largest stdout this reader accepts from one `git` invocation.
const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Bound on captured standard-error text in an error message.
const MAX_STDERR_TEXT_BYTES: usize = 512;

/// How much of a commit's content this scan renders as blob-source facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitTreeScanModeV1 {
    /// Render no blob-source facts: commits and ref observations only.
    CommitsOnly,
    /// Render one blob-source fact per path the commit added or modified
    /// relative to its first parent (or, for a root commit, relative to the
    /// empty tree).
    ChangedPaths,
}

/// One bounded scan request against one ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitScanRequestV1 {
    /// The fully qualified ref to observe and walk.
    pub ref_name: GitRefName,
    /// Hard bound on commits walked. A walk that would exceed it fails closed
    /// rather than silently truncating history.
    pub max_commits: usize,
    /// Hard bound on total facts rendered.
    pub max_facts: usize,
    /// How much of each commit's content to render.
    pub tree_mode: GitTreeScanModeV1,
}

/// What one scan read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitScanV1 {
    /// The ref the scan observed.
    pub ref_name: GitRefName,
    /// The object the ref pointed at when read.
    pub target: GitObjectId,
    /// Commit and blob-source facts, oldest commit first.
    pub facts: Vec<GitFactV1>,
    /// Commit ids walked, oldest first.
    pub commits: Vec<GitObjectId>,
}

/// A read-only reader bound to one local repository directory.
#[derive(Debug, Clone)]
pub struct GitRepositoryReader {
    git_dir: PathBuf,
    program: PathBuf,
    repository: GitRepositoryIdV1,
}

impl GitRepositoryReader {
    /// Bind a reader to one `--git-dir` and one repository identity.
    ///
    /// `program` defaults to `git` on `PATH` when `None`.
    pub fn new(
        git_dir: impl AsRef<Path>,
        repository: GitRepositoryIdV1,
        program: Option<PathBuf>,
    ) -> GitScanResult<Self> {
        repository.validate()?;
        Ok(Self {
            git_dir: git_dir.as_ref().to_path_buf(),
            program: program.unwrap_or_else(|| PathBuf::from("git")),
            repository,
        })
    }

    /// The repository identity every fact this reader produces carries.
    #[must_use]
    pub const fn repository(&self) -> &GitRepositoryIdV1 {
        &self.repository
    }

    /// Every fully qualified ref this repository currently has, sorted.
    pub fn list_refs(&self) -> GitScanResult<Vec<(GitRefName, GitObjectId)>> {
        let stdout = self.run(
            "for-each-ref",
            &["for-each-ref", "--format=%(objectname) %(refname)"],
        )?;
        let mut refs = Vec::new();
        for line in stdout.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(line).map_err(|_| GitScanError::Output {
                command: "for-each-ref",
                detail: "ref line is not UTF-8",
            })?;
            let (oid, name) = text.split_once(' ').ok_or(GitScanError::Output {
                command: "for-each-ref",
                detail: "ref line has no separator",
            })?;
            refs.push((GitRefName::parse(name)?, GitObjectId::parse_hex(oid)?));
        }
        refs.sort();
        Ok(refs)
    }

    /// Read where one ref points right now.
    pub fn resolve_ref(&self, ref_name: &GitRefName) -> GitScanResult<GitObjectId> {
        let stdout = self.run(
            "show-ref",
            &["show-ref", "--verify", "--", ref_name.as_str()],
        )?;
        let text = std::str::from_utf8(&stdout).map_err(|_| GitScanError::Output {
            command: "show-ref",
            detail: "ref line is not UTF-8",
        })?;
        let oid = text.split_whitespace().next().ok_or(GitScanError::Output {
            command: "show-ref",
            detail: "ref line is empty",
        })?;
        Ok(GitObjectId::parse_hex(oid)?)
    }

    /// Walk one ref and render its commit and blob-source facts.
    pub fn scan(&self, request: &GitScanRequestV1) -> GitScanResult<GitScanV1> {
        let target = self.resolve_ref(&request.ref_name)?;
        let commits = self.rev_list(&target, request.max_commits)?;
        let mut facts = Vec::new();
        for commit_id in &commits {
            let commit = self.read_commit(commit_id)?;
            let committed_at = commit.committer.at.clone();
            let tree_id = commit.tree_id.clone();
            facts.push(GitFactV1::Commit(commit));
            if request.tree_mode == GitTreeScanModeV1::ChangedPaths {
                for entry in self.changed_paths(commit_id)? {
                    facts.push(GitFactV1::BlobSource(GitBlobSourceFactV1 {
                        schema_version: GIT_FACT_SCHEMA_VERSION,
                        repository: self.repository.clone(),
                        commit_id: commit_id.clone(),
                        tree_id: tree_id.clone(),
                        path: entry.path,
                        mode: entry.mode,
                        byte_length: self.blob_size(&entry.blob_id)?,
                        blob_id: entry.blob_id,
                        committed_at: committed_at.clone(),
                    }));
                }
            }
            if facts.len() > request.max_facts {
                return Err(GitScanError::ScanTooLarge(request.max_facts));
            }
        }
        for fact in &facts {
            fact.validate()?;
        }
        Ok(GitScanV1 {
            ref_name: request.ref_name.clone(),
            target,
            facts,
            commits,
        })
    }

    /// Commit ids reachable from `target`, oldest first.
    fn rev_list(
        &self,
        target: &GitObjectId,
        max_commits: usize,
    ) -> GitScanResult<Vec<GitObjectId>> {
        let peeled = format!("{}^{{commit}}", target.to_hex());
        // One more than the bound, so an over-long history is detected rather
        // than silently truncated to the bound.
        let limit = format!("--max-count={}", max_commits.saturating_add(1));
        let stdout = self.run(
            "rev-list",
            &[
                "rev-list",
                "--topo-order",
                "--reverse",
                &limit,
                "--end-of-options",
                &peeled,
            ],
        )?;
        let mut commits = Vec::new();
        for line in stdout.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(line).map_err(|_| GitScanError::Output {
                command: "rev-list",
                detail: "commit id is not UTF-8",
            })?;
            commits.push(GitObjectId::parse_hex(text)?);
        }
        if commits.len() > max_commits {
            return Err(GitScanError::ScanTooLarge(max_commits));
        }
        Ok(commits)
    }

    fn read_commit(&self, commit_id: &GitObjectId) -> GitScanResult<GitCommitFactV1> {
        let hex = commit_id.to_hex();
        let object = self.run("cat-file", &["cat-file", "commit", &hex])?;
        let parsed = parse_commit_object(&object)?;
        Ok(GitCommitFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: self.repository.clone(),
            commit_id: commit_id.clone(),
            tree_id: parsed.tree_id,
            parents: parsed.parents,
            author: parsed.author,
            committer: parsed.committer,
            message: parsed.message,
            ancestry: super::fact::GitAncestryClaimV1::RecordedParents,
            // Turn linkage is supplied by whoever declares it, not discovered
            // here: this connector reads an object store and has no evidence
            // that any agent turn produced any commit.
            declared_links: Vec::new(),
        })
    }

    fn changed_paths(&self, commit_id: &GitObjectId) -> GitScanResult<Vec<ChangedPath>> {
        let hex = commit_id.to_hex();
        let stdout = self.run(
            "diff-tree",
            &[
                "diff-tree",
                "-r",
                "-z",
                "--root",
                "--no-commit-id",
                "--no-renames",
                "--diff-filter=AM",
                "--end-of-options",
                &hex,
            ],
        )?;
        parse_diff_tree(&stdout)
    }

    fn blob_size(&self, blob_id: &GitObjectId) -> GitScanResult<CanonicalDecimal> {
        let hex = blob_id.to_hex();
        let stdout = self.run("cat-file", &["cat-file", "-s", &hex])?;
        let text = std::str::from_utf8(&stdout)
            .map_err(|_| GitScanError::Output {
                command: "cat-file",
                detail: "blob size is not UTF-8",
            })?
            .trim();
        text.parse::<u64>().map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "blob size is not an integer",
        })?;
        CanonicalDecimal::parse(text.to_owned()).map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "blob size is not a canonical decimal",
        })
    }

    fn run(&self, label: &'static str, args: &[&str]) -> GitScanResult<Vec<u8>> {
        let mut command = Command::new(&self.program);
        command
            .arg("--no-optional-locks")
            .arg(format!("--git-dir={}", self.git_dir.display()))
            .args(args)
            // A scanned repository must not be able to use its own or the
            // host's configuration to make this process fetch, run a hook, or
            // prompt a human.
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "true")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_NAMESPACE")
            .env_remove("GIT_CEILING_DIRECTORIES")
            .env_remove("GIT_EXTERNAL_DIFF")
            .env_remove("GIT_ATTR_NOSYSTEM");
        let output = command
            .output()
            .map_err(|error| GitScanError::Spawn(error.to_string()))?;
        if !output.status.success() {
            let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            stderr.truncate(MAX_STDERR_TEXT_BYTES);
            return Err(GitScanError::Command {
                command: label,
                status: output.status.to_string(),
                stderr,
            });
        }
        if output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
            return Err(GitScanError::Output {
                command: label,
                detail: "output exceeded the reader's bound",
            });
        }
        Ok(output.stdout)
    }
}

/// One added-or-modified tree entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChangedPath {
    path: HexBytes,
    mode: GitFileModeV1,
    blob_id: GitObjectId,
}

/// Parsed fields of one commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCommit {
    tree_id: GitObjectId,
    parents: Vec<GitObjectId>,
    author: GitIdentityV1,
    committer: GitIdentityV1,
    message: HexBytes,
}

/// Parse `git cat-file commit <id>` output.
///
/// The object is bytes, not text: only the header keys and object ids are
/// required to be ASCII. Names, emails, and the message are copied through
/// unchanged.
fn parse_commit_object(object: &[u8]) -> GitScanResult<ParsedCommit> {
    let split = find_header_end(object).ok_or(GitScanError::Output {
        command: "cat-file",
        detail: "commit object has no header terminator",
    })?;
    let (headers, message) = object.split_at(split);
    // `find_header_end` keeps the header block's trailing newline, so the
    // remainder opens with the blank line that separates headers from message.
    let message = message.strip_prefix(b"\n").unwrap_or(message);

    let mut tree_id = None;
    let mut parents = Vec::new();
    let mut author = None;
    let mut committer = None;
    for line in headers.split(|byte| *byte == b'\n') {
        // Continuation lines of multi-line headers (a PGP signature, for
        // example) start with a space and carry no key of their own.
        if line.is_empty() || line.starts_with(b" ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix(b"tree ") {
            tree_id = Some(parse_hex_field(rest, "tree")?);
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            parents.push(parse_hex_field(rest, "parent")?);
        } else if let Some(rest) = line.strip_prefix(b"author ") {
            author = Some(parse_identity(rest)?);
        } else if let Some(rest) = line.strip_prefix(b"committer ") {
            committer = Some(parse_identity(rest)?);
        }
    }

    Ok(ParsedCommit {
        tree_id: tree_id.ok_or(GitScanError::Output {
            command: "cat-file",
            detail: "commit object has no tree header",
        })?,
        parents,
        author: author.ok_or(GitScanError::Output {
            command: "cat-file",
            detail: "commit object has no author header",
        })?,
        committer: committer.ok_or(GitScanError::Output {
            command: "cat-file",
            detail: "commit object has no committer header",
        })?,
        message: HexBytes::new(if message.is_empty() {
            b"\n".to_vec()
        } else {
            message.to_vec()
        })
        .map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "commit message exceeds the connector's bound",
        })?,
    })
}

fn find_header_end(object: &[u8]) -> Option<usize> {
    object
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| index + 1)
}

fn parse_hex_field(value: &[u8], detail: &'static str) -> GitScanResult<GitObjectId> {
    let _ = detail;
    let text = std::str::from_utf8(value).map_err(|_| GitScanError::Output {
        command: "cat-file",
        detail: "object id field is not UTF-8",
    })?;
    Ok(GitObjectId::parse_hex(text.trim())?)
}

/// Parse `Name <email> <unix seconds> <±HHMM>` from a commit header value.
fn parse_identity(value: &[u8]) -> GitScanResult<GitIdentityV1> {
    let unparseable = GitScanError::Output {
        command: "cat-file",
        detail: "identity header is not name <email> seconds offset",
    };
    let email_open = value
        .iter()
        .rposition(|byte| *byte == b'<')
        .ok_or(GitScanError::Output {
            command: "cat-file",
            detail: "identity header has no email",
        })?;
    let email_close = value
        .iter()
        .rposition(|byte| *byte == b'>')
        .ok_or(GitScanError::Output {
            command: "cat-file",
            detail: "identity header has no email",
        })?;
    if email_close < email_open {
        return Err(unparseable);
    }
    let name = value[..email_open]
        .strip_suffix(b" ")
        .unwrap_or(&value[..email_open]);
    let email = &value[email_open + 1..email_close];
    let clock = std::str::from_utf8(&value[email_close + 1..])
        .map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "identity clock is not UTF-8",
        })?
        .trim();
    let (seconds, offset) = clock.split_once(' ').ok_or(GitScanError::Output {
        command: "cat-file",
        detail: "identity clock has no offset",
    })?;
    let seconds: i64 = seconds.parse().map_err(|_| GitScanError::Timestamp)?;
    let at = DateTime::from_timestamp(seconds, 0).ok_or(GitScanError::Timestamp)?;
    Ok(GitIdentityV1 {
        name: HexBytes::new(if name.is_empty() {
            b" ".to_vec()
        } else {
            name.to_vec()
        })
        .map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "identity name exceeds the connector's bound",
        })?,
        email: HexBytes::new(if email.is_empty() {
            b" ".to_vec()
        } else {
            email.to_vec()
        })
        .map_err(|_| GitScanError::Output {
            command: "cat-file",
            detail: "identity email exceeds the connector's bound",
        })?,
        at: CanonicalTimestamp::from_datetime(&at).map_err(|_| GitScanError::Timestamp)?,
        utc_offset_minutes: parse_utc_offset(offset)?,
    })
}

fn parse_utc_offset(value: &str) -> GitScanResult<i32> {
    let unparseable = GitScanError::Output {
        command: "cat-file",
        detail: "identity offset is not ±HHMM",
    };
    let (sign, digits) = match value.as_bytes().first() {
        Some(b'+') => (1, &value[1..]),
        Some(b'-') => (-1, &value[1..]),
        _ => return Err(unparseable),
    };
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(unparseable);
    }
    let hours: i32 = digits[..2].parse().map_err(|_| GitScanError::Timestamp)?;
    let minutes: i32 = digits[2..].parse().map_err(|_| GitScanError::Timestamp)?;
    Ok(sign * (hours * 60 + minutes))
}

/// Parse NUL-separated `git diff-tree -r -z` raw output.
///
/// Records that do not begin with `:` are skipped rather than guessed at, so a
/// leading commit id (which `--no-commit-id` should already suppress) cannot be
/// mistaken for a tree entry.
fn parse_diff_tree(stdout: &[u8]) -> GitScanResult<Vec<ChangedPath>> {
    let unparseable = GitScanError::Output {
        command: "diff-tree",
        detail: "raw record is not :srcmode dstmode srcsha dstsha status",
    };
    let mut entries = Vec::new();
    let mut tokens = stdout
        .split(|byte| *byte == b'\0')
        .filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        if !token.starts_with(b":") {
            continue;
        }
        let meta = std::str::from_utf8(&token[1..]).map_err(|_| GitScanError::Output {
            command: "diff-tree",
            detail: "raw record is not UTF-8",
        })?;
        let fields: Vec<&str> = meta.split_whitespace().collect();
        let [_src_mode, dst_mode, _src_sha, dst_sha, _status] = fields.as_slice() else {
            return Err(unparseable);
        };
        let path = tokens.next().ok_or(GitScanError::Output {
            command: "diff-tree",
            detail: "raw record has no path",
        })?;
        // A gitlink or a tree is not blob content; skip rather than mint a
        // blob-source fact for something that has no blob.
        let Ok(mode) = GitFileModeV1::parse(dst_mode) else {
            continue;
        };
        entries.push(ChangedPath {
            path: HexBytes::new(path.to_vec()).map_err(|_| GitScanError::Output {
                command: "diff-tree",
                detail: "path exceeds the connector's bound",
            })?,
            mode,
            blob_id: GitObjectId::parse_hex(dst_sha)?,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT_OBJECT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
parent 1111111111111111111111111111111111111111\n\
author Ada Lovelace <ada@example.test> 1755259200 +0000\n\
committer Ada Lovelace <ada@example.test> 1755259260 -0530\n\
\n\
subject line\n\nbody line\n";

    #[test]
    fn a_commit_object_parses_into_provider_truth() {
        let parsed = parse_commit_object(COMMIT_OBJECT).unwrap();
        assert_eq!(
            parsed.tree_id.to_hex(),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        assert_eq!(parsed.parents.len(), 1);
        assert_eq!(parsed.author.name.as_bytes(), b"Ada Lovelace");
        assert_eq!(parsed.author.email.as_bytes(), b"ada@example.test");
        assert_eq!(parsed.author.utc_offset_minutes, 0);
        assert_eq!(parsed.committer.utc_offset_minutes, -330);
        assert_eq!(parsed.message.as_bytes(), b"subject line\n\nbody line\n");
    }

    #[test]
    fn a_multi_line_signature_header_does_not_become_a_parent() {
        let signed: Vec<u8> = [
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".as_slice(),
            b"gpgsig -----BEGIN PGP SIGNATURE-----\n".as_slice(),
            b" parent 2222222222222222222222222222222222222222\n".as_slice(),
            b" -----END PGP SIGNATURE-----\n".as_slice(),
            b"author A <a@b.test> 1755259200 +0000\n".as_slice(),
            b"committer A <a@b.test> 1755259200 +0000\n".as_slice(),
            b"\nmessage\n".as_slice(),
        ]
        .concat();
        let parsed = parse_commit_object(&signed).unwrap();
        assert!(
            parsed.parents.is_empty(),
            "a continuation line is not a header"
        );
    }

    #[test]
    fn an_oversized_commit_message_is_refused_rather_than_truncated() {
        let mut object = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author A <a@b.test> 1755259200 +0000\n\
committer A <a@b.test> 1755259200 +0000\n\n"
            .to_vec();
        object.extend(std::iter::repeat_n(
            b'x',
            super::super::fact::MAX_GIT_MESSAGE_BYTES + 1,
        ));
        assert!(matches!(
            parse_commit_object(&object),
            Err(GitScanError::Output { .. })
        ));
    }

    #[test]
    fn a_commit_object_without_a_committer_is_refused() {
        let broken = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author A <a@b.test> 1755259200 +0000\n\
\nmessage\n";
        assert!(parse_commit_object(broken).is_err());
    }

    #[test]
    fn a_non_utf8_name_survives_as_bytes() {
        let object: Vec<u8> = [
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".as_slice(),
            b"author \xff\xfe <a@b.test> 1755259200 +0000\n".as_slice(),
            b"committer \xff\xfe <a@b.test> 1755259200 +0000\n".as_slice(),
            b"\nmessage\n".as_slice(),
        ]
        .concat();
        let parsed = parse_commit_object(&object).unwrap();
        assert_eq!(parsed.author.name.as_bytes(), b"\xff\xfe");
    }

    #[test]
    fn utc_offsets_parse_only_in_the_exact_form() {
        assert_eq!(parse_utc_offset("+0000").unwrap(), 0);
        assert_eq!(parse_utc_offset("+0530").unwrap(), 330);
        assert_eq!(parse_utc_offset("-0800").unwrap(), -480);
        for bad in ["0000", "+00:00", "+000", "+00000", "+abcd", ""] {
            assert!(parse_utc_offset(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn diff_tree_records_parse_and_skip_non_blob_modes() {
        let stdout: Vec<u8> = [
            b":000000 100644 0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 A\0".as_slice(),
            b"README.md\0".as_slice(),
            b":000000 160000 0000000000000000000000000000000000000000 2222222222222222222222222222222222222222 A\0".as_slice(),
            b"vendor/sub\0".as_slice(),
            b":100644 100755 3333333333333333333333333333333333333333 4444444444444444444444444444444444444444 M\0".as_slice(),
            b"run.sh\0".as_slice(),
        ]
        .concat();
        let entries = parse_diff_tree(&stdout).unwrap();
        assert_eq!(entries.len(), 2, "the gitlink is not blob content");
        assert_eq!(entries[0].path.as_bytes(), b"README.md");
        assert_eq!(entries[0].mode, GitFileModeV1::Regular);
        assert_eq!(entries[1].mode, GitFileModeV1::Executable);
    }

    #[test]
    fn a_path_with_a_newline_survives_nul_separated_parsing() {
        let stdout: Vec<u8> = [
            b":000000 100644 0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 A\0".as_slice(),
            b"weird\nname.txt\0".as_slice(),
        ]
        .concat();
        let entries = parse_diff_tree(&stdout).unwrap();
        assert_eq!(entries[0].path.as_bytes(), b"weird\nname.txt");
    }

    #[test]
    fn a_truncated_diff_tree_record_is_refused() {
        let stdout = b":000000 100644 0000 A\0path\0".to_vec();
        assert!(parse_diff_tree(&stdout).is_err());
    }
}
