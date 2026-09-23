//! The enumeration algorithm, and the exhaustiveness verdict it owes (W3-OBSRT).
//!
//! # Why the algorithm is part of the receipt
//!
//! `mcp.remember.allowed_actions` is a claim about a closed set. A run that
//! answers "`deploy` is not an allowed action" is asserting that it saw the
//! whole set — and that assertion is only as good as the reader that produced
//! it. So this module never returns a bare list of variants. It returns a
//! [`RustEnumEnumerationV1`] that carries, alongside the members it found, the
//! algorithm it ran and every construct it met that it cannot prove it
//! understood. [`RustEnumEnumerationV1::exhaustive`] is false whenever that
//! diagnostic list is non-empty, and a non-exhaustive enumeration can never
//! reach a verified negative anywhere downstream.
//!
//! # What it refuses outright
//!
//! Locating the wrong item is worse than failing, so three cases are hard
//! errors rather than diagnostics:
//!
//! * the enum does not occur exactly once at module level (zero and two are
//!   the same refusal: "not found" must never become "not there", and "found
//!   two" must never become "picked one");
//! * its body is unterminated;
//! * it declares one variant name twice.
//!
//! # What it records as a diagnostic
//!
//! Everything that makes the *set* uncertain without making the *read*
//! impossible: `#[non_exhaustive]`, any non-doc attribute on the enum or on a
//! variant (a `#[cfg]` gate is the archetype — the variant list then depends
//! on a configuration this reader never evaluated), a macro invocation inside
//! the body, a variant carrying a payload, a variant shape the scanner does
//! not recognise, source whose braces the reader cannot balance, and hitting
//! the caller's member bound. Each is a
//! [`ContractId`] under the `enumeration.` prefix, registered on the
//! admission's
//! [`ObserverEnumerationAlgorithmV1`](crate::memory_contracts::observer::ObserverEnumerationAlgorithmV1)
//! so the closed set of things this observer knows it might not understand is
//! itself governance, not a runtime surprise.
//!
//! # The scanner
//!
//! A byte scanner over UTF-8 source that tracks line comments, nested block
//! comments, string, raw-string, byte-string and character literals, so a
//! `}` inside `"…"` or `/* … */` never closes a body and an `enum` inside a
//! comment is never located. It deliberately is not a Rust parser: a parser
//! would need the whole grammar to be trustworthy, whereas a scanner only
//! needs to be honest about what it skipped — which is exactly what the
//! diagnostics are.
//!
//! It also consumes each `#[…]` attribute group as ONE token, and it is the
//! only tokenizer in this module: every brace-depth counter here is driven by
//! it. That is a soundness property rather than a convenience. An attribute's
//! token tree may legally contain `{`, `}` and `;`, so a counter that sees
//! those bytes and a counter that steps over the group have two different
//! structural models of the same file — and the file is a blob the observer
//! does not control, so how far apart they drift is the blob's choice, not the
//! reader's. One tokenizer means there is no second model to steer.
//!
//! # What it cannot promise
//!
//! The reader raises a caveat for every case where it can PROVE its own model
//! of the file is inconsistent: a `}` closing a body it never saw opened,
//! braces still open at end of file, a comment or literal that ran off the end,
//! an attribute whose token tree does not nest. It cannot raise one where its
//! model is merely WEAKER than Rust's grammar. An author willing to make the
//! file uncompilable can still satisfy this scanner while meaning something
//! else to rustc: splice a `}` into the enum body to end it early and a `{`
//! further down to rebalance the file, and the braces nest, nothing runs off
//! the end, no token tree is malformed, and the short member list is one this
//! reader cannot tell from a true one. Closing that needs a parser, and a
//! parser needs the whole grammar to be trustworthy.
//!
//! So the honest statement of the guarantee is: an exhaustive read means the
//! reader found no evidence that it misread the file — not that no such
//! evidence could exist. What it does guarantee unconditionally is internal
//! consistency. There is one tokenization here, so no two parts of this reader
//! can be steered into disagreeing about the same bytes, which is a different
//! and much weaker thing to have to trust than a grammar.

use std::collections::BTreeSet;

use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};

use super::error::{ObserverRuntimeError, ObserverRuntimeResult};

/// Identity of the algorithm this module implements.
///
/// It is part of the admission body, so changing the scanner means a new
/// algorithm id and a new governance decision, not a silent behaviour change
/// under the same one.
///
/// `.v3` makes a `#[…]` group a single token in the one scanner every depth
/// counter in this module is driven by. `.v2` had already taught the attribute
/// reader to step over whole groups, but left the declaration locator, the body
/// finder and the variant splitter counting the `{` and `}` inside an
/// attribute's token tree. Those are two structural models of the same bytes,
/// and an attribute carrying a net-negative brace count (`#[doc( } )]`) drives
/// them apart: far enough to drop a `#[non_exhaustive]` off the enum, and one
/// layer down to close the body early and lose every variant after it — both
/// with no diagnostic, so both exhaustive. `.v3` also records, rather than
/// silently absorbs, each point where the reader's structural model diverges
/// from the bytes.
///
/// `.v2` located an item's attributes by walking whole `#[…]` groups rather
/// than by hunting backwards for the previous item's `}` or `;`. The `.v1`
/// reader could have its attribute search truncated by a `{`, `}` or `;`
/// inside a preceding attribute's token tree and would then report NO
/// attributes at all — losing a `#[non_exhaustive]` or a `#[cfg]` and calling
/// the read exhaustive. Two readers that disagree about whether a blob is
/// exhaustively enumerable are two different algorithms, so they get two
/// different ids.
pub const ENUMERATION_ALGORITHM_ID: &str = "enumeration.rust-enum-brace-scan.v3";

/// The enum declares `#[non_exhaustive]`, so the source itself says the set is
/// open.
pub const DIAGNOSTIC_NON_EXHAUSTIVE: &str = "enumeration.enum.non-exhaustive";
/// A non-doc attribute sits on the enum (a `#[cfg]` gate, most importantly).
pub const DIAGNOSTIC_ENUM_ATTRIBUTE: &str = "enumeration.enum.attribute";
/// The enum takes generic parameters, so "the variants" is not one set.
pub const DIAGNOSTIC_ENUM_GENERIC: &str = "enumeration.enum.generic";
/// A non-doc attribute sits on a variant.
pub const DIAGNOSTIC_VARIANT_ATTRIBUTE: &str = "enumeration.variant.attribute";
/// A macro invocation appears inside the body, so variants may be generated.
pub const DIAGNOSTIC_MACRO_UNRESOLVED: &str = "enumeration.macro.unresolved";
/// A variant carries a payload, so its members are not plain names.
pub const DIAGNOSTIC_VARIANT_PAYLOAD: &str = "enumeration.variant.payload";
/// A variant's shape is not one this scanner recognises.
pub const DIAGNOSTIC_VARIANT_UNRECOGNISED: &str = "enumeration.variant.unrecognised";
/// The caller's member bound was reached, so the read stopped early.
pub const DIAGNOSTIC_BOUND_EXCEEDED: &str = "enumeration.bound.exceeded";
/// The reader's brace model of the source does not balance.
///
/// A `}` closing a body the reader never saw opened, an attribute group it
/// could not step over, braces still open at end of file, or a comment or
/// literal that ran off the end of the file. Any of them
/// means the reader's structural model of the file has parted company with the
/// bytes, and an item read out of a file the reader cannot structure is an item
/// whose extent is a guess. It is deliberately file-wide and deliberately not
/// scoped to "after the item": a `}` spliced into an enum body closes that body
/// where the compiler would not, and the over-close that proves the file is
/// unbalanced only arrives later.
pub const DIAGNOSTIC_SOURCE_UNBALANCED: &str = "enumeration.source.unbalanced";

/// Every diagnostic this algorithm can raise, in `ContractId` sort order.
///
/// The admission registers exactly this set; a run that raised a diagnostic
/// outside it would be claiming an exhaustiveness caveat governance never saw.
pub const ALL_DIAGNOSTICS: [&str; 9] = [
    DIAGNOSTIC_BOUND_EXCEEDED,
    DIAGNOSTIC_ENUM_ATTRIBUTE,
    DIAGNOSTIC_ENUM_GENERIC,
    DIAGNOSTIC_NON_EXHAUSTIVE,
    DIAGNOSTIC_MACRO_UNRESOLVED,
    DIAGNOSTIC_SOURCE_UNBALANCED,
    DIAGNOSTIC_VARIANT_ATTRIBUTE,
    DIAGNOSTIC_VARIANT_PAYLOAD,
    DIAGNOSTIC_VARIANT_UNRECOGNISED,
];

/// Widest member bound a caller may configure.
pub const MAX_MEMBER_BOUND: usize = 4096;

/// What one enumeration read, and what it could not prove it understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustEnumEnumerationV1 {
    /// The enum the predicate names.
    enum_name: String,
    /// Variant names in declaration order.
    members: Vec<String>,
    /// Every diagnostic raised, strictly sorted and deduplicated.
    diagnostics: Vec<ContractId>,
    /// Bytes of source the scanner consumed to reach the closing brace.
    scanned_bytes: u64,
}

impl RustEnumEnumerationV1 {
    /// The enum this enumeration is about.
    #[must_use]
    pub fn enum_name(&self) -> &str {
        &self.enum_name
    }

    /// Variant names in declaration order.
    #[must_use]
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// Every exhaustiveness caveat this read raised.
    #[must_use]
    pub fn diagnostics(&self) -> &[ContractId] {
        &self.diagnostics
    }

    /// Bytes consumed reaching the closing brace.
    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    /// Whether this read enumerated the whole input domain.
    ///
    /// Exactly "no diagnostics were raised". There is deliberately no way to
    /// set this independently of the diagnostic list: an exhaustiveness claim
    /// and the reasons it might be wrong are one value, so a caller cannot
    /// keep the claim and drop the reasons.
    #[must_use]
    pub const fn exhaustive(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Whether `member` is among the variants this read found.
    #[must_use]
    pub fn contains(&self, member: &str) -> bool {
        self.members.iter().any(|found| found == member)
    }

    /// Exact output identity of this read.
    ///
    /// Frames the algorithm id, the exhaustiveness verdict, every diagnostic,
    /// and every member, so two reads that disagree about ANY of those — not
    /// only about the member list — produce different digests. A read that
    /// found the same members while silently dropping a `#[cfg]` caveat is a
    /// different output, and the receipt says so.
    #[must_use]
    pub fn output_digest(&self) -> Sha256Digest {
        let verdict: &[u8] = if self.exhaustive() {
            b"exhaustive"
        } else {
            b"non-exhaustive"
        };
        let mut parts: Vec<&[u8]> =
            Vec::with_capacity(self.diagnostics.len() + self.members.len() + 4);
        parts.push(ENUMERATION_ALGORITHM_ID.as_bytes());
        parts.push(self.enum_name.as_bytes());
        parts.push(verdict);
        parts.push(b"diagnostics");
        parts.extend(self.diagnostics.iter().map(|id| id.as_str().as_bytes()));
        parts.push(b"members");
        parts.extend(self.members.iter().map(String::as_bytes));
        framed_digest(DigestDomain::ObserverRunOutputV1, &parts)
    }
}

/// Enumerate one module-level Rust enum out of `source`.
///
/// `member_bound` is a hard cap on how many variants the read will accept.
/// Reaching it raises [`DIAGNOSTIC_BOUND_EXCEEDED`] and stops, which makes the
/// enumeration non-exhaustive — this is the honest way to model a reader that
/// ran out of budget, and it is also how a caller deliberately produces a
/// partial read to prove that a partial read cannot verify a negative.
pub fn enumerate_rust_enum(
    source: &str,
    enum_name: &str,
    member_bound: usize,
) -> ObserverRuntimeResult<RustEnumEnumerationV1> {
    if member_bound == 0 || member_bound > MAX_MEMBER_BOUND {
        return Err(ObserverRuntimeError::InvalidMemberBound);
    }
    let bytes = source.as_bytes();
    let located = locate_declarations(bytes, enum_name);
    let [declaration] = located.declarations.as_slice() else {
        return Err(ObserverRuntimeError::EnumNotUnique {
            name: enum_name.to_owned(),
            found: located.declarations.len(),
        });
    };

    let mut diagnostics: BTreeSet<String> = BTreeSet::new();
    // The reader could not structure the file it read this item out of, so
    // where the item begins and ends is a guess — and a guessed extent cannot
    // support a claim to have seen the whole set.
    if located.unbalanced {
        diagnostics.insert(DIAGNOSTIC_SOURCE_UNBALANCED.to_owned());
    }
    if declaration.generic {
        diagnostics.insert(DIAGNOSTIC_ENUM_GENERIC.to_owned());
    }
    // An attribute region the reader could not close is an unproven attribute
    // list, and an unproven attribute list is a caveat, never a clean read.
    if declaration.attributes.unparseable {
        diagnostics.insert(DIAGNOSTIC_ENUM_ATTRIBUTE.to_owned());
    }
    for attribute in &declaration.attributes.names {
        if attribute == "non_exhaustive" {
            diagnostics.insert(DIAGNOSTIC_NON_EXHAUSTIVE.to_owned());
        } else if !attribute_preserves_the_set(attribute) {
            diagnostics.insert(DIAGNOSTIC_ENUM_ATTRIBUTE.to_owned());
        }
    }

    let body_end = find_body_end(bytes, declaration.body_start)
        .ok_or_else(|| ObserverRuntimeError::EnumBodyUnterminated(enum_name.to_owned()))?;
    let body = &source[declaration.body_start..body_end];

    let mut members: Vec<String> = Vec::new();
    for item in split_top_level(body) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if members.len() == member_bound {
            diagnostics.insert(DIAGNOSTIC_BOUND_EXCEEDED.to_owned());
            break;
        }
        let stripped = strip_leading_attributes(item, &mut diagnostics);
        let stripped = stripped.trim();
        if stripped.is_empty() {
            diagnostics.insert(DIAGNOSTIC_VARIANT_UNRECOGNISED.to_owned());
            continue;
        }
        let (name, rest) = split_identifier(stripped);
        if name.is_empty() {
            diagnostics.insert(DIAGNOSTIC_VARIANT_UNRECOGNISED.to_owned());
            continue;
        }
        classify_variant_tail(rest.trim(), &mut diagnostics);
        if members.iter().any(|existing| existing == name) {
            return Err(ObserverRuntimeError::DuplicateMember {
                enum_name: enum_name.to_owned(),
                member: name.to_owned(),
            });
        }
        members.push(name.to_owned());
    }

    let mut sorted = Vec::with_capacity(diagnostics.len());
    for id in diagnostics {
        sorted.push(ContractId::new(id)?);
    }
    Ok(RustEnumEnumerationV1 {
        enum_name: enum_name.to_owned(),
        members,
        diagnostics: sorted,
        scanned_bytes: u64::try_from(body_end).unwrap_or(u64::MAX),
    })
}

/// One located `enum <Name>` declaration.
#[derive(Debug)]
struct Declaration {
    /// Byte offset just after the opening `{`.
    body_start: usize,
    /// What the reader could determine about the preceding attribute list.
    attributes: AttributeScan,
    /// Whether the declaration carries generic parameters.
    generic: bool,
}

/// Every module-level `enum <name>` declaration, plus what the reader made of
/// the file it found them in.
struct LocatedDeclarations {
    /// The declarations, in source order.
    declarations: Vec<Declaration>,
    /// The reader's brace model of the whole file did not balance.
    ///
    /// Applied to every declaration, including ones located before the point
    /// the divergence became visible — see [`DIAGNOSTIC_SOURCE_UNBALANCED`].
    unbalanced: bool,
}

/// Find every module-level `enum <name>` declaration, and the attribute list
/// attached to each.
///
/// "Module level" is brace depth zero: an enum nested inside a `mod`, a
/// function, or an `impl` is not the item a top-level predicate is about, and
/// silently accepting one would let an unrelated shadowing definition answer
/// the question.
///
/// The attribute list is accumulated in this same pass, off this same depth
/// counter, deliberately. A second pass would be a second structural model of
/// the same bytes, and the two could be steered apart by an attribute whose
/// token tree carries an unbalanced brace: one reader placing the enum at
/// module level while the other placed itself inside a body and discarded every
/// attribute it then met — silently turning a `#[non_exhaustive]` enum into an
/// exhaustively enumerated one. There is one counter, so there is nothing to
/// desynchronise.
fn locate_declarations(bytes: &[u8], enum_name: &str) -> LocatedDeclarations {
    let mut found = Vec::new();
    let mut scanner = Scanner::new(bytes);
    let mut depth: i64 = 0;
    // Attributes met at module level since the previous item ended.
    let mut names: Vec<String> = Vec::new();
    // A `#` at module level that opened no group this reader could name.
    let mut unparseable = false;
    // The reader's structural model has parted company with the bytes: a `}`
    // that closed a body it never opened, or an attribute group it could not
    // step over. Nothing later undoes either, and the scan ends by checking the
    // braces closed at all, so this is a verdict about the whole file.
    let mut unbalanced = false;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => {
                depth -= 1;
                if depth < 0 {
                    // A close with no open. This is NOT an item boundary — the
                    // reader has no idea where it is — so it must not reset the
                    // item state the way a real one does. Clamping keeps the
                    // scan going; the flag keeps it honest.
                    depth = 0;
                    unbalanced = true;
                } else if depth == 0 {
                    // The previous item's body ended; its attributes are not
                    // this item's.
                    names.clear();
                    unparseable = false;
                }
            }
            Event::Attribute {
                inner_start,
                inner_end,
            } => {
                if depth == 0 {
                    names.push(attribute_name(&bytes[inner_start..inner_end]));
                }
            }
            Event::UnreadableAttribute => {
                // The file's structure is unproven from here on, and at item
                // level this item's attribute list is unproven with it: the
                // reader met an attribute and cannot say what it was.
                unbalanced = true;
                if depth == 0 {
                    unparseable = true;
                }
            }
            Event::Word { start, end } => {
                if depth != 0 || &bytes[start..end] != b"enum" {
                    continue;
                }
                let mut probe = Scanner::at(bytes, end);
                let Some(Event::Word {
                    start: name_start,
                    end: name_end,
                }) = probe.next_event()
                else {
                    continue;
                };
                if &bytes[name_start..name_end] != enum_name.as_bytes() {
                    continue;
                }
                let mut generic = false;
                let mut after = name_end;
                let tail = skip_trivia(bytes, name_end);
                if bytes.get(tail) == Some(&b'<') {
                    generic = true;
                    let Some(close) = find_generic_end(bytes, tail) else {
                        continue;
                    };
                    after = close;
                }
                let brace = skip_trivia(bytes, after);
                if bytes.get(brace) != Some(&b'{') {
                    continue;
                }
                found.push(Declaration {
                    body_start: brace + 1,
                    attributes: AttributeScan::of(&names, unparseable),
                    generic,
                });
            }
            Event::Other => {
                if depth != 0 {
                    continue;
                }
                match bytes[scanner.position() - 1] {
                    // A `#` the scanner did not resolve into a group opens no
                    // group at all, so it hides no structure — but at item
                    // level the reader still cannot say what attribute it
                    // began, and an attribute it cannot name is one whose
                    // effect on the variant set is unknown.
                    b'#' => unparseable = true,
                    b';' => {
                        names.clear();
                        unparseable = false;
                    }
                    _ => {}
                }
            }
        }
    }
    LocatedDeclarations {
        declarations: found,
        // Braces still open at end of file is the same divergence seen from the
        // other side: the reader believes it is inside a body the bytes never
        // closed.
        unbalanced: unbalanced || depth != 0 || scanner.truncated(),
    }
}

/// Attributes that provably cannot add or remove a variant.
///
/// This list is the whole basis on which an attribute passes without costing
/// the read its exhaustiveness, so it is short and explicit rather than a
/// pattern. `derive` expands to trait impls beside the item; `repr` changes
/// layout; `doc`, `allow`, `deny`, `warn`, `expect`, `must_use` and
/// `deprecated` are diagnostics-only; `serde` renames the wire form of
/// variants this algorithm identifies by their Rust names. None of them can
/// make a variant appear or disappear.
///
/// Everything else — `cfg`, `cfg_attr`, and in particular any attribute
/// proc-macro, which may rewrite the item wholesale — raises
/// [`DIAGNOSTIC_ENUM_ATTRIBUTE`] or [`DIAGNOSTIC_VARIANT_ATTRIBUTE`] and makes
/// the read non-exhaustive. Unknown means unproven, and unproven means "I do
/// not know", never "it is fine".
pub const SET_PRESERVING_ATTRIBUTES: [&str; 10] = [
    "allow",
    "deny",
    "deprecated",
    "derive",
    "doc",
    "expect",
    "must_use",
    "repr",
    "serde",
    "warn",
];

/// Whether an attribute name is one of the proven set-preserving ones.
fn attribute_preserves_the_set(name: &str) -> bool {
    SET_PRESERVING_ATTRIBUTES.contains(&name)
}

/// What the reader could determine about an item's attribute list.
#[derive(Debug)]
struct AttributeScan {
    /// Names of the attributes attached to the item, sorted and deduplicated.
    names: Vec<String>,
    /// The reader met an attribute, or a stretch of file structure, it could
    /// not parse to its end.
    ///
    /// This is never "no attributes". An attribute the reader cannot close, or
    /// chose not to read, is an attribute whose effect on the variant set is
    /// unknown — and unknown costs the read its exhaustiveness, which is the
    /// whole reason this flag exists.
    unparseable: bool,
}

impl AttributeScan {
    /// Snapshot the attribute state [`locate_declarations`] accumulated for one
    /// located item.
    fn of(names: &[String], unparseable: bool) -> Self {
        let mut names = names.to_vec();
        names.sort_unstable();
        names.dedup();
        Self { names, unparseable }
    }
}

/// What the reader made of a `#` sitting at `hash`.
///
/// The three cases are kept apart because they cost the read different things.
/// Only the middle one leaves the reader unable to say where the group ended,
/// and therefore unable to vouch for the structure of anything after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeRead {
    /// A whole `#[…]` group: the bounds of the token tree between the
    /// brackets, and the offset just past the closing `]`.
    Group {
        /// Inclusive start of the token tree.
        inner_start: usize,
        /// Exclusive end of the token tree.
        inner_end: usize,
        /// Offset just past the closing `]`.
        end: usize,
    },
    /// A `#[…]` this reader will not accept as an attribute: its `]` is
    /// missing, its delimiters do not nest, or what is between them is not
    /// shaped like an attribute. A refusal, not an empty result — the reader
    /// cannot step over the region, so every byte after it is being read as
    /// code the compiler may read as attribute tokens, or the other way round.
    Unreadable,
    /// A `#` that opens no bracket group at all. One byte, delimiting nothing,
    /// so it cannot move any depth counter — but it is also not an attribute
    /// this reader can name.
    NotAnAttribute,
}

/// Read one whole attribute whose `#` sits at `hash`.
fn read_attribute(bytes: &[u8], hash: usize) -> AttributeRead {
    let mut cursor = skip_trivia(bytes, hash + 1);
    // `#![...]` is the inner form. It attaches to the enclosing item rather
    // than the next one, but it is still a group that must be stepped over
    // whole, and naming it costs at worst one spurious caveat.
    if bytes.get(cursor) == Some(&b'!') {
        cursor = skip_trivia(bytes, cursor + 1);
    }
    if bytes.get(cursor) != Some(&b'[') {
        return AttributeRead::NotAnAttribute;
    }
    let Some(end) = attribute_group_end(bytes, cursor) else {
        return AttributeRead::Unreadable;
    };
    if !attribute_inner_is_well_formed(&bytes[cursor + 1..end - 1]) {
        return AttributeRead::Unreadable;
    }
    AttributeRead::Group {
        inner_start: cursor + 1,
        inner_end: end - 1,
        end,
    }
}

/// Whether the token tree between an attribute's brackets is shaped like an
/// attribute at all.
///
/// Rust's attribute grammar is small and fixed: a path, then nothing, or `= …`,
/// or exactly one delimited group running to the end. Checking it is worth the
/// dozen lines, because the alternative is stepping over a region that is not
/// an attribute at all. `#[doc` followed by three variants and a `]` nests
/// perfectly well; read as one group it swallows those variants, and the
/// shorter member list that comes back is indistinguishable from a true one.
/// Everything this function rejects the compiler rejects too, so a refusal here
/// is a proof rather than a guess — and it costs the read its exhaustiveness
/// rather than costing it a member.
fn attribute_inner_is_well_formed(inner: &[u8]) -> bool {
    let mut cursor = skip_trivia(inner, 0);
    // A path: one or more identifiers joined by `::`, so `#[rustfmt::skip]` and
    // `#[tokio::test]` read as the attributes they are.
    loop {
        let start = cursor;
        while inner
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
        cursor = skip_trivia(inner, cursor);
        if inner[cursor..].starts_with(b"::") {
            cursor = skip_trivia(inner, cursor + 2);
            continue;
        }
        break;
    }
    if cursor >= inner.len() {
        return true;
    }
    match inner[cursor] {
        // `#[doc = "…"]`. What the value MEANS is the compiler's business,
        // but its shape is not: `= …` takes one expression, and an expression
        // has no top-level comma. A spliced variant list does, which is the
        // whole trick — `#[doc =` opened ahead of three variants and closed
        // after them would otherwise be stepped over as one attribute.
        b'=' => !has_top_level_comma(&inner[cursor + 1..]),
        // `#[derive(…)]`, `#[bar {…}]`: exactly one delimited group, and it
        // must run to the end of the tree.
        b'(' | b'[' | b'{' => attribute_group_end(inner, cursor)
            .is_some_and(|end| skip_trivia(inner, end) >= inner.len()),
        _ => false,
    }
}

/// Whether a token tree carries a `,` outside every delimited group.
fn has_top_level_comma(bytes: &[u8]) -> bool {
    let mut scanner = Scanner::brackets_at(bytes, 0);
    let mut depth: i64 = 0;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => depth -= 1,
            Event::Other => match bytes[scanner.position() - 1] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b',' if depth == 0 => return true,
                _ => {}
            },
            Event::Word { .. } | Event::Attribute { .. } | Event::UnreadableAttribute => {}
        }
    }
    false
}

/// The leading path segment of an attribute's token tree.
fn attribute_name(inner: &[u8]) -> String {
    let text = String::from_utf8_lossy(inner);
    let trimmed = text.trim_start();
    let name_end = trimmed
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(trimmed.len());
    trimmed[..name_end].to_owned()
}

/// Offset just past the `]` that closes the bracket group opening at `open`.
///
/// Uses the [`Scanner`] in its bracket-matching mode, so a `]` inside a string,
/// a raw string, a character literal or a comment does not close the group.
/// This is the one caller that must see an attribute's own delimiters rather
/// than step over the group, which is why the mode exists; it is bounded by
/// that one group, so it is not a second model of module structure.
///
/// Every delimiter inside the group must nest: an attribute's contents are a
/// token tree, and a token tree whose `(`, `[` and `{` do not pair up is not
/// something the compiler will accept either. Refusing it here is a proof, not
/// a guess — and it matters, because a group like `#[doc(` … `]` that closes
/// its bracket while leaving its paren open would otherwise be stepped over
/// whole, swallowing whatever sits between the two.
fn attribute_group_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut scanner = Scanner::brackets_at(bytes, open);
    let mut delimiters: Vec<u8> = Vec::new();
    while let Some(event) = scanner.next_event() {
        let position = scanner.position();
        let closing = match event {
            Event::OpenBrace => {
                delimiters.push(b'}');
                continue;
            }
            Event::CloseBrace => b'}',
            Event::Other => match bytes[position - 1] {
                b'(' => {
                    delimiters.push(b')');
                    continue;
                }
                b'[' => {
                    delimiters.push(b']');
                    continue;
                }
                closing @ (b')' | b']') => closing,
                _ => continue,
            },
            Event::Word { .. } | Event::Attribute { .. } | Event::UnreadableAttribute => continue,
        };
        if delimiters.pop() != Some(closing) {
            return None;
        }
        if delimiters.is_empty() {
            return Some(position);
        }
    }
    None
}

/// Offset just past the `>` closing a generic parameter list opening at `open`.
fn find_generic_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_i64;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            b'{' => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

/// Offset of the `}` that closes a body opening at `body_start`.
fn find_body_end(bytes: &[u8], body_start: usize) -> Option<usize> {
    let mut scanner = Scanner::at(bytes, body_start);
    let mut depth: i64 = 0;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => {
                if depth == 0 {
                    return Some(scanner.position() - 1);
                }
                depth -= 1;
            }
            // An attribute group is one token, so a `}` inside its token tree
            // is not the brace that closes this body.
            Event::Word { .. }
            | Event::Other
            | Event::Attribute { .. }
            | Event::UnreadableAttribute => {}
        }
    }
    None
}

/// Split an enum body at its top-level commas.
fn split_top_level(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut scanner = Scanner::new(bytes);
    let mut items = Vec::new();
    let mut depth: i64 = 0;
    let mut start = 0;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => depth -= 1,
            Event::Other => {
                let position = scanner.position();
                let byte = bytes[position - 1];
                match byte {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b',' if depth == 0 => {
                        items.push(&body[start..position - 1]);
                        start = position;
                    }
                    _ => {}
                }
            }
            // Same reason as everywhere else: a `,`, `(`, `[` or brace inside
            // an attribute's token tree does not split a variant.
            Event::Word { .. } | Event::Attribute { .. } | Event::UnreadableAttribute => {}
        }
    }
    if start < body.len() {
        items.push(&body[start..]);
    }
    items
}

/// Strip doc comments and attributes from the front of one variant item,
/// recording a diagnostic for every non-doc attribute removed.
fn strip_leading_attributes<'item>(
    item: &'item str,
    diagnostics: &mut BTreeSet<String>,
) -> &'item str {
    let mut rest = item.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("///") {
            rest = after.find('\n').map_or("", |index| &after[index + 1..]);
            rest = rest.trim_start();
            continue;
        }
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map_or("", |index| &after[index + 1..]);
            rest = rest.trim_start();
            continue;
        }
        if rest.starts_with("#[") {
            let Some(close) = matching_bracket(rest) else {
                diagnostics.insert(DIAGNOSTIC_VARIANT_ATTRIBUTE.to_owned());
                return rest;
            };
            let inner = &rest[2..close];
            let name_end = inner
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(inner.len());
            if !attribute_preserves_the_set(&inner[..name_end]) {
                diagnostics.insert(DIAGNOSTIC_VARIANT_ATTRIBUTE.to_owned());
            }
            rest = rest[close + 1..].trim_start();
            continue;
        }
        return rest;
    }
}

/// Offset of the `]` closing an attribute opening at the start of `text`.
///
/// Literal-aware via [`attribute_group_end`], so `#[doc = "]"]` closes at its
/// last bracket rather than at the one inside the string.
fn matching_bracket(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let open = bytes.iter().position(|byte| *byte == b'[')?;
    attribute_group_end(bytes, open).map(|end| end - 1)
}

/// Split a leading Rust identifier off `text`.
fn split_identifier(text: &str) -> (&str, &str) {
    let end = text
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(text.len());
    let (name, rest) = text.split_at(end);
    let first_is_identifier_start = name
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
    if first_is_identifier_start {
        (name, rest)
    } else {
        ("", text)
    }
}

/// Classify whatever follows a variant's name.
///
/// A discriminant (`= 3`) leaves the variant a plain name and raises nothing.
/// A payload, a macro, or anything unrecognised each raise their own
/// diagnostic: the member name is still readable, but the *set* is no longer
/// a set of plain names this observer can claim to have closed.
fn classify_variant_tail(tail: &str, diagnostics: &mut BTreeSet<String>) {
    if tail.is_empty() {
        return;
    }
    if tail.contains('!') {
        diagnostics.insert(DIAGNOSTIC_MACRO_UNRESOLVED.to_owned());
        return;
    }
    if tail.starts_with('(') || tail.starts_with('{') {
        diagnostics.insert(DIAGNOSTIC_VARIANT_PAYLOAD.to_owned());
        return;
    }
    if let Some(discriminant) = tail.strip_prefix('=') {
        // A discriminant leaves the variant a plain name. An attribute loose in
        // the tail does not: it means the body did not split where the compiler
        // would split it, so what follows is not a member list this reader can
        // claim to have closed.
        if discriminant.contains('#') {
            diagnostics.insert(DIAGNOSTIC_VARIANT_UNRECOGNISED.to_owned());
        }
        return;
    }
    diagnostics.insert(DIAGNOSTIC_VARIANT_UNRECOGNISED.to_owned());
}

/// Offset of the first byte at or after `from` that is neither whitespace nor
/// a comment.
fn skip_trivia(bytes: &[u8], from: usize) -> usize {
    let mut scanner = Scanner::at(bytes, from);
    scanner.skip_trivia();
    scanner.position()
}

/// What the scanner reports.
///
/// A whole `#[…]` group is ONE event. Every consumer therefore counts braces
/// over the same tokenization of the same bytes, which is what makes the
/// module's structural model single-valued: there is no arrangement of
/// attribute content that one counter can see and another cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// A `{` outside every literal, comment and attribute group.
    OpenBrace,
    /// A `}` outside every literal, comment and attribute group.
    CloseBrace,
    /// An identifier or keyword.
    Word {
        /// Inclusive start offset.
        start: usize,
        /// Exclusive end offset.
        end: usize,
    },
    /// A whole `#[…]` group, already stepped over. The bounds delimit the token
    /// tree between the brackets.
    Attribute {
        /// Inclusive start of the token tree.
        inner_start: usize,
        /// Exclusive end of the token tree.
        inner_end: usize,
    },
    /// A `#` the scanner could not read as an attribute group, so it could not
    /// be stepped over.
    UnreadableAttribute,
    /// Any other single significant byte; `position()` points just past it.
    Other,
}

/// A byte scanner that never mistakes literal or comment content for code.
struct Scanner<'source> {
    bytes: &'source [u8],
    index: usize,
    /// The scanner reached end of file inside a comment or a literal it never
    /// saw closed.
    ///
    /// Everything it skipped from there on it skipped on the strength of a
    /// delimiter that is not in the file. That is not a smaller read, it is a
    /// different file: an unterminated `/*` swallows the rest of the source, so
    /// a body closed early by a spliced `}` can be made to look balanced simply
    /// by hiding the real remainder inside a comment.
    truncated: bool,
    /// Whether `#[…]` groups are reported as one [`Event::Attribute`].
    ///
    /// True everywhere except inside [`attribute_group_end`], which matches one
    /// group's brackets and must therefore see them.
    atomic_attributes: bool,
}

impl<'source> Scanner<'source> {
    const fn new(bytes: &'source [u8]) -> Self {
        Self {
            bytes,
            index: 0,
            truncated: false,
            atomic_attributes: true,
        }
    }

    const fn at(bytes: &'source [u8], index: usize) -> Self {
        Self {
            bytes,
            index,
            truncated: false,
            atomic_attributes: true,
        }
    }

    /// A scanner that reports an attribute's brackets instead of stepping over
    /// the group. Only [`attribute_group_end`] may use it.
    const fn brackets_at(bytes: &'source [u8], index: usize) -> Self {
        Self {
            bytes,
            index,
            truncated: false,
            atomic_attributes: false,
        }
    }

    const fn position(&self) -> usize {
        self.index
    }

    /// Whether this scan ended inside a comment or literal that never closed.
    const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Advance past whitespace and comments.
    fn skip_trivia(&mut self) {
        loop {
            if self.index >= self.bytes.len() {
                self.index = self.bytes.len();
                return;
            }
            while self
                .bytes
                .get(self.index)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.index += 1;
            }
            if self.bytes[self.index..].starts_with(b"//") {
                self.index += 2;
                while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                    self.index += 1;
                }
                continue;
            }
            if self.bytes[self.index..].starts_with(b"/*") {
                self.index += 2;
                let mut depth = 1_i64;
                while self.index < self.bytes.len() && depth > 0 {
                    if self.bytes[self.index..].starts_with(b"/*") {
                        depth += 1;
                        self.index += 2;
                    } else if self.bytes[self.index..].starts_with(b"*/") {
                        depth -= 1;
                        self.index += 2;
                    } else {
                        self.index += 1;
                    }
                }
                if depth > 0 {
                    self.truncated = true;
                }
                continue;
            }
            return;
        }
    }

    /// The next significant event, skipping trivia and literal content.
    fn next_event(&mut self) -> Option<Event> {
        self.skip_trivia();
        let byte = *self.bytes.get(self.index)?;
        match byte {
            b'{' => {
                self.index += 1;
                Some(Event::OpenBrace)
            }
            b'}' => {
                self.index += 1;
                Some(Event::CloseBrace)
            }
            b'"' => {
                self.index += 1;
                self.skip_string();
                Some(Event::Other)
            }
            b'\'' => {
                self.skip_char_or_lifetime();
                Some(Event::Other)
            }
            b'r' if self.bytes[self.index..].starts_with(b"r\"")
                || self.bytes[self.index..].starts_with(b"r#") =>
            {
                if self.skip_raw_string() {
                    Some(Event::Other)
                } else {
                    Some(self.read_word())
                }
            }
            b'b' if self.bytes[self.index..].starts_with(b"b\"") => {
                self.index += 2;
                self.skip_string();
                Some(Event::Other)
            }
            byte if byte.is_ascii_alphanumeric() || byte == b'_' => Some(self.read_word()),
            b'#' if self.atomic_attributes => {
                let hash = self.index;
                match read_attribute(self.bytes, hash) {
                    AttributeRead::Group {
                        inner_start,
                        inner_end,
                        end,
                    } => {
                        self.index = end;
                        Some(Event::Attribute {
                            inner_start,
                            inner_end,
                        })
                    }
                    // Neither of the remaining cases can be stepped over, so
                    // both advance by the `#` alone. They differ in what they
                    // cost the read, which is the consumer's business.
                    AttributeRead::Unreadable => {
                        self.index = hash + 1;
                        Some(Event::UnreadableAttribute)
                    }
                    AttributeRead::NotAnAttribute => {
                        self.index = hash + 1;
                        Some(Event::Other)
                    }
                }
            }
            _ => {
                self.index += 1;
                Some(Event::Other)
            }
        }
    }

    fn read_word(&mut self) -> Event {
        let start = self.index;
        while self
            .bytes
            .get(self.index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.index += 1;
        }
        Event::Word {
            start,
            end: self.index,
        }
    }

    /// Consume a string body whose opening quote is already behind the cursor.
    fn skip_string(&mut self) {
        while self.index < self.bytes.len() {
            match self.bytes[self.index] {
                b'\\' => self.index += 2,
                b'"' => {
                    self.index += 1;
                    return;
                }
                _ => self.index += 1,
            }
        }
        self.truncated = true;
    }

    /// Consume a raw string. Returns false when the `r` opened an identifier
    /// (`r#type`, `rest`) rather than a raw literal.
    fn skip_raw_string(&mut self) -> bool {
        let start = self.index;
        let mut cursor = self.index + 1;
        let mut hashes = 0_usize;
        while self.bytes.get(cursor) == Some(&b'#') {
            hashes += 1;
            cursor += 1;
        }
        if self.bytes.get(cursor) != Some(&b'"') {
            self.index = start;
            return false;
        }
        cursor += 1;
        let mut terminator = Vec::with_capacity(hashes + 1);
        terminator.push(b'"');
        terminator.extend(std::iter::repeat_n(b'#', hashes));
        while cursor < self.bytes.len() {
            if self.bytes[cursor..].starts_with(&terminator) {
                self.index = cursor + terminator.len();
                return true;
            }
            cursor += 1;
        }
        self.index = self.bytes.len();
        self.truncated = true;
        true
    }

    /// Consume a character literal, or a lifetime, whichever this `'` opens.
    fn skip_char_or_lifetime(&mut self) {
        let start = self.index;
        let mut cursor = self.index + 1;
        if self.bytes.get(cursor) == Some(&b'\\') {
            cursor += 2;
        } else if cursor < self.bytes.len() {
            // Step over one UTF-8 scalar.
            cursor += 1;
            while cursor < self.bytes.len() && (self.bytes[cursor] & 0b1100_0000) == 0b1000_0000 {
                cursor += 1;
            }
        }
        if self.bytes.get(cursor) == Some(&b'\'') {
            self.index = cursor + 1;
            return;
        }
        // A lifetime: consume the tick only and let the name read as a word.
        self.index = start + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frozen snapshot of a real-world Rust module that declares the
    /// `RememberAction` and `RecallAction` enums. It is a checked-in fixture,
    /// not the live `src/service.rs`, so that module can change freely.
    const SERVICE_SOURCE: &str = include_str!("fixtures/service.rs.txt");

    fn enumerate(source: &str) -> RustEnumEnumerationV1 {
        enumerate_rust_enum(source, "Action", 64).unwrap()
    }

    fn ids(enumeration: &RustEnumEnumerationV1) -> Vec<&str> {
        enumeration
            .diagnostics()
            .iter()
            .map(ContractId::as_str)
            .collect()
    }

    #[test]
    fn a_plain_unit_enum_is_enumerated_exhaustively() {
        let enumeration = enumerate("pub enum Action {\n    Record,\n    Assert,\n}\n");
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(enumeration.exhaustive());
        assert!(enumeration.contains("Assert"));
        assert!(!enumeration.contains("Deploy"));
    }

    #[test]
    fn doc_comments_and_a_missing_trailing_comma_do_not_change_the_member_set() {
        let enumeration = enumerate(
            "/// Doc on the enum.\npub enum Action {\n    /// Doc.\n    Record,\n    // line\n    Assert\n}\n",
        );
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(enumeration.exhaustive());
    }

    #[test]
    fn every_diagnostic_the_admission_registers_is_one_this_algorithm_can_raise() {
        let mut expected = ALL_DIAGNOSTICS.to_vec();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(expected.len(), ALL_DIAGNOSTICS.len());
        for diagnostic in ALL_DIAGNOSTICS {
            ContractId::new(diagnostic).unwrap();
        }
    }

    #[test]
    fn a_non_exhaustive_enum_is_never_exhaustively_enumerated() {
        let enumeration = enumerate("#[non_exhaustive]\npub enum Action {\n    Record,\n}\n");
        assert_eq!(enumeration.members(), ["Record"]);
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_NON_EXHAUSTIVE]);
    }

    #[test]
    fn a_cfg_gated_variant_makes_the_read_non_exhaustive() {
        let enumeration = enumerate(
            "pub enum Action {\n    Record,\n    #[cfg(feature = \"x\")]\n    Assert,\n}\n",
        );
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_VARIANT_ATTRIBUTE]);
    }

    #[test]
    fn a_cfg_gated_enum_makes_the_read_non_exhaustive() {
        let enumeration = enumerate("#[cfg(unix)]\npub enum Action {\n    Record,\n}\n");
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_ENUM_ATTRIBUTE]);
    }

    #[test]
    fn a_brace_delimited_attribute_cannot_hide_the_non_exhaustive_marker() {
        // `#[bar { baz }]` is a legal attribute whose token tree contains
        // braces. A reader that treats any `}` as the end of the previous item
        // loses every attribute above it — including this `#[non_exhaustive]`.
        let enumeration = enumerate(
            "#[non_exhaustive]\n#[bar { baz }]\npub enum Action {\n    Record,\n    Assert,\n}\n",
        );
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_NON_EXHAUSTIVE));
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_ENUM_ATTRIBUTE));
    }

    #[test]
    fn a_brace_delimited_attribute_cannot_hide_a_cfg_gate() {
        let enumeration = enumerate(
            "#[cfg(feature = \"x\")]\n#[bar { baz }]\npub enum Action {\n    Record,\n    Assert,\n}\n",
        );
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_ENUM_ATTRIBUTE]);
    }

    #[test]
    fn a_semicolon_inside_an_attribute_does_not_end_the_previous_item() {
        let enumeration = enumerate(
            "#[non_exhaustive]\n#[bar(a; b)]\npub enum Action {\n    Record,\n    Assert,\n}\n",
        );
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_NON_EXHAUSTIVE));
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_ENUM_ATTRIBUTE));
    }

    #[test]
    fn an_unknown_brace_delimited_attribute_alone_makes_the_read_non_exhaustive() {
        // An attribute proc-macro may rewrite the item wholesale, so seeing one
        // at all costs the read its exhaustiveness — whatever delimiter it used.
        let enumeration =
            enumerate("#[bar { baz }]\npub enum Action {\n    Record,\n    Assert,\n}\n");
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_ENUM_ATTRIBUTE]);
    }

    #[test]
    fn an_attribute_region_the_reader_cannot_parse_fails_closed() {
        // Unbalanced `[`: the reader cannot prove what the attribute list was,
        // so it must say so rather than report an empty list.
        let enumeration =
            enumerate("#[bar[oops]\npub enum Action {\n    Record,\n    Assert,\n}\n");
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_ENUM_ATTRIBUTE));

        // A `#` at item level that never opens a bracket is equally unprovable.
        let stray = enumerate("#\npub enum Action {\n    Record,\n    Assert,\n}\n");
        assert!(!stray.exhaustive());
        assert!(ids(&stray).contains(&DIAGNOSTIC_ENUM_ATTRIBUTE));
    }

    #[test]
    fn a_preceding_item_with_braces_does_not_swallow_the_enum_attributes() {
        let enumeration = enumerate(
            "fn helper() { let _ = 1; }\n#[non_exhaustive]\npub enum Action {\n    Record,\n}\n",
        );
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_NON_EXHAUSTIVE]);
    }

    #[test]
    fn a_bracket_inside_an_attribute_string_does_not_close_it() {
        // `#[doc = "]"]` closes at the LAST bracket; a counter that is blind to
        // string literals would stop early and misread the rest as a variant.
        let enumeration = enumerate(
            "#[doc = \"]\"]\npub enum Action {\n    #[doc = \"]\"]\n    Record,\n    Assert,\n}\n",
        );
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(
            enumeration.exhaustive(),
            "diagnostics: {:?}",
            ids(&enumeration)
        );
    }

    #[test]
    fn a_macro_inside_the_body_makes_the_read_non_exhaustive() {
        let enumeration = enumerate("pub enum Action {\n    Record,\n    generated!(),\n}\n");
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_MACRO_UNRESOLVED));
    }

    #[test]
    fn a_payload_variant_makes_the_read_non_exhaustive_but_still_names_it() {
        let enumeration = enumerate("pub enum Action {\n    Record,\n    Assert(u32),\n}\n");
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_VARIANT_PAYLOAD]);
    }

    #[test]
    fn a_struct_variant_brace_does_not_terminate_the_body() {
        let enumeration = enumerate("pub enum Action {\n    Record { at: u64 },\n    Assert,\n}\n");
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
    }

    #[test]
    fn a_discriminant_is_still_a_plain_member() {
        let enumeration = enumerate("pub enum Action {\n    Record = 1,\n    Assert = 2,\n}\n");
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(enumeration.exhaustive());
    }

    #[test]
    fn a_generic_enum_makes_the_read_non_exhaustive() {
        let enumeration = enumerate("pub enum Action<T> {\n    Record,\n}\n");
        assert!(!enumeration.exhaustive());
        assert_eq!(ids(&enumeration), [DIAGNOSTIC_ENUM_GENERIC]);
    }

    #[test]
    fn reaching_the_member_bound_is_a_non_exhaustive_read_not_a_shorter_truth() {
        let source = "pub enum Action {\n    Record,\n    Assert,\n    Retract,\n}\n";
        let bounded = enumerate_rust_enum(source, "Action", 2).unwrap();
        assert_eq!(bounded.members(), ["Record", "Assert"]);
        assert!(!bounded.exhaustive());
        assert_eq!(ids(&bounded), [DIAGNOSTIC_BOUND_EXCEEDED]);
        // The bounded read cannot even see the member the full read finds, so
        // "absent" from it is exactly the claim that must never verify.
        assert!(!bounded.contains("Retract"));
        assert!(
            enumerate_rust_enum(source, "Action", 3)
                .unwrap()
                .contains("Retract")
        );
    }

    #[test]
    fn a_zero_or_oversized_member_bound_is_refused() {
        let source = "pub enum Action { Record }";
        assert!(matches!(
            enumerate_rust_enum(source, "Action", 0),
            Err(ObserverRuntimeError::InvalidMemberBound)
        ));
        assert!(matches!(
            enumerate_rust_enum(source, "Action", MAX_MEMBER_BOUND + 1),
            Err(ObserverRuntimeError::InvalidMemberBound)
        ));
    }

    #[test]
    fn an_absent_enum_is_refused_rather_than_read_as_an_empty_set() {
        let error = enumerate_rust_enum("pub enum Other { A }", "Action", 8).unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::EnumNotUnique { found: 0, .. }
        ));
    }

    #[test]
    fn two_declarations_are_refused_rather_than_one_being_picked() {
        let source = "pub enum Action { A }\npub enum Action { B }\n";
        let error = enumerate_rust_enum(source, "Action", 8).unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::EnumNotUnique { found: 2, .. }
        ));
    }

    #[test]
    fn a_nested_declaration_is_not_module_level() {
        let source = "mod inner {\n    pub enum Action { A }\n}\n";
        let error = enumerate_rust_enum(source, "Action", 8).unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::EnumNotUnique { found: 0, .. }
        ));
    }

    #[test]
    fn a_declaration_inside_a_comment_or_string_is_not_located() {
        let commented = "// pub enum Action { A }\npub enum Action { B }\n";
        assert_eq!(enumerate(commented).members(), ["B"]);
        let quoted = "const S: &str = \"pub enum Action { A }\";\npub enum Action { B }\n";
        assert_eq!(enumerate(quoted).members(), ["B"]);
        let raw = "const S: &str = r#\"pub enum Action { A }\"#;\npub enum Action { B }\n";
        assert_eq!(enumerate(raw).members(), ["B"]);
        let block = "/* pub enum Action { A } */\npub enum Action { B }\n";
        assert_eq!(enumerate(block).members(), ["B"]);
    }

    #[test]
    fn a_brace_inside_a_string_does_not_close_the_body() {
        let source = "pub enum Action {\n    Record = { 1 },\n}\n";
        // The scanner tracks the nested brace, so the body still closes at the
        // real terminator and the member survives.
        let enumeration = enumerate(source);
        assert_eq!(enumeration.members(), ["Record"]);
    }

    #[test]
    fn an_unterminated_body_is_refused() {
        let error =
            enumerate_rust_enum("pub enum Action {\n    Record,\n", "Action", 8).unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::EnumBodyUnterminated(_)
        ));
    }

    #[test]
    fn a_repeated_member_is_refused() {
        let error =
            enumerate_rust_enum("pub enum Action { Record, Record }", "Action", 8).unwrap_err();
        assert!(matches!(
            error,
            ObserverRuntimeError::DuplicateMember { .. }
        ));
    }

    #[test]
    fn a_lifetime_tick_does_not_open_a_character_literal() {
        let source = "struct Holder<'a>(&'a str);\npub enum Action { Record }\n";
        assert_eq!(enumerate(source).members(), ["Record"]);
    }

    #[test]
    fn output_digest_separates_members_diagnostics_and_exhaustiveness() {
        let plain = enumerate("pub enum Action { Record, Assert }");
        let gated = enumerate("pub enum Action {\n    Record,\n    #[cfg(unix)]\n    Assert,\n}\n");
        assert_eq!(plain.members(), gated.members());
        assert_ne!(plain.output_digest(), gated.output_digest());

        let reordered = enumerate("pub enum Action { Assert, Record }");
        assert_ne!(plain.output_digest(), reordered.output_digest());
        assert_eq!(
            plain.output_digest(),
            enumerate("pub enum Action { Record, Assert }").output_digest()
        );
    }

    #[test]
    fn a_crafted_attribute_cannot_make_the_real_enum_look_exhaustive() {
        // The observed blob is untrusted by construction, so "a source file
        // written to defeat this reader" is in the threat model. Here a real
        // file is crafted so that a brace-and-semicolon token tree sits between
        // the reader and a `#[non_exhaustive]`.
        let source = SERVICE_SOURCE.replace(
            "pub enum RememberAction {",
            "#[non_exhaustive]\n#[rewrites_the_item { and; a; semicolon }]\npub enum RememberAction {",
        );
        let enumeration = enumerate_rust_enum(&source, "RememberAction", 64).unwrap();
        assert!(
            !enumeration.exhaustive(),
            "diagnostics: {:?}",
            ids(&enumeration)
        );
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_NON_EXHAUSTIVE));
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_ENUM_ATTRIBUTE));
        // `Deploy` really is absent from the fixture's enum. A read that cannot
        // prove it saw the whole set still must not be allowed to say so, and
        // downstream only ever learns that through the diagnostics.
        assert!(!enumeration.contains("Deploy"));
    }

    #[test]
    fn the_real_remember_action_enum_enumerates_exhaustively() {
        let source = SERVICE_SOURCE;
        let enumeration = enumerate_rust_enum(source, "RememberAction", 64).unwrap();
        assert!(
            enumeration.exhaustive(),
            "diagnostics: {:?}",
            ids(&enumeration)
        );
        for expected in [
            "Record",
            "Assert",
            "Supersede",
            "Retract",
            "Forget",
            "Restore",
            "Resolve",
            "Relate",
        ] {
            assert!(enumeration.contains(expected), "missing {expected}");
        }
        assert!(!enumeration.contains("Deploy"));
        // The other closed action enum in the same file must not be confused
        // for this one.
        let recall = enumerate_rust_enum(source, "RecallAction", 64).unwrap();
        assert!(recall.exhaustive());
        assert!(recall.contains("Search"));
        assert!(!recall.contains("Record"));
    }

    // -- One tokenization of brace depth ---------------------------------
    //
    // Every scanner in this module that counts `{` and `}` must agree about
    // which bytes are code and which are an attribute's token tree. Where two
    // of them disagreed, an attacker who controls the blob could steer one into
    // a different structural model of the same bytes and hide an attribute — or
    // a whole tail of variants — from a read that still called itself
    // exhaustive. These are the vectors that disagreement produced.

    #[test]
    fn a_net_negative_brace_in_an_attribute_cannot_erase_the_enum_attributes() {
        // `#[doc( } )]` is a legal attribute whose token tree carries one more
        // `}` than `{`. A scanner that lets attribute content move module-level
        // depth reaches -1 here, and the bare `{` then returns it to 0, where
        // the enum reads as module level — while an attribute reader that steps
        // over the group whole is at +1 and drops every attribute after it.
        // `#[non_exhaustive]` then vanishes with no diagnostic at all.
        let source =
            "#[doc( } )]\n{\n#[non_exhaustive]\npub enum Action {\n    Record,\n    Assert,\n}\n";
        let read = enumerate_rust_enum(source, "Action", 64);
        assert!(
            !read.as_ref().is_ok_and(RustEnumEnumerationV1::exhaustive),
            "a crafted attribute bought an exhaustive read: {read:?}"
        );
    }

    #[test]
    fn a_net_negative_brace_in_an_attribute_cannot_erase_a_cfg_gate() {
        let source = "#[doc( } )]\n{\n#[cfg(feature = \"nope\")]\npub enum Action {\n    Record,\n    Assert,\n}\n";
        let read = enumerate_rust_enum(source, "Action", 64);
        assert!(
            !read.as_ref().is_ok_and(RustEnumEnumerationV1::exhaustive),
            "a crafted attribute bought an exhaustive read: {read:?}"
        );
    }

    #[test]
    fn a_net_negative_brace_in_an_attribute_is_recorded_not_absorbed() {
        // The same attribute with no bare `{` to rebalance it. `#[doc( } )]` is
        // not a token tree the compiler would accept — its `(` never closes
        // before the `]` — so the reader refuses it as a group instead of
        // stepping over it, and the stray `}` it then meets is a close with no
        // open. Both facts are recorded rather than absorbed: the file is
        // flagged as one this reader cannot structure, and the marker below is
        // still found ON the enum rather than lost along with it.
        let source =
            "#[doc( } )]\n#[non_exhaustive]\npub enum Action {\n    Record,\n    Assert,\n}\n";
        let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_NON_EXHAUSTIVE));
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED));
    }

    #[test]
    fn a_net_negative_brace_in_a_variant_attribute_cannot_drop_later_variants() {
        // The same disagreement one layer down: the body scanners counted the
        // braces inside a variant attribute while the attribute stripper
        // stepped over the group whole, so the body closed early and the tail
        // of the enum disappeared. A discriminant tail raises nothing, so the
        // truncated read called itself exhaustive.
        let source = "pub enum Action {\n    Record = 1 #[doc( } )],\n    Assert = 2,\n}\n";
        let read = enumerate_rust_enum(source, "Action", 64);
        assert!(
            !read
                .as_ref()
                .is_ok_and(|read| read.exhaustive() && !read.contains("Assert")),
            "a crafted variant attribute bought an exhaustive read missing a member: {read:?}"
        );
    }

    #[test]
    fn a_crafted_blob_cannot_report_a_present_variant_as_absent() {
        // End to end on a real file. The observed blob is untrusted by
        // construction and this one genuinely IS the object a pin would name,
        // so no integrity check upstream can catch it: the entire defence is
        // the reader refusing to call a read exhaustive when it cannot prove it
        // saw the whole set. Here `Forget` is deleted and a `#[non_exhaustive]`
        // is hidden behind a net-negative brace count — which is exactly a
        // verified negative asserting that `forget` is not an allowed remember
        // action, the worst output this subsystem can produce.
        let source = SERVICE_SOURCE
            .replace(
                "pub enum RememberAction {",
                "#[doc( } )]\n{\n#[non_exhaustive]\npub enum RememberAction {",
            )
            .replace("    Forget,\n", "");
        let read = enumerate_rust_enum(&source, "RememberAction", 64);
        assert!(
            !read
                .as_ref()
                .is_ok_and(|read| read.exhaustive() && !read.contains("Forget")),
            "a crafted blob bought a verified negative about `forget`: {read:?}"
        );
    }

    #[test]
    fn an_over_close_anywhere_in_the_file_costs_the_read_its_exhaustiveness() {
        // A `}` spliced into the body ends the enum early. The reader cannot
        // know that from the body alone — but the enum's real closing brace
        // then closes a body the reader never saw opened, and a file whose
        // braces the reader cannot balance is a file whose items it cannot
        // place.
        let source = "pub enum Action {\n    Record,\n}\n    Assert,\n}\n";
        let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
        assert_eq!(enumeration.members(), ["Record"]);
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED));
    }

    #[test]
    fn braces_left_open_at_end_of_file_cost_the_read_its_exhaustiveness() {
        let source = "pub enum Action {\n    Record,\n    Assert,\n}\n{\n";
        let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
        assert_eq!(enumeration.members(), ["Record", "Assert"]);
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED));
    }

    #[test]
    fn an_unterminated_comment_cannot_hide_the_rest_of_the_file() {
        // Splicing `}` after the opening brace empties the enum, and an
        // unterminated `/*` then swallows the remainder — including the real
        // closing brace whose over-close would have given the truncation away.
        // The braces balance, so the only thing left to notice is that the
        // reader skipped to end of file on the strength of a `*/` that is not
        // in the file. An empty exhaustive read is a verified negative about
        // every action there is, so this one is worth noticing.
        let source = "pub enum Action {\n}\n    Record,\n    Assert,\n/*\n}\n";
        let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
        assert!(enumeration.members().is_empty());
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED));
    }

    #[test]
    fn an_unterminated_string_cannot_hide_the_rest_of_the_file() {
        let source = "pub enum Action {\n}\n    Record,\n\"\n}\n";
        let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
        assert!(!enumeration.exhaustive());
        assert!(ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED));
    }

    #[test]
    fn an_attribute_shape_the_grammar_does_not_allow_is_refused() {
        // Both of these close their bracket and nest perfectly, so a reader
        // that matches only delimiters steps over each as one attribute — and
        // over the two variants each one spans. Neither is an attribute rustc
        // would accept: an attribute is a path, then nothing, or `= <one
        // expression>`, or one delimited group running to the end.
        for source in [
            // A path followed by loose tokens.
            "pub enum Action {\n    Record,\n    #[doc\n    Assert,\n    Retract,\n    ]\n    Restore,\n}\n",
            // A value that is a variant list rather than an expression.
            "pub enum Action {\n    Record,\n    #[doc =\n    Assert,\n    Retract,\n    ]\n    Restore,\n}\n",
        ] {
            let read = enumerate_rust_enum(source, "Action", 64);
            assert!(
                !read
                    .as_ref()
                    .is_ok_and(|read| read.exhaustive() && !read.contains("Assert")),
                "an ill-shaped attribute bought an exhaustive read missing a member: {read:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_attribute_shape_is_still_read_as_one() {
        // The guard above must not cost the reader the attributes it exists to
        // find. A path, a path with `::`, a value, and each delimiter form.
        for (source, expected) in [
            ("#[non_exhaustive]\npub enum Action { Record }\n", true),
            (
                "#[rustfmt::skip]\n#[non_exhaustive]\npub enum Action { Record }\n",
                true,
            ),
            (
                "#[doc = \"x\"]\n#[non_exhaustive]\npub enum Action { Record }\n",
                true,
            ),
            (
                "#[derive(Debug, Clone)]\n#[non_exhaustive]\npub enum Action { Record }\n",
                true,
            ),
            (
                "#[bar { a, b }]\n#[non_exhaustive]\npub enum Action { Record }\n",
                true,
            ),
            (
                "#[bar [ a, b ]]\n#[non_exhaustive]\npub enum Action { Record }\n",
                true,
            ),
        ] {
            let enumeration = enumerate_rust_enum(source, "Action", 64).unwrap();
            assert_eq!(
                ids(&enumeration).contains(&DIAGNOSTIC_NON_EXHAUSTIVE),
                expected,
                "the marker was lost in {source:?}: {:?}",
                ids(&enumeration)
            );
            assert!(
                !ids(&enumeration).contains(&DIAGNOSTIC_SOURCE_UNBALANCED),
                "an ordinary attribute is not a structural failure in {source:?}"
            );
        }
    }

    #[test]
    fn an_attribute_token_tree_whose_delimiters_do_not_nest_is_refused() {
        // `#[doc(` … `]` closes its bracket while leaving its paren open. A
        // reader that matched only brackets would step over the whole span as
        // one attribute — here, over three variants — and report the shorter
        // list as the complete one. rustc will not accept a token tree that
        // does not nest, so refusing it is a proof rather than a guess.
        let source = "pub enum Action {\n    Record,\n    #[doc(\n    Assert,\n    Retract,\n    ]\n    Restore,\n}\n";
        let read = enumerate_rust_enum(source, "Action", 64);
        assert!(
            !read
                .as_ref()
                .is_ok_and(|read| read.exhaustive() && !read.contains("Assert")),
            "an unnesting token tree bought an exhaustive read missing a member: {read:?}"
        );
    }
}
