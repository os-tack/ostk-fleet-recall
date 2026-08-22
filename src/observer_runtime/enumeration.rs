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
//! not recognise, and hitting the caller's member bound. Each is a
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

use std::collections::BTreeSet;

use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};

use super::error::{ObserverRuntimeError, ObserverRuntimeResult};

/// Identity of the algorithm this module implements.
///
/// It is part of the admission body, so changing the scanner means a new
/// algorithm id and a new governance decision, not a silent behaviour change
/// under the same one.
pub const ENUMERATION_ALGORITHM_ID: &str = "enumeration.rust-enum-brace-scan.v1";

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

/// Every diagnostic this algorithm can raise, in `ContractId` sort order.
///
/// The admission registers exactly this set; a run that raised a diagnostic
/// outside it would be claiming an exhaustiveness caveat governance never saw.
pub const ALL_DIAGNOSTICS: [&str; 8] = [
    DIAGNOSTIC_BOUND_EXCEEDED,
    DIAGNOSTIC_ENUM_ATTRIBUTE,
    DIAGNOSTIC_ENUM_GENERIC,
    DIAGNOSTIC_NON_EXHAUSTIVE,
    DIAGNOSTIC_MACRO_UNRESOLVED,
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
    let declarations = locate_declarations(bytes, enum_name);
    let [declaration] = declarations.as_slice() else {
        return Err(ObserverRuntimeError::EnumNotUnique {
            name: enum_name.to_owned(),
            found: declarations.len(),
        });
    };

    let mut diagnostics: BTreeSet<String> = BTreeSet::new();
    if declaration.generic {
        diagnostics.insert(DIAGNOSTIC_ENUM_GENERIC.to_owned());
    }
    for attribute in &declaration.attributes {
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
    /// Non-doc attribute names immediately preceding the declaration.
    attributes: Vec<String>,
    /// Whether the declaration carries generic parameters.
    generic: bool,
}

/// Find every module-level `enum <name>` declaration.
///
/// "Module level" is brace depth zero: an enum nested inside a `mod`, a
/// function, or an `impl` is not the item a top-level predicate is about, and
/// silently accepting one would let an unrelated shadowing definition answer
/// the question.
fn locate_declarations(bytes: &[u8], enum_name: &str) -> Vec<Declaration> {
    let mut found = Vec::new();
    let mut scanner = Scanner::new(bytes);
    let mut depth: i64 = 0;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => depth -= 1,
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
                    attributes: preceding_attributes(bytes, start),
                    generic,
                });
            }
            Event::Other => {}
        }
    }
    found
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

/// Names of the attributes attached to an item.
///
/// The region searched runs from the end of the previous module-level item (a
/// depth-zero `;` or `}`) to the item's own keyword, so a multi-line
/// attribute, an interleaved doc comment, and a block comment are all handled
/// by bracket matching rather than by a line heuristic. A line-oriented reader
/// would stop at the first line it did not recognise and silently miss a
/// `#[cfg]` above it, which is exactly the caveat that must not be missed.
fn preceding_attributes(bytes: &[u8], item_start: usize) -> Vec<String> {
    let region = &bytes[last_item_boundary(bytes, item_start)..item_start];
    let text = String::from_utf8_lossy(region);
    let mut attributes = parse_attribute_names(text.as_ref());
    attributes.sort_unstable();
    attributes.dedup();
    attributes
}

/// Offset just past the last module-level `;` or `}` before `before`.
fn last_item_boundary(bytes: &[u8], before: usize) -> usize {
    let prefix = &bytes[..before];
    let mut scanner = Scanner::new(prefix);
    let mut depth: i64 = 0;
    let mut boundary = 0_usize;
    while let Some(event) = scanner.next_event() {
        match event {
            Event::OpenBrace => depth += 1,
            Event::CloseBrace => {
                depth -= 1;
                if depth <= 0 {
                    depth = 0;
                    boundary = scanner.position();
                }
            }
            Event::Other => {
                let position = scanner.position();
                if depth == 0 && prefix[position - 1] == b';' {
                    boundary = position;
                }
            }
            Event::Word { .. } => {}
        }
    }
    boundary
}

/// Attribute names appearing at the front of `text`, skipping comments.
fn parse_attribute_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map_or("", |index| &after[index + 1..]);
            rest = rest.trim_start();
            continue;
        }
        if rest.starts_with("/*") {
            let Some(end) = rest.find("*/") else {
                return names;
            };
            rest = rest[end + 2..].trim_start();
            continue;
        }
        if rest.starts_with('#') {
            let Some(open) = rest.find('[') else {
                return names;
            };
            let Some(close) = matching_bracket(&rest[open..]) else {
                return names;
            };
            let inner = &rest[open + 1..open + close];
            let name_end = inner
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(inner.len());
            names.push(inner[..name_end].to_owned());
            rest = rest[open + close + 1..].trim_start();
            continue;
        }
        return names;
    }
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
            Event::Word { .. } | Event::Other => {}
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
            Event::Word { .. } => {}
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
fn matching_bracket(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0_i64;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
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
    if tail.starts_with('=') {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// A `{` outside every literal and comment.
    OpenBrace,
    /// A `}` outside every literal and comment.
    CloseBrace,
    /// An identifier or keyword.
    Word {
        /// Inclusive start offset.
        start: usize,
        /// Exclusive end offset.
        end: usize,
    },
    /// Any other single significant byte; `position()` points just past it.
    Other,
}

/// A byte scanner that never mistakes literal or comment content for code.
struct Scanner<'source> {
    bytes: &'source [u8],
    index: usize,
}

impl<'source> Scanner<'source> {
    const fn new(bytes: &'source [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    const fn at(bytes: &'source [u8], index: usize) -> Self {
        Self { bytes, index }
    }

    const fn position(&self) -> usize {
        self.index
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
    fn the_real_remember_action_enum_enumerates_exhaustively() {
        let source = include_str!("../service.rs");
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
}
