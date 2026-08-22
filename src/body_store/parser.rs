//! Deterministic reference parser for the body projection.
//!
//! The body projector must turn one immutable source-object version into an
//! ordered set of chunk occurrences with exact byte-range spans. Which parser
//! produced a chunk is part of that chunk's identity ([`ParserKeyV1`]), so the
//! parser is not free-form: it is a frozen [`ParserKeyV1`] plus a deterministic
//! byte-range segmentation that depends only on the source bytes and the
//! parser's declared version.
//!
//! Two reference parser keys are provided so the projector's shadow-generation
//! path can be exercised as ordinary software: [`reference_parser_key_v1`]
//! segments on blank-line (`"\n\n"`) boundaries, and
//! [`reference_parser_key_v2`] segments on single-newline (`"\n"`) boundaries.
//! Because the two keys differ in every identity-bearing field, re-running the
//! projector under v2 over the same source produces a *different* occurrence and
//! manifest set (a shadow generation), never an in-place rewrite of the v1 rows.
//!
//! This is a reference segmentation, not a claim about how production connectors
//! will chunk their formats; production parsers register their own frozen
//! [`ParserKeyV1`] and their own segmentation. The projector, its identities,
//! its idempotency, and its fail-closed collision handling are all independent
//! of which concrete segmentation is plugged in here.

use sha2::{Digest as _, Sha256};

use crate::memory_contracts::chunk_identity::{NormalizationRuleV1, ParserKeyV1};
use crate::memory_contracts::digest::Sha256Digest;

const PARSER_SCHEMA_VERSION: u32 = 1;

/// Parser version whose segmentation splits on blank-line boundaries.
pub const PARAGRAPH_PARSER_VERSION: u32 = 1;
/// Parser version whose segmentation splits on single-newline boundaries.
pub const LINE_PARSER_VERSION: u32 = 2;

/// One contiguous half-open `[start, end)` byte range the parser extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedSegmentV1 {
    /// Inclusive start byte offset into the source-object version.
    pub byte_start: u64,
    /// Exclusive end byte offset into the source-object version.
    pub byte_end: u64,
}

/// Plain SHA-256 of a fixed label, used only to mint the non-zero artifact and
/// configuration digests a [`ParserKeyV1`] requires. Deliberately not a
/// domain-separated digest: these are opaque configuration identities, not a
/// content identity in any frozen preimage.
fn label_digest(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(label.as_bytes()).into())
}

/// The blank-line reference parser key (generation 1).
#[must_use]
pub fn reference_parser_key_v1() -> ParserKeyV1 {
    ParserKeyV1 {
        schema_version: PARSER_SCHEMA_VERSION,
        parser_artifact_digest: label_digest("ostk-body-reference-parser"),
        parser_version: PARAGRAPH_PARSER_VERSION,
        configuration_digest: label_digest("ostk-body-reference-parser:paragraph"),
        declared_normalization_rules: vec![NormalizationRuleV1::NewlineLf],
    }
}

/// The single-newline reference parser key (a distinct parser used to exercise
/// the shadow-generation upgrade path).
#[must_use]
pub fn reference_parser_key_v2() -> ParserKeyV1 {
    ParserKeyV1 {
        schema_version: PARSER_SCHEMA_VERSION,
        parser_artifact_digest: label_digest("ostk-body-reference-parser"),
        parser_version: LINE_PARSER_VERSION,
        configuration_digest: label_digest("ostk-body-reference-parser:line"),
        declared_normalization_rules: vec![NormalizationRuleV1::NewlineLf],
    }
}

/// Segment `source` into ordered, non-overlapping byte ranges, one per non-empty
/// run of bytes between the delimiter this parser's version selects.
///
/// The result is deterministic in the source bytes alone: it never depends on
/// wall-clock time, iteration order of any map, or external state, so replaying
/// the same source under the same parser key reproduces byte-identical spans
/// (REPLAY-01). Delimiter bytes are excluded from every span, so spans may have
/// gaps but never overlap.
#[must_use]
pub fn parse_source(parser_key: &ParserKeyV1, source: &[u8]) -> Vec<ParsedSegmentV1> {
    let delimiter: &[u8] = if parser_key.parser_version == PARAGRAPH_PARSER_VERSION {
        b"\n\n"
    } else {
        b"\n"
    };
    segment_on(source, delimiter)
}

fn segment_on(source: &[u8], delimiter: &[u8]) -> Vec<ParsedSegmentV1> {
    let mut segments = Vec::new();
    let mut segment_start = 0_usize;
    let mut cursor = 0_usize;
    while cursor + delimiter.len() <= source.len() {
        if &source[cursor..cursor + delimiter.len()] == delimiter {
            if cursor > segment_start {
                push_segment(&mut segments, segment_start, cursor);
            }
            cursor += delimiter.len();
            segment_start = cursor;
        } else {
            cursor += 1;
        }
    }
    if source.len() > segment_start {
        push_segment(&mut segments, segment_start, source.len());
    }
    segments
}

fn push_segment(segments: &mut Vec<ParsedSegmentV1>, start: usize, end: usize) {
    // `as u64` is lossless: source length is bounded far below u64::MAX by the
    // governed-content byte cap, and start/end are indices into it.
    segments.push(ParsedSegmentV1 {
        byte_start: start as u64,
        byte_end: end as u64,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_parser_keys_are_valid_and_distinct() {
        let v1 = reference_parser_key_v1();
        let v2 = reference_parser_key_v2();
        v1.validate().unwrap();
        v2.validate().unwrap();
        // Distinct keys => distinct identities => a v2 run is a new generation,
        // never a reuse of v1's occurrence identities.
        assert_ne!(v1.key_digest().unwrap(), v2.key_digest().unwrap());
    }

    #[test]
    fn paragraph_parser_splits_on_blank_lines_and_excludes_delimiters() {
        let source = b"alpha\n\nbeta\n\n";
        let segments = parse_source(&reference_parser_key_v1(), source);
        assert_eq!(
            segments,
            vec![
                ParsedSegmentV1 {
                    byte_start: 0,
                    byte_end: 5
                },
                ParsedSegmentV1 {
                    byte_start: 7,
                    byte_end: 11
                },
            ]
        );
        // Spans never overlap and are strictly ordered.
        assert!(
            segments
                .windows(2)
                .all(|w| w[0].byte_end <= w[1].byte_start)
        );
    }

    #[test]
    fn line_parser_produces_more_segments_than_paragraph_parser() {
        let source = b"one\ntwo\n\nthree";
        let paragraphs = parse_source(&reference_parser_key_v1(), source);
        let lines = parse_source(&reference_parser_key_v2(), source);
        // The line parser is genuinely a different parser: same source, more
        // (and different) segments. This is what makes the v1 -> v2 upgrade a
        // real shadow generation rather than a no-op.
        assert!(lines.len() > paragraphs.len());
    }

    #[test]
    fn segmentation_is_deterministic() {
        let source = b"a\n\nbb\n\nccc\n\n";
        assert_eq!(
            parse_source(&reference_parser_key_v1(), source),
            parse_source(&reference_parser_key_v1(), source)
        );
    }

    #[test]
    fn empty_source_yields_no_segments() {
        assert!(parse_source(&reference_parser_key_v1(), b"").is_empty());
        assert!(parse_source(&reference_parser_key_v1(), b"\n\n\n\n").is_empty());
    }
}
