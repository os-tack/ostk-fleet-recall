//! Sanitizing collected text: the first thing that happens to provider text,
//! before redaction, splitting, or any digest.
//!
//! Collected text is third-party content an agent will read. Invisible scalars
//! are how instructions hide in it (the TAG block spells ASCII invisibly,
//! bidirectional controls reorder what a reviewer sees, zero-width scalars
//! split a word a filter looks for), so they are removed and counted, and the
//! count travels in the envelope so recall can say something was removed.
//!
//! [`sanitize_text`] is total and idempotent: its output is exactly the form
//! [`is_sanitized_text`] accepts, and sanitizing that output again changes
//! nothing. It never refuses a text; the envelope contract refuses anything
//! that did not come through it.
//!
//! [`is_sanitized_text`]: crate::memory_contracts::collected_item::is_sanitized_text

use unicode_normalization::UnicodeNormalization as _;

use crate::memory_contracts::collected_item::{CollectedScalarClassV1, classify_collected_scalar};

/// One sanitized text and what sanitizing it did.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SanitizedTextV1 {
    /// NFC text holding no hidden scalar, no control but `\n` and `\t`, and no
    /// private-use scalar or noncharacter.
    pub text: String,
    /// Hidden scalars removed.
    pub hidden_scalars_removed: u32,
    /// Controls folded to a space (line endings are not counted: `\r\n` and a
    /// lone `\r` both become `\n`).
    pub controls_folded: u32,
    /// Private-use scalars and noncharacters replaced with U+FFFD.
    pub replaced_scalars: u32,
}

impl SanitizedTextV1 {
    /// Whether a replacement lost provider content.
    #[must_use]
    pub const fn is_lossy(&self) -> bool {
        self.replaced_scalars > 0
    }
}

/// Deliberately prints counts only: sanitized text is still provider content.
impl std::fmt::Debug for SanitizedTextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SanitizedTextV1")
            .field("text_bytes", &self.text.len())
            .field("hidden_scalars_removed", &self.hidden_scalars_removed)
            .field("controls_folded", &self.controls_folded)
            .field("replaced_scalars", &self.replaced_scalars)
            .finish()
    }
}

/// Sanitize one multi-line text.
///
/// In order: `\r\n` and a lone `\r` become `\n`; hidden scalars are removed;
/// `\n` and `\t` are kept; every other control becomes one space; private-use
/// scalars and noncharacters become U+FFFD; the result is composed to NFC.
/// Removal runs before composition, so a base and a combining mark a hidden
/// scalar separated still compose.
#[must_use]
pub fn sanitize_text(raw: &str) -> SanitizedTextV1 {
    let mut folded = String::with_capacity(raw.len());
    let mut outcome = SanitizedTextV1::default();
    let mut scalars = raw.chars().peekable();
    while let Some(scalar) = scalars.next() {
        match classify_collected_scalar(scalar) {
            CollectedScalarClassV1::Keep | CollectedScalarClassV1::KeptControl => {
                folded.push(scalar);
            }
            CollectedScalarClassV1::CarriageReturn => {
                if scalars.peek() != Some(&'\n') {
                    folded.push('\n');
                }
            }
            CollectedScalarClassV1::Hidden => {
                outcome.hidden_scalars_removed = outcome.hidden_scalars_removed.saturating_add(1);
            }
            CollectedScalarClassV1::Control => {
                folded.push(' ');
                outcome.controls_folded = outcome.controls_folded.saturating_add(1);
            }
            CollectedScalarClassV1::Replaced => {
                folded.push('\u{fffd}');
                outcome.replaced_scalars = outcome.replaced_scalars.saturating_add(1);
            }
        }
    }
    outcome.text = folded.nfc().collect();
    outcome
}

/// Sanitize one single-line display string (a label, a display name, a
/// heading path): [`sanitize_text`], then every `\n` and `\t` becomes a space
/// and the ends are trimmed.
#[must_use]
pub fn sanitize_line(raw: &str) -> SanitizedTextV1 {
    let mut outcome = sanitize_text(raw);
    if outcome.text.contains(['\n', '\t']) {
        outcome.text = outcome.text.replace(['\n', '\t'], " ");
    }
    let trimmed = outcome.text.trim();
    if trimmed.len() != outcome.text.len() {
        outcome.text = trimmed.to_owned();
    }
    outcome
}

/// Truncate `text` to at most `max` bytes on a `char` boundary. For display
/// strings only: an id or a link target is refused when it is too long, never
/// shortened.
#[must_use]
pub fn truncate_on_char_boundary(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut boundary = max;
        while boundary > 0 && !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::collected_item::is_sanitized_text;

    #[test]
    fn hidden_unicode_is_stripped_and_counted() {
        // "ignore" spelled in the TAG block, a right-to-left override, a
        // zero-width space inside a word, a word joiner, and a BOM.
        let tag_payload: String = "ignore"
            .chars()
            .map(|letter| char::from_u32(0xe_0000 + u32::from(letter)).unwrap())
            .collect();
        let raw = format!("retry{tag_payload} bud\u{200b}get \u{202e}5\u{202c}\u{2060}\u{feff}");
        let sanitized = sanitize_text(&raw);
        assert_eq!(sanitized.text, "retry budget 5");
        assert_eq!(sanitized.hidden_scalars_removed, 6 + 5);
        assert_eq!(sanitized.controls_folded, 0);
        assert!(!sanitized.is_lossy());
    }

    #[test]
    fn newlines_and_tabs_are_kept_and_other_controls_fold_to_a_space() {
        let sanitized = sanitize_text("a\r\nb\rc\td\u{0007}e\u{0000}f");
        assert_eq!(sanitized.text, "a\nb\nc\td e f");
        assert_eq!(sanitized.controls_folded, 2);
    }

    #[test]
    fn private_use_scalars_are_replaced_and_mark_the_text_lossy() {
        let sanitized = sanitize_text("icon \u{e000} and \u{fdd0} and \u{10fffd}");
        assert_eq!(sanitized.text, "icon \u{fffd} and \u{fffd} and \u{fffd}");
        assert_eq!(sanitized.replaced_scalars, 3);
        assert!(sanitized.is_lossy());
    }

    #[test]
    fn output_is_nfc_even_when_a_hidden_scalar_split_a_composition() {
        // e, ZWJ, combining acute: removing the joiner leaves e + U+0301,
        // which composes to U+00E9.
        let sanitized = sanitize_text("cafe\u{200d}\u{301}");
        assert_eq!(sanitized.text, "caf\u{e9}");
    }

    #[test]
    fn sanitizing_is_idempotent_and_reaches_the_contract_form() {
        for raw in [
            "plain",
            "tab\there\nline",
            "cafe\u{301}\u{200b}\r\n\u{202e}x\u{e0041}\u{e000}\u{7}",
            "",
        ] {
            let once = sanitize_text(raw);
            assert!(is_sanitized_text(&once.text), "{raw:?} did not sanitize");
            let twice = sanitize_text(&once.text);
            assert_eq!(twice.text, once.text);
            assert_eq!(twice.hidden_scalars_removed, 0);
            assert_eq!(twice.controls_folded, 0);
            assert_eq!(twice.replaced_scalars, 0);
        }
    }

    #[test]
    fn a_line_folds_newlines_and_tabs_and_trims() {
        let sanitized = sanitize_line("  plat\u{200b}-eng\n\tteam  ");
        assert_eq!(sanitized.text, "plat-eng  team");
        assert_eq!(sanitized.hidden_scalars_removed, 1);
    }

    #[test]
    fn truncation_never_splits_a_scalar() {
        assert_eq!(truncate_on_char_boundary("caf\u{e9}".to_owned(), 4), "caf");
        assert_eq!(truncate_on_char_boundary("abc".to_owned(), 8), "abc");
    }
}
