//! Sectioning one document into parts: markdown by its headings, and any other
//! text by its paragraphs (ADR 0008 D8).
//!
//! Every function here is pure and works on byte offsets into the source, so a
//! section's `span` names exactly the bytes its text came from: the sections
//! of one source are contiguous, never overlap, and concatenate back to the
//! whole source, front matter and blank lines included.
//!
//! # Markdown
//!
//! * **Front matter.** A source that opens with a `---` line and closes it
//!   with a `---` or `...` line has YAML front matter. Its top-level `title`
//!   and `status` scalars are read; its bytes stay in the first section.
//! * **Headings.** An ATX heading (`#` to `######`) or a setext heading (a
//!   paragraph underlined with `=` or `-`) starts a section. A section's
//!   anchor is its heading path, `Top > Sub > Leaf`; text before the first
//!   heading has none. Nothing inside a fenced code block (three or more
//!   backticks or tildes) is a heading.
//! * **Blank sections** (only whitespace) join the section that follows them,
//!   or the one before at the end, so no part is empty.
//! * **Large sections** are split at blank lines outside code fences into
//!   pieces of at most the part bound, each keeping its section's anchor. A
//!   fence is only cut when it alone is larger than a part, at a line break.
//! * **Many sections.** A version holds at most [`MAX_PARTS`] parts, so when a
//!   document has more sections than that, consecutive sections are packed
//!   into pieces of at most the part bound; a packed piece takes its first
//!   section's anchor.
//!
//! # Other text
//!
//! A plain-text, `reStructuredText`, or `AsciiDoc` source is one unanchored
//! section, split at blank lines like a large markdown section.

use crate::memory_contracts::collected_item::{MAX_PART_TEXT_BYTES, MAX_PARTS};

/// One section: a half-open byte range of the source, and its heading path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionV1 {
    /// The heading path, `Top > Sub > Leaf`; `None` before the first heading.
    pub anchor: Option<String>,
    /// First byte.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
}

/// What one markdown source says about itself, and its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownOutlineV1 {
    /// The front matter's `title`.
    pub front_matter_title: Option<String>,
    /// The front matter's `status`.
    pub status: Option<String>,
    /// The text of the first level-1 heading.
    pub first_heading: Option<String>,
    /// The sections, in source order.
    pub sections: Vec<SectionV1>,
}

impl MarkdownOutlineV1 {
    /// The document's title: the front matter's, else its first level-1
    /// heading, with the front matter's status after it when it has one.
    #[must_use]
    pub fn title(&self) -> Option<String> {
        let title = self
            .front_matter_title
            .clone()
            .or_else(|| self.first_heading.clone())?;
        Some(match &self.status {
            Some(status) => format!("{title} (status: {status})"),
            None => title,
        })
    }
}

/// One source line: its byte range, with its line break, and its text
/// without the line break.
#[derive(Debug, Clone, Copy)]
struct LineV1<'a> {
    start: usize,
    end: usize,
    text: &'a str,
}

fn lines(source: &str) -> Vec<LineV1<'_>> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < source.len() {
        let end = source[start..]
            .find('\n')
            .map_or(source.len(), |index| start + index + 1);
        let text = source[start..end]
            .strip_suffix('\n')
            .unwrap_or_else(|| &source[start..end]);
        let text = text.strip_suffix('\r').unwrap_or(text);
        lines.push(LineV1 { start, end, text });
        start = end;
    }
    lines
}

fn is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// The text after at most three spaces of indentation, or `None` for an
/// indented code line.
fn unindented(text: &str) -> Option<&str> {
    let spaces = text.bytes().take_while(|byte| *byte == b' ').count();
    (spaces <= 3).then(|| &text[spaces..])
}

/// A code fence line: its character and length.
fn fence(text: &str) -> Option<(char, usize)> {
    let rest = unindented(text)?;
    let marker = rest.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let length = rest.chars().take_while(|scalar| *scalar == marker).count();
    if length < 3 {
        return None;
    }
    // A backtick fence's info string holds no backtick.
    if marker == '`' && rest[length..].contains('`') {
        return None;
    }
    Some((marker, length))
}

/// Whether `text` closes a fence opened with `open`.
fn closes(text: &str, open: (char, usize)) -> bool {
    let Some(rest) = unindented(text) else {
        return false;
    };
    let length = rest.chars().take_while(|scalar| *scalar == open.0).count();
    length >= open.1 && is_blank(&rest[length * open.0.len_utf8()..])
}

/// An ATX heading: its level and text.
fn atx_heading(text: &str) -> Option<(usize, String)> {
    let rest = unindented(text)?;
    let level = rest.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let after = &rest[level..];
    if !(after.is_empty() || after.starts_with(' ') || after.starts_with('\t')) {
        return None;
    }
    let mut content = after.trim();
    // A closing run of `#`, preceded by a space, is not part of the text.
    let trimmed = content.trim_end_matches('#');
    if trimmed.is_empty() {
        content = "";
    } else if trimmed.len() < content.len() && trimmed.ends_with([' ', '\t']) {
        content = trimmed.trim_end();
    }
    Some((level, content.to_owned()))
}

/// A setext underline: the level it gives the paragraph above it.
fn setext_underline(text: &str) -> Option<usize> {
    let rest = unindented(text)?.trim_end();
    let marker = rest.chars().next()?;
    let level = match marker {
        '=' => 1,
        '-' => 2,
        _ => return None,
    };
    rest.chars().all(|scalar| scalar == marker).then_some(level)
}

/// Whether `text` can be a line of a paragraph a setext underline turns into
/// a heading: not blank, not indented code, not a heading, a fence, a list
/// item, a quote, or a thematic break.
fn is_paragraph_line(text: &str) -> bool {
    let Some(rest) = unindented(text) else {
        return false;
    };
    if is_blank(rest) || atx_heading(text).is_some() || fence(text).is_some() {
        return false;
    }
    if rest.starts_with('>') {
        return false;
    }
    let list_marker = |marker: char| {
        rest.strip_prefix(marker)
            .is_some_and(|after| after.is_empty() || after.starts_with([' ', '\t']))
    };
    if list_marker('-') || list_marker('*') || list_marker('+') {
        return false;
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let after = &rest[digits..];
        if (after.starts_with('.') || after.starts_with(')'))
            && (after.len() == 1 || after[1..].starts_with([' ', '\t']))
        {
            return false;
        }
    }
    // A line of only `-`, `*`, or `_` (with spaces) is a thematic break.
    let marks: String = rest
        .chars()
        .filter(|scalar| !scalar.is_whitespace())
        .collect();
    !(marks.len() >= 3
        && ['-', '*', '_']
            .iter()
            .any(|mark| marks.chars().all(|scalar| scalar == *mark)))
}

/// The front matter: the index of the first line after it, and its `title`
/// and `status`.
fn front_matter(lines: &[LineV1<'_>]) -> (usize, Option<String>, Option<String>) {
    if lines
        .first()
        .is_none_or(|line| line.text.trim_end() != "---")
    {
        return (0, None, None);
    }
    let Some(close) = lines
        .iter()
        .skip(1)
        .position(|line| matches!(line.text.trim_end(), "---" | "..."))
        .map(|index| index + 1)
    else {
        return (0, None, None);
    };
    let mut title = None;
    let mut status = None;
    for line in &lines[1..close] {
        // Top-level keys only: an indented line belongs to a nested value.
        if line.text.starts_with([' ', '\t']) {
            continue;
        }
        let Some((key, value)) = line.text.split_once(':') else {
            continue;
        };
        let value = scalar(value);
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "title" => title = Some(value),
            "status" => status = Some(value),
            _ => {}
        }
    }
    (close + 1, title, status)
}

/// One YAML scalar on one line, unquoted.
fn scalar(value: &str) -> String {
    let value = value.trim();
    let unquoted = ['"', '\'']
        .iter()
        .find_map(|quote| {
            value
                .strip_prefix(*quote)
                .and_then(|inner| inner.strip_suffix(*quote))
        })
        .unwrap_or(value);
    unquoted.trim().to_owned()
}

/// One heading found in the source: where its section starts, its level, and
/// its text.
struct HeadingV1 {
    start: usize,
    level: usize,
    text: String,
}

/// Every heading outside front matter and code fences, in order.
fn headings(lines: &[LineV1<'_>], body_from: usize) -> Vec<HeadingV1> {
    let mut found: Vec<HeadingV1> = Vec::new();
    let mut open: Option<(char, usize)> = None;
    // Where the paragraph the current line continues began, as a line index.
    let mut paragraph: Option<usize> = None;
    for (index, line) in lines.iter().enumerate().skip(body_from) {
        if let Some(fence_open) = open {
            if closes(line.text, fence_open) {
                open = None;
            }
            paragraph = None;
            continue;
        }
        if let Some(opened) = fence(line.text) {
            open = Some(opened);
            paragraph = None;
            continue;
        }
        if let Some((level, text)) = atx_heading(line.text) {
            found.push(HeadingV1 {
                start: line.start,
                level,
                text,
            });
            paragraph = None;
            continue;
        }
        if let (Some(level), Some(first)) = (setext_underline(line.text), paragraph) {
            let text = lines[first..index]
                .iter()
                .map(|line| line.text.trim())
                .collect::<Vec<_>>()
                .join(" ");
            found.push(HeadingV1 {
                start: lines[first].start,
                level,
                text,
            });
            paragraph = None;
            continue;
        }
        paragraph = if is_paragraph_line(line.text) {
            paragraph.or(Some(index))
        } else {
            None
        };
    }
    found
}

/// Outline one markdown source: front matter, the first level-1 heading, and
/// sections of at most [`MAX_PART_TEXT_BYTES`], at most [`MAX_PARTS`] of them
/// when the source fits in that many.
#[must_use]
pub fn outline_markdown(source: &str) -> MarkdownOutlineV1 {
    outline_markdown_within(source, MAX_PART_TEXT_BYTES, MAX_PARTS as usize)
}

/// [`outline_markdown`] under explicit bounds.
#[must_use]
pub fn outline_markdown_within(
    source: &str,
    max_bytes: usize,
    max_sections: usize,
) -> MarkdownOutlineV1 {
    let lines = lines(source);
    let (body_from, front_matter_title, status) = front_matter(&lines);
    let headings = headings(&lines, body_from);
    let first_heading = headings
        .iter()
        .find(|heading| heading.level == 1 && !heading.text.is_empty())
        .map(|heading| heading.text.clone());

    let mut sections = Vec::with_capacity(headings.len() + 1);
    let first_start = headings
        .first()
        .map_or(source.len(), |heading| heading.start);
    if first_start > 0 {
        sections.push(SectionV1 {
            anchor: None,
            start: 0,
            end: first_start,
        });
    }
    let mut path: Vec<(usize, String)> = Vec::new();
    for (index, heading) in headings.iter().enumerate() {
        while path
            .last()
            .is_some_and(|(level, _)| *level >= heading.level)
        {
            path.pop();
        }
        path.push((heading.level, heading.text.clone()));
        let anchor = path
            .iter()
            .map(|(_, text)| text.as_str())
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(" > ");
        sections.push(SectionV1 {
            anchor: (!anchor.is_empty()).then_some(anchor),
            start: heading.start,
            end: headings
                .get(index + 1)
                .map_or(source.len(), |next| next.start),
        });
    }
    let sections = join_blank_sections(source, sections);
    let sections = sections
        .into_iter()
        .flat_map(|section| split_section(source, &lines, &section, max_bytes))
        .collect();
    MarkdownOutlineV1 {
        front_matter_title,
        status,
        first_heading,
        sections: pack_sections(sections, max_bytes, max_sections),
    }
}

/// Section one plain source (text, reStructuredText, AsciiDoc): one
/// unanchored section, split at blank lines into pieces of at most
/// [`MAX_PART_TEXT_BYTES`].
#[must_use]
pub fn outline_plain(source: &str) -> Vec<SectionV1> {
    outline_plain_within(source, MAX_PART_TEXT_BYTES, MAX_PARTS as usize)
}

/// [`outline_plain`] under explicit bounds.
#[must_use]
pub fn outline_plain_within(source: &str, max_bytes: usize, max_sections: usize) -> Vec<SectionV1> {
    if source.is_empty() {
        return Vec::new();
    }
    let lines = lines(source);
    let whole = SectionV1 {
        anchor: None,
        start: 0,
        end: source.len(),
    };
    pack_sections(
        split_plain(source, &lines, &whole, max_bytes),
        max_bytes,
        max_sections,
    )
}

/// Join every whitespace-only section to the section after it (or, at the
/// end, before it), keeping the ranges contiguous.
fn join_blank_sections(source: &str, sections: Vec<SectionV1>) -> Vec<SectionV1> {
    let mut joined: Vec<SectionV1> = Vec::with_capacity(sections.len());
    let mut carried: Option<usize> = None;
    for mut section in sections {
        if let Some(start) = carried.take() {
            section.start = start;
        }
        if is_blank(&source[section.start..section.end]) {
            carried = Some(section.start);
            continue;
        }
        joined.push(section);
    }
    if let Some(start) = carried {
        match joined.last_mut() {
            Some(last) => last.end = source.len(),
            None => joined.push(SectionV1 {
                anchor: None,
                start,
                end: source.len(),
            }),
        }
    }
    joined
}

/// Split one markdown section at blank lines outside code fences into pieces
/// of at most `max_bytes`.
fn split_section(
    source: &str,
    lines: &[LineV1<'_>],
    section: &SectionV1,
    max_bytes: usize,
) -> Vec<SectionV1> {
    if section.end - section.start <= max_bytes {
        return vec![section.clone()];
    }
    // Candidate cuts: the start of each line after a blank line, outside a
    // fence; then, only if a piece still has none, any line start.
    let mut paragraph_cuts = Vec::new();
    let mut line_cuts = Vec::new();
    let mut open: Option<(char, usize)> = None;
    let mut previous_blank = false;
    for line in lines
        .iter()
        .filter(|line| line.start >= section.start && line.end <= section.end)
    {
        if line.start > section.start {
            line_cuts.push(line.start);
            if previous_blank && open.is_none() {
                paragraph_cuts.push(line.start);
            }
        }
        match open {
            Some(opened) if closes(line.text, opened) => open = None,
            Some(_) => {}
            None => open = fence(line.text),
        }
        previous_blank = open.is_none() && is_blank(line.text);
    }
    cut(source, section, max_bytes, &paragraph_cuts, &line_cuts)
}

/// Split one plain section at blank lines into pieces of at most `max_bytes`.
fn split_plain(
    source: &str,
    lines: &[LineV1<'_>],
    section: &SectionV1,
    max_bytes: usize,
) -> Vec<SectionV1> {
    if section.end - section.start <= max_bytes {
        return vec![section.clone()];
    }
    let mut paragraph_cuts = Vec::new();
    let mut line_cuts = Vec::new();
    let mut previous_blank = false;
    for line in lines {
        if line.start > section.start {
            line_cuts.push(line.start);
            if previous_blank {
                paragraph_cuts.push(line.start);
            }
        }
        previous_blank = is_blank(line.text);
    }
    cut(source, section, max_bytes, &paragraph_cuts, &line_cuts)
}

/// Cut `section` greedily at the furthest preferred cut inside the bound,
/// else the furthest line start, else the last character boundary.
fn cut(
    source: &str,
    section: &SectionV1,
    max_bytes: usize,
    preferred: &[usize],
    fallback: &[usize],
) -> Vec<SectionV1> {
    let mut pieces = Vec::new();
    let mut start = section.start;
    while section.end - start > max_bytes {
        let limit = start + max_bytes;
        let furthest = |cuts: &[usize]| {
            cuts.iter()
                .copied()
                .filter(|cut| *cut > start && *cut <= limit)
                .max()
        };
        let end = furthest(preferred)
            .or_else(|| furthest(fallback))
            .unwrap_or_else(|| {
                let mut end = limit;
                while !source.is_char_boundary(end) {
                    end -= 1;
                }
                if end == start {
                    // A bound smaller than one scalar: take it whole.
                    end = start + source[start..].chars().next().map_or(1, char::len_utf8);
                }
                end
            });
        pieces.push(SectionV1 {
            anchor: section.anchor.clone(),
            start,
            end,
        });
        start = end;
    }
    pieces.push(SectionV1 {
        anchor: section.anchor.clone(),
        start,
        end: section.end,
    });
    pieces
}

/// When there are more sections than `max_sections`, pack consecutive ones
/// into pieces of at most `max_bytes`; a packed piece keeps its first
/// section's anchor.
fn pack_sections(
    sections: Vec<SectionV1>,
    max_bytes: usize,
    max_sections: usize,
) -> Vec<SectionV1> {
    if sections.len() <= max_sections {
        return sections;
    }
    let mut packed: Vec<SectionV1> = Vec::new();
    for section in sections {
        match packed.last_mut() {
            Some(last) if section.end - last.start <= max_bytes => last.end = section.end,
            _ => packed.push(section),
        }
    }
    packed
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn texts<'a>(source: &'a str, sections: &[SectionV1]) -> Vec<&'a str> {
        sections
            .iter()
            .map(|section| &source[section.start..section.end])
            .collect()
    }

    fn anchors(sections: &[SectionV1]) -> Vec<Option<&str>> {
        sections
            .iter()
            .map(|section| section.anchor.as_deref())
            .collect()
    }

    /// The sections tile the source: contiguous, in order, and together
    /// exactly its bytes.
    fn assert_tiles(source: &str, sections: &[SectionV1]) {
        let mut at = 0;
        for section in sections {
            assert_eq!(section.start, at, "{sections:?}");
            assert!(section.end > section.start, "{sections:?}");
            at = section.end;
        }
        assert_eq!(at, source.len());
        assert_eq!(texts(source, sections).concat(), source);
    }

    #[test]
    fn atx_and_setext_headings_start_sections_with_their_heading_path() {
        // A setext heading's paragraph starts after a blank line: CommonMark
        // joins the lines of a paragraph into one heading.
        let source = "intro line\n\n# Retry policy\nbudget text\n## Backoff ##\njitter text\n\n\
                      Limits\n------\nlimit text\n\nAppendix\n===\nappendix text\n### Deep\ndeep\n";
        let outline = outline_markdown(source);
        assert_tiles(source, &outline.sections);
        assert_eq!(
            anchors(&outline.sections),
            [
                None,
                Some("Retry policy"),
                Some("Retry policy > Backoff"),
                Some("Retry policy > Limits"),
                Some("Appendix"),
                Some("Appendix > Deep"),
            ]
        );
        assert_eq!(
            texts(source, &outline.sections)[3],
            "Limits\n------\nlimit text\n\n"
        );
        let joined = outline_markdown("one\ntwo\n===\n");
        assert_eq!(anchors(&joined.sections), [Some("one two")]);
        assert_eq!(outline.first_heading.as_deref(), Some("Retry policy"));
        assert_eq!(outline.title().as_deref(), Some("Retry policy"));
    }

    #[test]
    fn a_hash_without_a_space_a_list_or_a_thematic_break_starts_nothing() {
        let source = "# Top\n#hashtag\n- item\n---\n\n***\ntext\n";
        let outline = outline_markdown(source);
        assert_eq!(anchors(&outline.sections), [Some("Top")]);
        assert_tiles(source, &outline.sections);
    }

    #[test]
    fn front_matter_supplies_title_and_status_and_stays_in_the_first_section() {
        let source = "---\ntitle: \"Retry budgets\"\nstatus: accepted\nauthors:\n  - title: nested\n---\n\
                      preface\n# Heading one\nbody\n";
        let outline = outline_markdown(source);
        assert_eq!(outline.front_matter_title.as_deref(), Some("Retry budgets"));
        assert_eq!(outline.status.as_deref(), Some("accepted"));
        assert_eq!(
            outline.title().as_deref(),
            Some("Retry budgets (status: accepted)")
        );
        assert_eq!(anchors(&outline.sections), [None, Some("Heading one")]);
        assert!(texts(source, &outline.sections)[0].starts_with("---\ntitle:"));
        assert_tiles(source, &outline.sections);

        // The front matter's closing `---` is not a setext underline, and an
        // unclosed opening line is not front matter.
        let unclosed = "---\ntitle: x\n# Real\n";
        let outline = outline_markdown(unclosed);
        assert_eq!(outline.front_matter_title, None);
        assert_eq!(anchors(&outline.sections), [None, Some("Real")]);
    }

    #[test]
    fn a_heading_inside_a_code_fence_is_code() {
        let source =
            "# Top\n```sh\n# not a heading\nrun\n```\n~~~~\n## nor this\n~~~\n~~~~\n## After\n";
        let outline = outline_markdown(source);
        assert_eq!(
            anchors(&outline.sections),
            [Some("Top"), Some("Top > After")]
        );
        assert!(texts(source, &outline.sections)[0].contains("# not a heading"));
        assert_tiles(source, &outline.sections);
    }

    #[test]
    fn blank_sections_join_their_neighbours() {
        let source = "\n\n# One\n\n# Two\ntext\n\n";
        let outline = outline_markdown(source);
        assert_tiles(source, &outline.sections);
        assert_eq!(outline.sections.len(), 2);
        assert_eq!(texts(source, &outline.sections)[0], "\n\n# One\n\n");
        assert!(
            outline
                .sections
                .iter()
                .all(|section| !is_blank(&source[section.start..section.end]))
        );
        let only_blank = "\n\n  \n";
        let sections = outline_markdown(only_blank).sections;
        assert_tiles(only_blank, &sections);
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn a_section_over_the_part_bound_splits_at_blank_lines_outside_fences() {
        let paragraph = format!("{}\n\n", "word ".repeat(2_000));
        let fenced = format!(
            "```\n{}\n\n{}\n```\n\n",
            "a".repeat(5_000),
            "b".repeat(5_000)
        );
        let source = format!(
            "# Big\n{}{fenced}{}",
            paragraph.repeat(4),
            paragraph.repeat(4)
        );
        assert!(source.len() > MAX_PART_TEXT_BYTES);
        let outline = outline_markdown(&source);
        assert_tiles(&source, &outline.sections);
        assert!(outline.sections.len() > 1);
        for (section, text) in outline
            .sections
            .iter()
            .zip(texts(&source, &outline.sections))
        {
            assert!(text.len() <= MAX_PART_TEXT_BYTES);
            assert_eq!(section.anchor.as_deref(), Some("Big"));
            // No piece starts inside the fence.
            let before = &source[..section.start];
            assert_eq!(
                before.matches("```").count() % 2,
                0,
                "a cut fell inside the code fence"
            );
        }
    }

    #[test]
    fn a_fence_larger_than_a_part_is_cut_at_a_line_break() {
        let line = format!("{}\n", "x".repeat(99));
        let source = format!("# Code\n```\n{}```\n", line.repeat(20));
        let outline = outline_markdown_within(&source, 500, 64);
        assert_tiles(&source, &outline.sections);
        for text in texts(&source, &outline.sections) {
            assert!(text.len() <= 500);
            assert!(text.ends_with('\n'));
        }
    }

    #[test]
    fn more_sections_than_parts_are_packed_under_the_bound() {
        let source = (0..100).fold(String::new(), |mut source, index| {
            let _ = write!(source, "# H{index}\ntext {index}\n");
            source
        });
        let outline = outline_markdown_within(&source, 200, 64);
        assert_tiles(&source, &outline.sections);
        assert!(outline.sections.len() <= 64);
        assert_eq!(outline.sections[0].anchor.as_deref(), Some("H0"));
        assert!(
            outline
                .sections
                .iter()
                .all(|section| section.end - section.start <= 200)
        );
        // Under the part count, nothing is packed.
        let few = (0..3).fold(String::new(), |mut few, index| {
            let _ = write!(few, "# H{index}\ntext\n");
            few
        });
        assert_eq!(outline_markdown(&few).sections.len(), 3);
    }

    #[test]
    fn plain_text_is_one_section_split_at_blank_lines() {
        assert!(outline_plain("").is_empty());
        let small = "one paragraph\n\nanother\n";
        assert_eq!(
            outline_plain(small),
            [SectionV1 {
                anchor: None,
                start: 0,
                end: small.len()
            }]
        );
        let big = format!("{}\n\n", "line of text ".repeat(100)).repeat(40);
        let sections = outline_plain_within(&big, 4_096, 64);
        assert_tiles(&big, &sections);
        assert!(sections.len() > 1);
        for text in texts(&big, &sections) {
            assert!(text.len() <= 4_096);
            assert!(text.ends_with("\n\n"), "cut at a blank line");
        }
    }

    #[test]
    fn crlf_line_endings_are_read_and_kept() {
        let source = "# One\r\ntext\r\n\r\nTwo\r\n===\r\nmore\r\n";
        let outline = outline_markdown(source);
        assert_eq!(anchors(&outline.sections), [Some("One"), Some("Two")]);
        assert_tiles(source, &outline.sections);
    }
}
