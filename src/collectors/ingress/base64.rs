//! Strict base64 (RFC 4648 section 4: the standard alphabet, padded), for
//! Standard Webhooks signatures and `whsec_` secrets (ADR 0008 D12).
//!
//! Decoding accepts exactly one text per byte string: its length is a
//! multiple of four, padding appears only at the end of the last quantum,
//! every other character is in the alphabet, and the bits padding leaves
//! unused are zero. Anything else (whitespace, the URL-safe alphabet, a
//! missing or extra `=`) is refused rather than repaired, so a signature
//! entry is either exactly one tag or ignored.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Encode `bytes`, padded.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - 6 * index;
                text.push(char::from(ALPHABET[((bits >> shift) & 0x3f) as usize]));
            } else {
                text.push('=');
            }
        }
    }
    text
}

/// Decode `text`, or `None` when it is not exactly the canonical encoding of
/// some bytes. See the module documentation.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let quanta = bytes.len() / 4;
    let mut decoded = Vec::with_capacity(quanta * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding > 0 && index + 1 != quanta) {
            return None;
        }
        let mut sextets = [0_u8; 4];
        for (slot, byte) in sextets.iter_mut().zip(&chunk[..4 - padding]) {
            *slot = sextet(*byte)?;
        }
        let bits = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        let [_, first, second, third] = bits.to_be_bytes();
        match padding {
            0 => decoded.extend([first, second, third]),
            // The bits a padded quantum leaves unused must be zero, so one
            // byte string has one encoding.
            1 if third == 0 => decoded.extend([first, second]),
            2 if second == 0 && third == 0 => decoded.push(first),
            _ => return None,
        }
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_4648_vectors_round_trip() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(
                decode(encoded).as_deref(),
                Some(plain.as_bytes()),
                "{encoded}"
            );
        }
        let every: Vec<u8> = (0..=255).collect();
        for length in 0..every.len() {
            assert_eq!(
                decode(&encode(&every[..length])).as_deref(),
                Some(&every[..length])
            );
        }
    }

    #[test]
    fn anything_but_the_canonical_padded_text_is_refused() {
        for text in [
            "Zg", "Zg=", "Zh==", "Zm9=", "Z===", "====", "Zg==Zg==", "Zm9v\n", " Zm9v", "Zm-_",
            "Zm9v=", "Zm=v",
        ] {
            assert_eq!(decode(text), None, "{text:?}");
        }
    }
}
