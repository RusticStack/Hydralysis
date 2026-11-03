//! The text Python gives for a document it cannot read, so a refusal reads the same from either implementation.
//!
//! `durable._classify` reports an unreadable record file as `unparseable (<reason>)`, where the reason is
//! `str(exception)[:80]` of the `UnicodeDecodeError` from `raw.decode("utf-8")` or of the `json.JSONDecodeError` from
//! `json.loads`. serde_json words its refusals differently, and callers (and tests) match on Python's words, so this
//! module reproduces them. It is only run on the error path, after serde_json has refused the bytes.
//!
//! [`decode_error`] is a transcription of the reference decoder (`Lib/json/decoder.py`: `JSONObject`, `JSONArray`,
//! `py_scanstring`, `JSONDecoder.decode`) with the wording of the C scanner that `json.loads` really uses (it names no
//! character in "Invalid control character at" and "Invalid \escape", and puts the latter at the backslash); positions
//! are in characters (code points), as Python indexes a `str`. A document that Python accepts yields `None`. Known gap:
//! Python also reads `NaN`, `Infinity` and `-Infinity` (a value `serde_json` cannot hold), so such a document is refused
//! by the Rust reader with serde's wording instead of being read.

/// A document nested deeper than this is left to the caller (Python raises `RecursionError`, not a decode error).
const MAX_DEPTH: usize = 900;

struct Failure {
    message: String,
    position: usize,
}

type Scan<T> = Result<T, Failure>;

/// Python's refusal of the UTF-8 BYTES, as `str(UnicodeDecodeError)`; `None` when they decode.
pub fn utf8_error(raw: &[u8]) -> Option<String> {
    let error = std::str::from_utf8(raw).err()?;
    let start = error.valid_up_to();
    let first = raw[start];
    let Some(length) = error.error_len() else {
        // A sequence cut off by the end of the data: Python names every byte of it.
        return Some(if raw.len() - start == 1 {
            format!("'utf-8' codec can't decode byte 0x{first:02x} in position {start}: unexpected end of data")
        } else {
            format!("'utf-8' codec can't decode bytes in position {start}-{}: unexpected end of data", raw.len() - 1)
        });
    };
    let reason = if (0xC2..=0xF4).contains(&first) { "invalid continuation byte" } else { "invalid start byte" };
    if length == 1 {
        Some(format!("'utf-8' codec can't decode byte 0x{first:02x} in position {start}: {reason}"))
    } else {
        Some(format!("'utf-8' codec can't decode bytes in position {start}-{}: {reason}", start + length - 1))
    }
}

/// `str(json.JSONDecodeError)` that `json.loads(text)` raises, or `None` when Python reads TEXT.
pub fn decode_error(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let failure = if chars.first() == Some(&'\u{feff}') {
        Failure { message: "Unexpected UTF-8 BOM (decode using utf-8-sig)".into(), position: 0 }
    } else {
        match (Decoder { chars: &chars }).document() {
            Ok(()) => return None,
            Err(failure) => failure,
        }
    };
    if failure.message.is_empty() {
        return None; // too deep: not a decode error in Python
    }
    let before = &chars[..failure.position.min(chars.len())];
    let line = before.iter().filter(|&&c| c == '\n').count() + 1;
    let column = match before.iter().rposition(|&c| c == '\n') {
        Some(at) => failure.position - at,
        None => failure.position + 1,
    };
    Some(format!("{}: line {line} column {column} (char {})", failure.message, failure.position))
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn fail<T>(message: &str, position: usize) -> Scan<T> {
    Err(Failure { message: message.to_string(), position })
}

struct Decoder<'a> {
    chars: &'a [char],
}

impl Decoder<'_> {
    fn at(&self, index: usize) -> Option<char> {
        self.chars.get(index).copied()
    }

    /// `WHITESPACE.match(s, index).end()`; an INDEX past the end counts as the end.
    fn skip_space(&self, index: usize) -> usize {
        let mut index = index.min(self.chars.len());
        while self.at(index).is_some_and(is_space) {
            index += 1;
        }
        index
    }

    /// `JSONDecoder.decode`: the value, then only whitespace.
    fn document(&self) -> Scan<()> {
        let start = self.skip_space(0);
        let end = self.value(start, 0)?;
        let end = self.skip_space(end);
        if end != self.chars.len() {
            return fail("Extra data", end);
        }
        Ok(())
    }

    /// `scan_once`: the end of the value at INDEX; `StopIteration(idx)` becomes "Expecting value" at idx.
    fn value(&self, index: usize, depth: usize) -> Scan<usize> {
        if depth > MAX_DEPTH {
            return Err(Failure { message: String::new(), position: index });
        }
        let Some(first) = self.at(index) else { return fail("Expecting value", index) };
        match first {
            '"' => self.string(index + 1).map(|(end, _)| end),
            '{' => self.object(index + 1, depth),
            '[' => self.array(index + 1, depth),
            _ => {
                for word in ["null", "true", "false", "NaN", "Infinity", "-Infinity"] {
                    if self.literal(index, word) {
                        return Ok(index + word.len());
                    }
                }
                if let Some(end) = self.number(index) {
                    return Ok(end);
                }
                fail("Expecting value", index)
            }
        }
    }

    fn literal(&self, index: usize, word: &str) -> bool {
        word.chars().enumerate().all(|(offset, c)| self.at(index + offset) == Some(c))
    }

    /// `-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`
    fn number(&self, start: usize) -> Option<usize> {
        let digit = |index: usize| self.at(index).is_some_and(|c| c.is_ascii_digit());
        let mut index = start;
        if self.at(index) == Some('-') {
            index += 1;
        }
        match self.at(index) {
            Some('0') => index += 1,
            Some('1'..='9') => {
                while digit(index) {
                    index += 1;
                }
            }
            _ => return None,
        }
        if self.at(index) == Some('.') && digit(index + 1) {
            index += 1;
            while digit(index) {
                index += 1;
            }
        }
        if matches!(self.at(index), Some('e' | 'E')) {
            let mut at = index + 1;
            if matches!(self.at(at), Some('-' | '+')) {
                at += 1;
            }
            if digit(at) {
                while digit(at) {
                    at += 1;
                }
                index = at;
            }
        }
        Some(index)
    }

    /// `py_scanstring(s, end)`: END is the index after the opening quote; returns (index after the closing quote, begin).
    fn string(&self, mut end: usize) -> Scan<(usize, usize)> {
        let begin = end - 1;
        loop {
            let Some(found) = (end..self.chars.len()).find(|&i| matches!(self.chars[i], '"' | '\\') || (self.chars[i] as u32) < 0x20) else {
                return fail("Unterminated string starting at", begin);
            };
            let terminator = self.chars[found];
            end = found + 1;
            if terminator == '"' {
                return Ok((end, begin));
            }
            if terminator != '\\' {
                return fail("Invalid control character at", end - 1);
            }
            let Some(escape) = self.at(end) else { return fail("Unterminated string starting at", begin) };
            if escape == 'u' {
                let unit = self.hex4(end)?;
                end += 5;
                if (0xD800..=0xDBFF).contains(&unit) && self.at(end) == Some('\\') && self.at(end + 1) == Some('u') {
                    let second = self.hex4(end + 1)?;
                    if (0xDC00..=0xDFFF).contains(&second) {
                        end += 6;
                    }
                }
            } else if matches!(escape, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') {
                end += 1;
            } else {
                return fail("Invalid \\escape", end - 1);
            }
        }
    }

    /// `_decode_uXXXX(s, pos)`: four hex digits after the `u` at POS.
    fn hex4(&self, at: usize) -> Scan<u32> {
        let mut value = 0u32;
        for offset in 1..=4 {
            match self.at(at + offset).and_then(|c| c.to_digit(16)) {
                Some(d) => value = value * 16 + d,
                None => return fail("Invalid \\uXXXX escape", at),
            }
        }
        Ok(value)
    }

    /// `JSONObject`: END is the index after `{`; returns the index after `}`.
    fn object(&self, mut end: usize, depth: usize) -> Scan<usize> {
        let mut next = self.at(end);
        if next != Some('"') {
            if next.is_none_or(is_space) {
                end = self.skip_space(end);
                next = self.at(end);
            }
            if next == Some('}') {
                return Ok(end + 1);
            } else if next != Some('"') {
                return fail("Expecting property name enclosed in double quotes", end);
            }
        }
        end += 1;
        loop {
            end = self.string(end)?.0;
            if self.at(end) != Some(':') {
                end = self.skip_space(end);
                if self.at(end) != Some(':') {
                    return fail("Expecting ':' delimiter", end);
                }
            }
            end += 1;
            if self.at(end).is_some_and(is_space) {
                end += 1;
                if self.at(end).is_some_and(is_space) {
                    end = self.skip_space(end + 1);
                }
            }
            end = self.value(end, depth + 1)?;
            let mut after = self.at(end);
            if after.is_some_and(is_space) {
                end = self.skip_space(end + 1);
                after = self.at(end);
            }
            end += 1;
            match after {
                Some('}') => return Ok(end),
                Some(',') => {}
                _ => return fail("Expecting ',' delimiter", end - 1),
            }
            let comma = end - 1;
            end = self.skip_space(end);
            let key = self.at(end);
            end += 1;
            if key != Some('"') {
                if key == Some('}') {
                    return fail("Illegal trailing comma before end of object", comma);
                }
                return fail("Expecting property name enclosed in double quotes", end - 1);
            }
        }
    }

    /// `JSONArray`: END is the index after `[`; returns the index after `]`.
    fn array(&self, mut end: usize, depth: usize) -> Scan<usize> {
        let mut next = self.at(end);
        if next.is_none_or(is_space) {
            end = self.skip_space(end + 1);
            next = self.at(end);
        }
        if next == Some(']') {
            return Ok(end + 1);
        }
        loop {
            end = self.value(end, depth + 1)?;
            let mut after = self.at(end);
            if after.is_none_or(is_space) {
                end = self.skip_space(end + 1);
                after = self.at(end);
            }
            end += 1;
            match after {
                Some(']') => return Ok(end),
                Some(',') => {}
                _ => return fail("Expecting ',' delimiter", end - 1),
            }
            let comma = end - 1;
            if self.at(end).is_some_and(is_space) {
                end += 1;
                if self.at(end).is_some_and(is_space) {
                    end = self.skip_space(end + 1);
                }
            }
            if self.at(end) == Some(']') {
                return fail("Illegal trailing comma before end of array", comma);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_error, utf8_error};

    /// Each expected text was produced by `json.loads` on Python 3.15 (the differential test in tests/test_rust_pyjson.py
    /// compares thousands of mutated documents; these pin the wording where no Python is at hand).
    #[test]
    fn json_refusals_read_as_python_words() {
        let cases = [
            ("{broken", "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"),
            ("{\"a\": 1,}", "Illegal trailing comma before end of object: line 1 column 8 (char 7)"),
            ("[1,]", "Illegal trailing comma before end of array: line 1 column 3 (char 2)"),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            ("{\"a\" 1}", "Expecting ':' delimiter: line 1 column 6 (char 5)"),
            ("\"a\nb\"", "Invalid control character at: line 1 column 3 (char 2)"),
            ("\"\\q\"", "Invalid \\escape: line 1 column 2 (char 1)"),
            ("\"\\u12\"", "Invalid \\uXXXX escape: line 1 column 3 (char 2)"),
            ("{\"a\": 1} x", "Extra data: line 1 column 10 (char 9)"),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            ("{\"a\": 1,\n \"b\": ?}", "Expecting value: line 2 column 7 (char 15)"),
            ("\u{feff}{}", "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)"),
            ("{\"a\": tru}", "Expecting value: line 1 column 7 (char 6)"),
        ];
        for (document, expected) in cases {
            assert_eq!(decode_error(document).as_deref(), Some(expected), "{document:?}");
        }
    }

    #[test]
    fn a_document_python_reads_is_not_an_error() {
        for document in ["{}", "[1, 2.5e3, \"x\", null, true]", " {\"a\": {\"b\": []}} \n", "NaN", "[-Infinity]"] {
            assert_eq!(decode_error(document), None, "{document:?}");
        }
    }

    #[test]
    fn utf8_refusals_read_as_python_words() {
        assert_eq!(utf8_error(b"{}"), None);
        assert_eq!(utf8_error(b"\xff").as_deref(), Some("'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"));
        assert_eq!(utf8_error(b"a\xc3").as_deref(), Some("'utf-8' codec can't decode byte 0xc3 in position 1: unexpected end of data"));
        assert_eq!(
            utf8_error(b"\xe2\x82").as_deref(),
            Some("'utf-8' codec can't decode bytes in position 0-1: unexpected end of data")
        );
        assert_eq!(
            utf8_error(b"\xe2\x82x").as_deref(),
            Some("'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte")
        );
    }
}
