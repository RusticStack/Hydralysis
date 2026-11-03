//! The clean case of `hydralysis.trace.read_jsonl`: a JSONL file of producer events in which every line is a JSON object
//! that satisfies the event schema and has a canonical form.
//!
//! Anything else (a torn tail, a corrupt line, an over-the-bound file, a line that is not canonical) is left to the Python
//! implementation, which writes the reasons the callers show: [`read_clean`] answers `None` and the Python reads the file
//! again from the top. A clean file is by far the common case and the one that is large.

use crate::Result;
use crate::canon::check;
use crate::schema::Schema;
use serde_json::Value;

/// The events of a clean file and the number of lines the Python reports (`len(lines)`).
#[derive(Debug, Clone, PartialEq)]
pub struct Clean {
    pub events: Vec<Value>,
    pub lines: usize,
}

/// `bytes.strip()` is empty: only ASCII white space.
fn blank(line: &[u8]) -> bool {
    line.iter().all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

/// How [`read_clean_with`] stopped early.
#[derive(Debug)]
pub enum Visit<E> {
    /// The schema check could not be made.
    Schema(crate::Error),
    /// The caller's sink refused an event.
    Sink(E),
}

/// Offer each event of DATA to SINK while the file is clean; the number of lines (`len(lines)` of the Python) when it was, else
/// `None` (the caller then discards what the sink took). DATA is not blank (the Python answers `empty` for that first) and
/// has at most MAX_EVENTS events. Events are handed over one at a time so the caller never holds them all as parsed values.
pub fn read_clean_with<E>(
    data: &[u8],
    max_events: usize,
    schema: &Schema,
    mut sink: impl FnMut(Value) -> std::result::Result<(), E>,
) -> std::result::Result<Option<usize>, Visit<E>> {
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    let (mut lines, mut taken) = (0usize, 0usize);
    for raw in body.split(|&b| b == b'\n') {
        lines += 1;
        if blank(raw) {
            continue;
        }
        let Ok(event) = serde_json::from_slice::<Value>(raw) else { return Ok(None) };
        if !event.is_object() || !schema.accepts(&event).map_err(Visit::Schema)? || check(&event).is_err() {
            return Ok(None);
        }
        if taken >= max_events {
            return Ok(None);
        }
        taken += 1;
        sink(event).map_err(Visit::Sink)?;
    }
    Ok(Some(lines))
}

/// The events of DATA when the file is clean, else `None`; see [`read_clean_with`].
pub fn read_clean(data: &[u8], max_events: usize, schema: &Schema) -> Result<Option<Clean>> {
    let mut events = Vec::new();
    let lines = read_clean_with(data, max_events, schema, |event| {
        events.push(event);
        Ok::<(), std::convert::Infallible>(())
    });
    match lines {
        Ok(lines) => Ok(lines.map(|lines| Clean { events, lines })),
        Err(Visit::Schema(error)) => Err(error),
        Err(Visit::Sink(never)) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Schema {
        let text = include_str!("../../../../src/hydralysis/trace_schema/event.schema.json");
        Schema::compile(&serde_json::from_str(text).unwrap()).unwrap()
    }

    fn line(seq: u64) -> String {
        json!({"kind": "app.tick", "source_id": "s", "source_seq": seq, "producer_gen": 1, "clock_domain": "m",
               "t_mono_ns": seq, "confidence": "exact", "payload": {"k": "\u{e9}"}})
        .to_string()
    }

    #[test]
    fn a_clean_file_gives_its_events_and_line_count() {
        let text = format!("{}\n\n  \n{}\r\n{}\n", line(0), line(1), line(2));
        let clean = read_clean(text.as_bytes(), 10, &schema()).unwrap().unwrap();
        assert_eq!(clean.events.len(), 3);
        assert_eq!(clean.lines, 5);
        let unterminated = format!("{}\n{}", line(0), line(1));
        assert_eq!(read_clean(unterminated.as_bytes(), 10, &schema()).unwrap().unwrap().lines, 2);
    }

    #[test]
    fn every_kind_of_damage_is_left_to_the_python() {
        let bad_kind = line(1).replace("app.tick", "Bad");
        let float = line(1).replace("\"source_seq\":1", "\"source_seq\":1.0");
        for text in [
            format!("{}\n{{broken", line(0)),
            format!("{}\n{}\n", line(0), bad_kind),
            format!("{}\n[1]\n", line(0)),
            format!("{}\n{}\n", line(0), float),
            format!("{}\n\u{ff}\n", line(0)),
        ] {
            assert_eq!(read_clean(text.as_bytes(), 10, &schema()).unwrap(), None, "{text:?}");
        }
        let two = format!("{}\n{}\n", line(0), line(1));
        assert_eq!(read_clean(two.as_bytes(), 1, &schema()).unwrap(), None, "over the bound");
        assert!(read_clean(two.as_bytes(), 2, &schema()).unwrap().is_some());
    }
}
