//! Rust re-expressions (same cases) of the white-box Python tests: tests/test_pe.py and tests/test_prologue_table.py.
//! See TESTMAP.md for the old -> new map.

use hy_query::prologue::{self, compare, compare_table, find_pattern, matches, parse_expect};
use hy_query::{Image, PeError, tools};
use serde_json::json;

struct Spec<'a> {
    text: &'a [u8],
    name: &'a [u8],
    machine: u16,
    virtual_size: u32,
    text_raw: u32,
}

impl Default for Spec<'_> {
    fn default() -> Self {
        Spec { text: b"", name: b".text", machine: 0x14C, virtual_size: 0x100, text_raw: 0x20 }
    }
}

fn put(d: &mut [u8], at: usize, bytes: &[u8]) {
    d[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Port of `image()` in tests/test_pe.py: two sections, virtual .text tail would alias .data on disk.
#[allow(clippy::type_complexity)]
fn image_bytes(spec: Spec) -> Vec<u8> {
    let default_text: Vec<u8> = [vec![0x90u8; 31], vec![0xC3]].concat();
    let text = if spec.text.is_empty() { &default_text[..] } else { spec.text };
    let data_off = 0x200 + spec.text_raw as usize;
    let data_va = 0x1000 + ((spec.text_raw + 0xFFF) & !0xFFF);
    let mut d = vec![0u8; data_off + 0x20];
    put(&mut d, 0, b"MZ");
    put(&mut d, 0x3C, &0x80u32.to_le_bytes());
    put(&mut d, 0x80, b"PE\0\0");
    put(&mut d, 0x84, &spec.machine.to_le_bytes());
    put(&mut d, 0x86, &2u16.to_le_bytes());
    put(&mut d, 0x84 + 16, &224u16.to_le_bytes());
    put(&mut d, 0x84 + 18, &0x102u16.to_le_bytes());
    let opt = 0x98;
    put(&mut d, opt, &0x10Bu16.to_le_bytes());
    put(&mut d, opt + 16, &0x1000u32.to_le_bytes());
    put(&mut d, opt + 28, &0x400000u32.to_le_bytes());
    put(&mut d, opt + 32, &0x1000u32.to_le_bytes());
    put(&mut d, opt + 36, &0x200u32.to_le_bytes());
    put(&mut d, opt + 56, &0x3000u32.to_le_bytes());
    put(&mut d, opt + 60, &0x200u32.to_le_bytes());
    put(&mut d, opt + 92, &16u32.to_le_bytes());
    let sections: [(&[u8], u32, u32, u32, u32, u32); 2] = [
        (spec.name, spec.virtual_size, 0x1000, spec.text_raw, 0x200, 0x6000_0020),
        (b".data", 0x20, data_va, 0x20, data_off as u32, 0xC000_0040),
    ];
    for (i, (label, vsize, rva, raw_size, raw_off, flags)) in sections.iter().enumerate() {
        let at = opt + 224 + i * 40;
        put(&mut d, at, label);
        for (j, v) in [vsize, rva, raw_size, raw_off].iter().enumerate() {
            put(&mut d, at + 8 + j * 4, &v.to_le_bytes());
        }
        put(&mut d, at + 36, &flags.to_le_bytes());
    }
    let mut t = text.to_vec();
    t.resize(spec.text_raw as usize, 0x90);
    put(&mut d, 0x200, &t);
    put(&mut d, data_off, &b"DATA".repeat(8));
    d
}

fn image(spec: Spec) -> Image {
    Image::from_vec("fixture.exe", image_bytes(spec)).unwrap()
}

fn value_err<T: std::fmt::Debug>(r: Result<T, PeError>) -> String {
    match r {
        Err(PeError::Value(m)) => m,
        other => panic!("expected ValueError, got {other:?}"),
    }
}

// ---- tests/test_pe.py::FileBackedReads ----

#[test]
fn string_search_returns_full_string_start_and_wide_text() {
    let mut text = b"\0prefixSuffix\0\0".to_vec();
    text.extend("Wide".encode_utf16().flat_map(u16::to_le_bytes));
    text.extend([0, 0]);
    let pe = image(Spec { text: &text, ..Spec::default() });
    let result = tools::find_strings(&pe, "Suffix|Wide", 10).unwrap();
    assert!(result.contains("0x1001 ascii prefixSuffix"), "{result}");
    assert!(result.contains("0x100f utf-16le Wide"), "{result}");
    assert!(!result.contains("0x1007 ascii Suffix"));
}

#[test]
fn virtual_tail_does_not_alias_next_section() {
    let pe = image(Spec::default());
    assert_eq!(pe.rva_to_offset(0x1020), None);
    assert!(value_err(pe.read_rva(0x1020, 4)).contains("not in a section"));
    assert!(value_err(pe.read_rva(0x101F, 2)).contains("file-backed"));
    assert_eq!(pe.read_rva(0x2000, 4).unwrap(), b"DATA");
}

#[test]
fn truncated_file_and_negative_reads_are_refused() {
    let full = image(Spec::default());
    let pe = Image::from_vec("fixture.exe", full.data()[..0x221].to_vec()).unwrap();
    assert!(value_err(pe.read_rva(0x2000, 2)).contains("file-backed"));
    assert!(value_err(pe.read_rva(0x1000, -1)).contains("non-negative"));
}

#[test]
fn disassembly_at_section_end_uses_available_bytes() {
    assert!(tools::disasm(&image(Spec::default()), 0x101F, 40).unwrap().contains("ret"));
}

#[test]
fn other_pe_architecture_is_not_silently_decoded_as_x64() {
    let pe = image(Spec { machine: 0x1C4, ..Spec::default() });
    assert!(value_err(tools::disasm(&pe, 0x1000, 40)).contains("x86/x64 only"));
}

// ---- tests/test_pe.py::ProvenanceAndCandidates ----

#[test]
fn header_keeps_full_build_hash() {
    let pe = image(Spec::default());
    assert!(pe.header().contains(&pe.fingerprint().sha256));
    assert_eq!(pe.fingerprint().sha256.len(), 64);
}

#[test]
fn wrapper_indicator_is_a_warning_not_a_packed_verdict() {
    let pe = image(Spec { name: b".bind", ..Spec::default() });
    assert!(pe.fingerprint().analysis_warnings.join(" ").contains(".bind"));
    assert!(pe.fingerprint().packing_status.contains("not proof"));
    assert!(pe.header().contains("executable SHA-256"));
    assert!(image(Spec::default()).fingerprint().analysis_warnings.is_empty());
    assert!(image(Spec::default()).fingerprint().packing_status.contains("not proof"));
}

#[test]
fn callees_does_not_decode_e8_inside_an_immediate() {
    // mov eax,0x909090e8; nop; ret -- its E8 byte is not a call opcode.
    let pe = image(Spec { text: &[0xB8, 0xE8, 0x90, 0x90, 0x90, 0x90, 0xC3], ..Spec::default() });
    assert!(tools::callees(&pe, 0x1000, 30).unwrap().contains("0 decoded direct call(s)"));
}

#[test]
fn last_possible_call_site_is_included_and_labelled_candidate() {
    let mut text = vec![0x90u8; 27];
    text.push(0xE8);
    text.extend((-32i32).to_le_bytes());
    let pe = image(Spec { text: &text, ..Spec::default() });
    let callers = tools::callers(&pe, 0x1000, 50).unwrap();
    assert!(callers.contains("rva:0x101b E8 call candidate -> rva:0x1000"), "{callers}");
    assert!(callers.contains("instruction boundaries unverified"));
    assert!(tools::callees(&pe, 0x1000, 30).unwrap().contains("rva:0x101b call rva:0x1000"));
}

// ---- tests/test_pe.py::SignatureVerification ----

#[test]
fn all_wildcards_cannot_validate_a_hook() {
    assert!(value_err(compare(&[0x90, 0x90], "?? ??")).contains("concrete byte"));
    assert!(value_err(find_pattern(b"abc", &[None, None], 10)).contains("concrete byte"));
    assert!(!matches(b"abc", &[None, None]));
    assert!(!matches(b"abc", &[]));
}

#[test]
fn anchored_search_handles_edges_overlap_and_limits() {
    let p = |s| parse_expect(s).unwrap();
    assert_eq!(find_pattern(b"aaa", &p("61 61"), 10).unwrap(), vec![0, 1]);
    assert_eq!(find_pattern(b"aXbaYb", &p("61 ?? 62"), 10).unwrap(), vec![0, 3]);
    assert_eq!(find_pattern(b"XaYa", &p("?? 61"), 1).unwrap(), vec![0]);
    assert_eq!(find_pattern(b"aXb", &p("61 ?? 62 ??"), 10).unwrap(), Vec::<usize>::new());
    assert_eq!(find_pattern(b"XaYb", &p("?? 61 ?? 62"), 10).unwrap(), vec![0]);
}

// ---- tests/test_prologue_table.py ----

#[test]
fn common_hook_table_forms_normalize_to_the_same_bytes() {
    let expected: Vec<Option<u8>> = hex_bytes("488bc448894808565741544156415748").into_iter().map(Some).collect();
    let comma = hex_bytes("488bc448894808565741544156415748").iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(",");
    let esc: String = hex_bytes("488bc448894808565741544156415748").iter().map(|b| format!("\\x{b:02x}")).collect();
    for text in [
        "488bc448894808565741544156415748",
        "0x488bc448894808565741544156415748",
        "48 8B C4 48 89 48 08 56 57 41 54 41 56 41 57 48",
        comma.as_str(),
        esc.as_str(),
    ] {
        assert_eq!(parse_expect(text).unwrap(), expected, "{text}");
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn wildcards_are_whole_bytes_and_need_a_literal() {
    assert_eq!(parse_expect("48??C4 ? 0x08").unwrap(), vec![Some(0x48), None, Some(0xC4), None, Some(8)]);
    for text in ["488", "4?", "48?C", "?? ??", "", "0x", "gg", "-1"] {
        assert!(parse_expect(text).is_err(), "{text}");
    }
}

/// A 0x20-byte image whose .text is all 0x90, base 0x400000 (the Mock in the Python test).
fn table_image() -> Image {
    image(Spec { text: &[0x90; 32], ..Spec::default() })
}

fn resolver(value: &str) -> Result<i64, String> {
    Ok(i64::from_str_radix(value.rsplit(':').next().unwrap().trim_start_matches("0x"), 16).unwrap_or(0x1000))
}

#[test]
fn twenty_one_rows_share_one_build_fingerprint() {
    let img = table_image();
    let rows: Vec<_> = (0..21).map(|i| json!({"name": format!("site{i}"), "address": "rva:0x1000", "expect": "9090"})).collect();
    let result = compare_table(&img, &json!(rows), &mut resolver).unwrap();
    assert_eq!(result["matched"], json!(true));
    assert_eq!(result["summary"], json!({"checked": 21, "matched": 21, "failed": 0}));
    assert_eq!(result["rows"][0]["va"], json!("va:0x401000"));
    assert_eq!(result["rows"][0]["rva"], json!("rva:0x1000"));
    assert_eq!(result["fingerprint"]["sha256"], json!(img.fingerprint().sha256));
}

#[test]
fn mismatch_is_retained_among_all_results() {
    let img = table_image();
    let rows = json!([{"address": "x", "expect": "90"}, {"address": "x", "expect": "91"}, {"address": "x", "expect": "??90"}]);
    let result = compare_table(&img, &rows, &mut |_| Ok(0x1000)).unwrap();
    assert_eq!(result["matched"], json!(false));
    let flags: Vec<_> = result["rows"].as_array().unwrap().iter().map(|r| r["match"].clone()).collect();
    assert_eq!(flags, vec![json!(true), json!(false), json!(true)]);
    assert_eq!(result["summary"], json!({"checked": 3, "matched": 2, "failed": 1}));
    assert_eq!(result["rows"][1]["actual"], json!("90"));
}

#[test]
fn a_row_may_accept_several_prologues_and_names_the_one_that_matched() {
    let img = table_image();
    let rows = json!([{"address": "x", "expect": ["48 8B", "90 90"]}, {"address": "x", "expect": ["48", "49"]}]);
    let result = compare_table(&img, &rows, &mut |_| Ok(0x1000)).unwrap();
    assert_eq!(result["rows"][0]["match"], json!(true));
    assert_eq!(result["rows"][1]["match"], json!(false));
    assert_eq!(result["rows"][0]["matched_alternative"], json!(1));
    assert!(result["rows"][1]["matched_alternative"].is_null());
    assert!(compare_table(&img, &json!([{"address": "x", "expect": []}]), &mut |_| Ok(0x1000)).is_err());
}

#[test]
fn all_rows_validate_before_any_bytes_are_read() {
    let img = table_image();
    let long = "90".repeat(4097);
    for bad in [
        json!({"address": "x", "expect": "??"}),
        json!({"address": "x", "expect": "90", "guess": true}),
        json!({"address": "x", "expect": long}),
        json!({"address": "x", "expect": "90", "name": 7}),
    ] {
        let rows = json!([{"address": "x", "expect": "90"}, bad]);
        assert!(compare_table(&img, &rows, &mut |_| Ok(0x1000)).is_err(), "{rows}");
    }
}

#[test]
fn file_backed_boundary_is_checked_before_reads() {
    let img = table_image();
    let rows = json!([{"address": "first", "expect": "90"}, {"address": "last", "expect": "9090"}]);
    let msg = value_err(compare_table(&img, &rows, &mut |v| Ok(if v == "first" { 0x1000 } else { 0x101f })));
    assert!(msg.contains("file-backed"), "{msg}");
}

#[test]
fn total_byte_budget_and_row_budget() {
    let img = image(Spec { text_raw: 100000, virtual_size: 100000, ..Spec::default() });
    let row = json!({"address": "x", "expect": "90".repeat(4096)});
    let rows = json!(vec![row.clone(); 17]);
    let msg = value_err(compare_table(&img, &rows, &mut |_| Ok(0x1000)));
    assert!(msg.contains("65536"), "{msg}");
    for rows in [json!([]), json!(vec![row.clone(); 201]), json!({}), json!(null)] {
        let msg = value_err(compare_table(&img, &rows, &mut |_| Ok(0x1000)));
        assert!(msg.contains("1..200"), "{msg}");
    }
}

#[test]
fn parse_rva_matches_python() {
    let base = 0x1_4000_0000;
    assert_eq!(prologue::parse_rva("rva:0x10", base).unwrap(), 0x10);
    assert_eq!(prologue::parse_rva("va:0x140000010", base).unwrap(), 0x10);
    assert_eq!(prologue::parse_rva("0x140000010", base).unwrap(), 0x10);
    assert_eq!(prologue::parse_rva("0x10", base).unwrap(), 0x10);
    assert!(prologue::parse_rva("va:0x10", base).is_err());
    assert!(prologue::parse_rva("zz:1", base).is_err());
    assert!(prologue::parse_rva("-3", base).is_err());
}

// ---- tests/test_client.py::ImportSlots (white-box: patched pefile objects) ----

#[test]
fn each_import_names_its_iat_slot_and_a_pattern_filters() {
    // import descriptor at 0x1000, ILT at 0x1040, hint/names at 0x1060/0x1070, DLL name at 0x1080, IAT slots at 0x2010
    let mut text = vec![0u8; 0x100];
    let w32 = |t: &mut Vec<u8>, at: usize, v: u32| t[at..at + 4].copy_from_slice(&v.to_le_bytes());
    w32(&mut text, 0, 0x1040); // OriginalFirstThunk
    w32(&mut text, 12, 0x1080); // Name
    w32(&mut text, 16, 0x2010); // FirstThunk
    w32(&mut text, 0x40, 0x1060);
    w32(&mut text, 0x44, 0x1070);
    w32(&mut text, 0x48, 0x8000_0007); // by ordinal 7
    text[0x62..0x6a].copy_from_slice(b"glClear ");
    text[0x72..0x7a].copy_from_slice(b"glFlush ");
    text[0x80..0x8c].copy_from_slice(b"OPENGL32.dll");
    let mut bytes = image_bytes(Spec { text: &text, text_raw: 0x100, ..Spec::default() });
    // data directory 1 (imports) of the PE32 optional header at 0x98: directories start at +96, entry 1 at +104
    bytes[0x98 + 104..0x98 + 108].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[0x98 + 108..0x98 + 112].copy_from_slice(&40u32.to_le_bytes());
    let pe = Image::from_vec("fixture.exe", bytes).unwrap();
    let listed = tools::imports_text(&pe, 10, "").unwrap();
    assert!(listed.contains("rva:0x2010 OPENGL32.dll glClear"), "{listed}");
    assert!(listed.contains("rva:0x2018 OPENGL32.dll ord:7"), "{listed}");
    let filtered = tools::imports_text(&pe, 10, "glclear").unwrap();
    assert!(!filtered.contains("glFlush"));
}
