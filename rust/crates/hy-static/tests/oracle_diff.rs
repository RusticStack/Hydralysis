//! Differential checks of the static plane against the recorded Java oracle (`OracleProgram.java` over the stock
//! `ProgramDB`) and, for bytes, against the PE file the fixture project was analysed from.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hy_static::{Error, StaticProgram, Xref, address_text, answer};
use serde_json::json;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn analysed() -> StaticProgram {
    StaticProgram::open(&fixtures().join("legacy-12.1.4-analysed"), "/flow_fixture.exe").unwrap()
}

fn oracle() -> Vec<String> {
    std::fs::read_to_string(fixtures().join("oracle/oracleprog-legacy-12.1.4-analysed.txt")).unwrap().lines().map(str::to_owned).collect()
}

/// Value of ` key=` in an oracle line; bracketed values may hold spaces.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!(" {key}=");
    let start = line.find(&pat).map(|i| i + pat.len()).unwrap();
    let rest = &line[start..];
    if let Some(inner) = rest.strip_prefix('[') { &inner[..inner.find(']').unwrap()] } else { rest.split(' ').next().unwrap() }
}

/// `ram:140001000` to 0x140001000; `None` for another space.
fn ram(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("ram:")?, 16).ok()
}

fn oracle_ref_line(x: &Xref, dir_from: bool) -> String {
    let from = x.from.map_or_else(|| "EXT_FROM".to_owned(), |f| format!("ram:{f:x}"));
    let tag = if dir_from { "ref" } else { "toref" };
    format!(
        "{tag} from={from} to=ram:{:x} type={} op={} src={} primary={} kind={}",
        x.to, x.ref_type, x.op_index, x.source, x.primary, x.kind
    )
}

/// The oracle's reference lines grouped by the address the list is keyed by (to for `toref`, from for `ref`), in
/// file order, without the `sym=` column.
fn oracle_refs(lines: &[String], tag: &str) -> BTreeMap<String, Vec<String>> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in lines.iter().filter(|l| l.starts_with(&format!("{tag} from="))) {
        let key = if tag == "toref" { field(line, "to") } else { field(line, "from") };
        // drop ` sym=<id>`: the plane does not show the symbol id
        let sym = line.find(" sym=").unwrap();
        let after = line[sym + 1..].find(' ').map_or(line.len(), |i| sym + 1 + i);
        groups.entry(key.to_owned()).or_default().push(format!("{}{}", &line[..sym], &line[after..]));
    }
    groups
}

#[test]
fn identity_matches_the_oracle_and_the_project() {
    let p = analysed();
    let lines = oracle();
    let info = p.info();
    assert_eq!(info.name, "flow_fixture.exe");
    assert_eq!(info.program_path, "/flow_fixture.exe");
    assert_eq!(info.language, "x86:LE:64:default");
    assert_eq!(info.db_version, 32);
    assert_eq!(info.image_base, 0x1_4000_0000);
    assert_eq!(format!("image_base=ram:{:x}", info.image_base), lines[3]);
    assert_eq!(info.sha256, "d105b8ad8a5f549a8a2c205e95f71e1b84bcc7ec183f63ea9804442be855179b");
}

#[test]
fn xrefs_to_equal_the_oracle_for_every_stored_list_and_for_addresses_with_none() {
    let p = analysed();
    let lines = oracle();
    let groups = oracle_refs(&lines, "toref");
    let mut checked = 0;
    let mut declined = 0;
    for (key, expected) in &groups {
        let Some(to) = ram(key) else { continue };
        // Offset, shifted, external and stack kinds are declined, never shown partly.
        let plain = expected.iter().all(|l| l.ends_with("kind=MemReferenceDB") || l.ends_with("kind=EntryPointReferenceDB"));
        match p.xrefs_to(to) {
            Ok(got) => {
                assert!(plain, "{key}: answered a list holding another kind");
                let got: Vec<String> = got.iter().map(|x| oracle_ref_line(x, false)).collect();
                assert_eq!(&got, expected, "xrefs to {key}");
                checked += 1;
            }
            Err(Error::Unsupported(_)) => {
                assert!(!plain, "{key}: declined a plain list");
                declined += 1;
            }
            Err(other) => panic!("{key}: {other}"),
        }
    }
    assert!(checked > 1000, "only {checked} lists compared");
    // No stored list: empty, for every instruction address and a few others.
    let mut empty = 0;
    for l in lines.iter().filter(|l| l.starts_with("inst ")) {
        let at = ram(field(l, "addr")).expect("instruction address");
        if !groups.contains_key(&format!("ram:{at:x}")) {
            assert_eq!(p.xrefs_to(at).unwrap(), vec![], "no refs to ram:{at:x}");
            empty += 1;
        }
    }
    assert!(empty > 1000, "only {empty} empty answers compared");
    for at in [0u64, 1, 0x1000, 0x1_3fff_ffff, 0x1_4000_0000 + 0x0fff_ffff, u64::MAX] {
        if !groups.contains_key(&format!("ram:{at:x}")) {
            assert_eq!(p.xrefs_to(at).unwrap(), vec![], "ram:{at:x}");
        }
    }
    eprintln!("compared {checked} reference lists, {declined} declined, {empty} empty");
}

#[test]
fn xrefs_from_equal_the_oracle() {
    let p = analysed();
    let lines = oracle();
    let groups = oracle_refs(&lines, "ref");
    let mut checked = 0;
    for (key, expected) in &groups {
        let Some(from) = ram(key) else { continue };
        let plain = expected.iter().all(|l| l.ends_with("kind=MemReferenceDB") && ram(field(l, "to")).is_some());
        match p.xrefs_from(from) {
            Ok(got) => {
                assert!(plain, "{key}: answered a list holding another kind or space");
                let got: Vec<String> = got.iter().map(|x| oracle_ref_line(x, true)).collect();
                assert_eq!(&got, expected, "xrefs from {key}");
                checked += 1;
            }
            Err(Error::Unsupported(_)) => assert!(!plain, "{key}: declined a plain list"),
            Err(other) => panic!("{key}: {other}"),
        }
    }
    assert!(checked > 1000, "only {checked} lists compared");
}

#[test]
fn functions_equal_the_oracle() {
    let p = analysed();
    let lines = oracle();
    let mut expected: BTreeMap<u64, &String> = BTreeMap::new();
    let mut entry_of_id: BTreeMap<i64, u64> = BTreeMap::new();
    for l in lines.iter().filter(|l| l.starts_with("func id=")) {
        let id: i64 = field(l, "id").parse().unwrap();
        if let Some(e) = ram(field(l, "entry")) {
            expected.insert(e, l);
            entry_of_id.insert(id, e);
        }
    }
    let got = p.functions().unwrap();
    assert_eq!(got.len(), expected.len());
    assert!(got.len() > 400);
    for f in got {
        let l = expected.get(&f.entry).unwrap_or_else(|| panic!("extra function {:x}", f.entry));
        assert_eq!(f.id.to_string(), field(l, "id"));
        let thunk: i64 = field(l, "thunk").parse().unwrap();
        assert_eq!(f.thunk_of.unwrap_or(-1), thunk, "thunk link of {:x}", f.entry);
        if thunk < 0 {
            assert_eq!(f.var_args.to_string(), field(l, "vararg"));
            assert_eq!(f.inline.to_string(), field(l, "inline"));
            assert_eq!(f.no_return.to_string(), field(l, "noreturn"));
            assert_eq!(f.calling_convention, field(l, "cc"));
        }
    }
    // A function is found by its entry, and an address inside a body is not claimed to be anything.
    let first = &got[0];
    assert_eq!(p.function_at_entry(first.entry).unwrap().as_ref(), Some(first));
    assert_eq!(p.function_at_entry(first.entry + 1).unwrap(), None);
}

#[test]
fn symbols_equal_the_oracle_and_names_are_found_by_name() {
    let p = analysed();
    let lines = oracle();
    let rows = p.symbols().unwrap();
    let expected: Vec<&String> = lines.iter().filter(|l| l.starts_with("sym id=")).collect();
    assert_eq!(rows.len(), expected.len());
    let mut by_name: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for (row, l) in rows.iter().zip(&expected) {
        assert_eq!(row.id.to_string(), field(l, "id"));
        assert_eq!(row.name, field(l, "name"));
        assert_eq!(row.parent_id.to_string(), field(l, "parent"));
        assert_eq!(row.symbol_type.to_string(), field(l, "type"));
        assert_eq!(row.source, field(l, "source"));
        let at = field(l, "addr");
        match ram(at) {
            Some(a) => assert_eq!(row.address, Some(a)),
            None => assert_eq!(row.address, None, "{at}"),
        }
        if !row.name.is_empty() {
            by_name.entry(row.name.clone()).or_default().push(row.id);
        }
    }
    assert!(by_name.len() > 100);
    for (name, ids) in &by_name {
        let got: Vec<i64> = p.symbols_named(name).unwrap().iter().map(|s| s.id).collect();
        assert_eq!(&got, ids, "symbols named {name}");
    }
    assert!(p.symbols_named("no_such_symbol_anywhere").unwrap().is_empty());
    // A default name is computed by Ghidra, not stored: declined.
    assert!(matches!(p.symbols_named("FUN_140001030"), Err(Error::Unsupported(_))));
    // A default-named function gets its computed name.
    let named: Vec<_> = p.functions().unwrap().iter().filter(|f| f.default_named).collect();
    assert!(!named.is_empty());
    assert!(named.iter().all(|f| f.name == format!("FUN_{}", address_text(f.entry))));
}

/// A PE section table entry.
struct Section {
    rva: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

fn pe_sections(pe: &[u8]) -> (Vec<Section>, u32) {
    let u32_at = |o: usize| u32::from_le_bytes(pe[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u16::from_le_bytes(pe[o..o + 2].try_into().unwrap());
    let nt = u32_at(0x3c) as usize;
    let count = u16_at(nt + 6) as usize;
    let optional = u16_at(nt + 20) as usize;
    let headers = u32_at(nt + 24 + 60);
    let table = nt + 24 + optional;
    let sections = (0..count)
        .map(|i| {
            let o = table + i * 40;
            Section { virtual_size: u32_at(o + 8), rva: u32_at(o + 12), raw_size: u32_at(o + 16), raw_ptr: u32_at(o + 20) }
        })
        .collect();
    (sections, headers)
}

#[test]
fn bytes_equal_the_pe_image_the_project_was_analysed_from() {
    let p = analysed();
    let pe = std::fs::read(fixtures().join("flow_fixture.exe")).unwrap();
    let (sections, headers) = pe_sections(&pe);
    let base = p.info().image_base;
    let mut compared = 0usize;
    let mut differing = Vec::new();
    for block in p.blocks() {
        let ghidra_progdb::Address::Space { offset: start, .. } = &block.start else { panic!() };
        let got = p.read_bytes(*start, block.length as usize).unwrap();
        if block.is_artificial() {
            continue; // Ghidra's own block (the thread data block), nothing in the PE to compare with
        }
        let rva = (start - base) as u32;
        let mut expected = vec![0u8; block.length as usize];
        if rva == 0 {
            expected.copy_from_slice(&pe[..block.length as usize]);
            assert!(block.length as u32 <= headers.max(block.length as u32));
        } else {
            let s = sections.iter().find(|s| s.rva == rva).expect("section for block");
            let n = s.raw_size.min(s.virtual_size).min(block.length as u32) as usize;
            expected[..n].copy_from_slice(&pe[s.raw_ptr as usize..s.raw_ptr as usize + n]);
        }
        for (i, (a, b)) in got.iter().zip(&expected).enumerate() {
            if a != b {
                differing.push((block.name.clone(), i));
            }
        }
        compared += got.len();
    }
    eprintln!("compared {compared} bytes; {} differ", differing.len());
    assert!(compared > 100_000);
    // Anything Ghidra changed after loading (pointer fix-ups of the loader) would show here; none is expected in
    // this fixture, so a difference is a reader error.
    assert!(differing.is_empty(), "differences: {:?}", &differing[..differing.len().min(20)]);
}

#[test]
fn partial_reads_cross_parts_and_blocks_and_refuse_what_is_not_initialised() {
    let p = analysed();
    let base = p.info().image_base;
    let whole = p.read_bytes(base, 0x400).unwrap();
    for (offset, len) in [(1usize, 15usize), (0x3e0, 32), (0x3fe, 2), (0, 0x400)] {
        assert_eq!(p.read_bytes(base + offset as u64, len).unwrap(), whole[offset..offset + len], "read at +{offset:#x} len {len}");
    }
    assert_eq!(p.read_bytes(base, 0).unwrap(), Vec::<u8>::new());
    // Across the end of the headers block into the gap before .text.
    assert!(matches!(p.read_bytes(base + 0x3f0, 0x20), Err(Error::Unsupported(_))));
    // Across the file-backed and buffer-backed parts of .data (3072 + 2504 bytes).
    let data = base + 0x1a000;
    let seam = p.read_bytes(data + 3072 - 8, 16).unwrap();
    assert_eq!(seam[..8], p.read_bytes(data + 3072 - 8, 8).unwrap()[..]);
    assert_eq!(seam[8..], p.read_bytes(data + 3072, 8).unwrap()[..]);
    // The artificial thread block lives at a high offset of the same space.
    assert_eq!(p.read_bytes(0xff_0000_0000, 6224).unwrap().len(), 6224);
    assert!(matches!(p.read_bytes(0x10, 4), Err(Error::Unsupported(_))));
    assert!(matches!(p.read_bytes(u64::MAX, 2), Err(Error::Unsupported(_))));
}

fn request(address: &str, limit: u64, cursor: &str) -> serde_json::Value {
    json!({"id": "t", "action": "xrefs", "address": address, "limit": limit, "cursor": cursor,
           "contains": "", "timeout_s": 30, "options": {}, "expected_sha256": ""})
}

#[test]
fn the_xrefs_answer_has_the_engine_shape_and_pages_like_it() {
    let p = analysed();
    let lines = oracle();
    let groups = oracle_refs(&lines, "toref");
    let (key, list) = groups.iter().filter(|(k, _)| ram(k).is_some()).max_by_key(|(_, v)| v.len()).unwrap();
    assert!(list.len() >= 3, "the busiest address has {} refs", list.len());
    let at = ram(key).unwrap();
    let all = p.xrefs_to(at).unwrap();

    let first = answer(&p, &request(&format!("va:0x{at:x}"), 2, "")).unwrap();
    assert_eq!(first["ok"], json!(true));
    assert_eq!(first["id"], json!("t"));
    assert_eq!(first["program"], json!("flow_fixture.exe"));
    assert_eq!(first["image_base"], json!("0x140000000"));
    assert_eq!(first["address_kind"], json!("VA"));
    assert_eq!(first["sha256"], json!(p.info().sha256));
    assert_eq!(first["truncated"], json!(true));
    assert_eq!(first["next_cursor"], json!("0x2"));
    let rows = first["references"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        json!({"from": format!("0x{}", all[0].from_text()), "to": format!("0x{}", address_text(at)), "type": all[0].ref_type})
    );

    // Following the cursor to the end returns every row once, and the last page is not truncated.
    let mut seen = Vec::new();
    let mut cursor = String::new();
    loop {
        let page = answer(&p, &request(&format!("0x{at:x}"), 2, &cursor)).unwrap();
        seen.extend(page["references"].as_array().unwrap().iter().cloned());
        if page["truncated"] == json!(true) {
            cursor = page["next_cursor"].as_str().unwrap().to_owned();
        } else {
            assert!(page.get("next_cursor").is_none());
            break;
        }
    }
    assert_eq!(seen.len(), all.len());

    // rva: adds the image base; a cursor past the end is an empty, untruncated page.
    let by_rva = answer(&p, &request(&format!("rva:0x{:x}", at - p.info().image_base), 200, "")).unwrap();
    assert_eq!(by_rva["references"].as_array().unwrap().len(), all.len());
    let past = answer(&p, &request(&format!("0x{at:x}"), 5, "0xffff")).unwrap();
    assert_eq!(past["references"], json!([]));
    assert_eq!(past["truncated"], json!(false));
}

#[test]
fn entry_point_references_print_like_the_engine() {
    // tests/data/tool_golden records the engine printing the entry-point source as "0xEntry Point".
    let p = analysed();
    let entry = p
        .xrefs_to(0x1_4000_14f0)
        .unwrap()
        .into_iter()
        .find(|x| x.from.is_none())
        .expect("the oracle lists an entry point reference to ram:1400014f0");
    assert_eq!(entry.from_text(), "Entry Point");
    let page = answer(&p, &request("0x1400014f0", 50, "")).unwrap();
    assert!(page["references"].as_array().unwrap().iter().any(|r| r["from"] == json!("0xEntry Point")));
}

#[test]
fn what_the_plane_does_not_know_is_declined_not_guessed() {
    let p = analysed();
    for action in ["function", "functions", "decompile", "blocks", "status", "stop", "type_edit", "data", "scan"] {
        let mut r = request("0x140001030", 5, "");
        r["action"] = json!(action);
        assert!(matches!(answer(&p, &r), Err(Error::Unsupported(_))), "{action}");
    }
    for bad in ["", "main", "0x", "rva:", "ram:140001000", "0xzz", "va:0x1ffffffffffffffff"] {
        assert!(matches!(answer(&p, &request(bad, 5, "")), Err(Error::Unsupported(_))), "{bad:?}");
    }
    assert!(matches!(answer(&p, &request("0x140001030", 0, "")), Err(Error::Unsupported(_))));
    assert!(matches!(answer(&p, &request("0x140001030", 201, "")), Err(Error::Unsupported(_))));
    assert!(matches!(answer(&p, &request("0x140001030", 5, "xyz")), Err(Error::Unsupported(_))));
    assert!(matches!(answer(&p, &request("0x140001030", 5, "0xffffffffffffffff")), Err(Error::Unsupported(_))));
    let mut wrong = request("0x140001030", 5, "");
    wrong["expected_sha256"] = json!("00".repeat(32));
    assert!(matches!(answer(&p, &wrong), Err(Error::Unsupported(_))));
    let mut right = request("0x140001030", 5, "");
    right["expected_sha256"] = json!(p.info().sha256.to_uppercase());
    assert!(answer(&p, &right).is_ok());
}

#[test]
fn an_unanalysed_project_and_foreign_layouts_are_declined() {
    let unanalysed = StaticProgram::open(&fixtures().join("legacy-12.1.4"), "/flow_fixture.exe");
    assert!(matches!(unanalysed, Err(Error::Unsupported(_))), "{:?}", unanalysed.err());
    let missing = StaticProgram::open(&fixtures().join("legacy-12.1.4-analysed"), "/nope.exe");
    assert!(matches!(missing, Err(Error::Unsupported(_))));
    let none = StaticProgram::open(&fixtures().join("does-not-exist"), "/flow_fixture.exe");
    assert!(matches!(none, Err(Error::Unsupported(_))));
    // The project can be named by its .gpr, its folder, its .rep folder, and the program with or without the slash.
    let dir = fixtures().join("legacy-12.1.4-analysed");
    for project in [dir.join("legacy.gpr"), dir.clone(), dir.join("legacy.rep")] {
        for name in ["/flow_fixture.exe", "flow_fixture.exe"] {
            assert!(StaticProgram::open(&project, name).is_ok(), "{project:?} {name}");
        }
    }
}
