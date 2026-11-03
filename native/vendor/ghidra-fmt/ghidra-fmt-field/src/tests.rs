//! Field, schema and record tests.
//!
//! `Framework/DB/src/test` has no unit test for the Field classes; they are only exercised
//! through the table tests (`DBTestUtils`, `DB*TableTest`), which need the table layer. These
//! tests therefore state the Java semantics directly; the table-level ports live in
//! `ghidra-fmt-db`.

use super::*;
use std::cmp::Ordering::{Equal, Greater, Less};

fn rt(ty: &FieldType, f: &Field) {
    let bytes = f.to_bytes();
    assert_eq!(bytes.len(), f.length());
    let (back, next) = Field::read(ty, &bytes, 0).unwrap();
    assert_eq!(&back, f);
    assert_eq!(next, bytes.len());
    assert_eq!(Field::read_length(ty, &bytes, 0).unwrap(), bytes.len());
    assert_eq!(f.field_type(), *ty);
}

#[test]
fn type_codes() {
    for (code, ty) in [
        (0, FieldType::Byte),
        (1, FieldType::Short),
        (2, FieldType::Int),
        (3, FieldType::Long),
        (4, FieldType::String),
        (5, FieldType::Binary),
        (6, FieldType::Boolean),
        (7, FieldType::Fixed10),
    ] {
        assert_eq!(FieldType::from_code(code).unwrap(), ty);
        assert_eq!(ty.code(), code);
    }
    // index: primary nibble << 4 | indexed nibble
    let t = FieldType::from_code(0x34).unwrap(); // string indexed, long primary
    assert_eq!(
        t,
        FieldType::Index {
            indexed: Box::new(FieldType::String),
            primary: Box::new(FieldType::Long)
        }
    );
    assert_eq!(t.code(), 0x34);
    assert!(t.is_variable_length());
    assert_eq!(FieldType::from_code(0x32).unwrap().fixed_length(), Some(12));
    // legacy: nibble 8 reads as legacy, but writes back with a long primary nibble
    let legacy = FieldType::from_code(0x82).unwrap();
    assert!(matches!(legacy, FieldType::LegacyIndex { .. }));
    assert!(legacy.is_variable_length());
    assert_eq!(legacy.code(), 0x32);
    // unsupported
    for bad in [0x88u8, 0x08, 0x0f, 0xf3, 0x39, 0x3c] {
        assert!(FieldType::from_code(bad).is_err(), "{bad:#x}");
    }
    // variable-length primary key is an illegal argument
    assert!(matches!(
        FieldType::from_code(0x42),
        Err(FieldError::IllegalArgument(_))
    ));
    assert!(FieldType::Long.can_index());
    assert!(!FieldType::Byte.can_index());
    assert!(!FieldType::Boolean.can_index());
    assert!(!FieldType::from_code(0x32).unwrap().can_index());
}

#[test]
fn encodings_round_trip_and_are_big_endian() {
    rt(&FieldType::Byte, &Field::Byte(-5));
    rt(&FieldType::Short, &Field::Short(-2));
    rt(&FieldType::Int, &Field::Int(0x0102_0304));
    rt(&FieldType::Long, &Field::Long(i64::MIN));
    rt(&FieldType::Boolean, &Field::Boolean(1));
    rt(&FieldType::Boolean, &Field::Boolean(7)); // raw byte kept
    rt(
        &FieldType::Fixed10,
        &Field::Fixed10([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    );
    rt(&FieldType::String, &Field::string("héllo"));
    rt(&FieldType::String, &Field::string(""));
    rt(&FieldType::String, &Field::String(None));
    rt(&FieldType::Binary, &Field::Binary(Some(vec![0, 255, 7])));
    rt(&FieldType::Binary, &Field::Binary(None));
    assert_eq!(Field::Int(0x0102_0304).to_bytes(), [1, 2, 3, 4]);
    assert_eq!(Field::string("ab").to_bytes(), [0, 0, 0, 2, b'a', b'b']);
    assert_eq!(Field::String(None).to_bytes(), [0xff; 4]);
    assert_eq!(Field::Binary(Some(vec![])).to_bytes(), [0, 0, 0, 0]);
    assert_eq!(Field::String(None).length(), 4);
    assert!(Field::String(None).is_null());
    assert!(!Field::string("").is_null());
    assert_eq!(Field::Boolean(7).long_value(), Some(7));
}

#[test]
fn raw_string_bytes_survive_a_read_write() {
    let stored = [0, 0, 0, 3, 0xff, b'a', 0xc3];
    let (f, _) = Field::read(&FieldType::String, &stored, 0).unwrap();
    assert_eq!(f.to_bytes(), stored);
}

#[test]
fn short_reads_error() {
    assert!(Field::read(&FieldType::Long, &[0; 7], 0).is_err());
    assert!(Field::read(&FieldType::String, &[0, 0, 0, 9, 1], 0).is_err());
    assert!(Field::read(&FieldType::Binary, &[0, 0], 0).is_err());
    assert!(Field::read(&FieldType::Fixed10, &[0; 9], 0).is_err());
}

#[test]
fn index_fields() {
    let ty = FieldType::from_code(0x34).unwrap();
    let f = Field::new_index(Field::string("k"), Field::Long(9), false).unwrap();
    rt(&ty, &f);
    assert_eq!(f.length(), 5 + 8);
    // read_length of the indexed part only (primary is fixed)
    assert_eq!(Field::read_length(&ty, &f.to_bytes(), 0).unwrap(), 13);

    assert!(Field::new_index(Field::Int(1), Field::string("x"), false).is_err());

    let legacy = Field::new_index(Field::Int(1), Field::Long(2), true).unwrap();
    assert!(legacy.is_variable_length());
    let lt = FieldType::from_code(0x82).unwrap();
    let (back, next) = Field::read(&lt, &legacy.to_bytes(), 0).unwrap();
    assert_eq!(back, legacy);
    assert_eq!(next, 12);

    // compare: indexed value first, then primary key
    let a = Field::new_index(Field::Int(1), Field::Long(5), false).unwrap();
    let b = Field::new_index(Field::Int(1), Field::Long(6), false).unwrap();
    let c = Field::new_index(Field::Int(2), Field::Long(0), false).unwrap();
    assert_eq!(a.compare(&b), Ok(Less));
    assert_eq!(b.compare(&c), Ok(Less));
    assert_eq!(c.compare(&a), Ok(Greater));
    assert_eq!(a.compare_to_stored(&b.to_bytes(), 0), Ok(Less));
}

#[test]
fn index_values_are_truncated_to_64_stored_bytes() {
    let long = "x".repeat(100);
    let f = Field::new_index(Field::string(&long), Field::Long(1), false).unwrap();
    let Field::Index(i) = &f else { panic!() };
    assert_eq!(i.indexed.length(), 4 + 60);
    // shorter than the limit: untouched
    let f = Field::new_index(Field::string(&"y".repeat(59)), Field::Long(1), false).unwrap();
    let Field::Index(i) = &f else { panic!() };
    assert_eq!(i.indexed.length(), 4 + 59);
    // binary
    let f = Field::new_index(Field::Binary(Some(vec![1; 70])), Field::Long(1), false).unwrap();
    let Field::Index(i) = &f else { panic!() };
    assert_eq!(i.indexed, Field::Binary(Some(vec![1; 60])));
    // truncation counts UTF-16 units; a cut surrogate pair becomes '?'
    let s = format!("{}{}", "a".repeat(59), "\u{10000}");
    let f = Field::new_index(Field::string(&s), Field::Long(1), false).unwrap();
    let Field::Index(i) = &f else { panic!() };
    let Field::String(Some(js)) = &i.indexed else {
        panic!()
    };
    assert_eq!(js.as_str(), format!("{}?", "a".repeat(59)));
}

#[test]
fn ordering() {
    assert_eq!(Field::Long(-1).compare(&Field::Long(0)), Ok(Less));
    assert_eq!(Field::Byte(-1).compare(&Field::Byte(1)), Ok(Less));
    assert_eq!(Field::Short(5).compare(&Field::Short(5)), Ok(Equal));
    assert_eq!(Field::Boolean(2).compare(&Field::Boolean(1)), Ok(Greater));
    // Fixed10 is unsigned
    let lo = Field::Fixed10([0; 10]);
    let hi = Field::Fixed10([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let hi2 = Field::Fixed10([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(lo.compare(&hi), Ok(Less));
    assert_eq!(hi.compare(&hi2), Ok(Less));
    // Binary: unsigned lexicographic, shorter first on a common prefix, null first
    let b = |v: &[u8]| Field::Binary(Some(v.to_vec()));
    assert_eq!(b(&[0x80]).compare(&b(&[0x7f])), Ok(Greater));
    assert_eq!(b(&[1]).compare(&b(&[1, 0])), Ok(Less));
    assert_eq!(Field::Binary(None).compare(&b(&[])), Ok(Less));
    assert_eq!(Field::Binary(None).compare(&Field::Binary(None)), Ok(Equal));
    // String: UTF-16 code unit order (differs from code point order)
    let s = |v: &str| Field::string(v);
    assert_eq!(s("\u{10000}").compare(&s("\u{ffff}")), Ok(Less));
    assert_eq!(s("a").compare(&s("ab")), Ok(Less));
    assert_eq!(Field::String(None).compare(&s("")), Ok(Less));
    assert_eq!(s("").compare(&Field::String(None)), Ok(Greater));
    // different types never compare
    assert_eq!(
        Field::Int(1).compare(&Field::Long(1)),
        Err(FieldError::TypeMismatch)
    );
    // against a stored value
    assert_eq!(Field::Int(3).compare_to_stored(&[0, 0, 0, 9], 0), Ok(Less));
    assert_eq!(s("b").compare_to_stored(&s("a").to_bytes(), 0), Ok(Greater));
    assert_eq!(
        b(&[2]).compare_to_stored(&[0xff, 0xff, 0xff, 0xff], 0),
        Ok(Greater)
    );
}

fn master_like() -> Schema {
    // TableRecord.schema
    Schema::new(
        0,
        FieldType::Long,
        "TableNum",
        vec![
            FieldType::String,
            FieldType::Int,
            FieldType::Int,
            FieldType::Byte,
            FieldType::Binary,
            FieldType::String,
            FieldType::Int,
            FieldType::Long,
            FieldType::Int,
        ],
        [
            "TableName",
            "SchemaVersion",
            "RootBufferId",
            "KeyType",
            "FieldTypes",
            "FieldNames",
            "IndexColumn",
            "MaxKey",
            "RecordCount",
        ]
        .map(String::from)
        .to_vec(),
        &[],
    )
    .unwrap()
}

#[test]
fn schema_encoding_round_trips() {
    let s = master_like();
    assert_eq!(s.encoded_key_field_type(), 3);
    assert_eq!(s.encoded_field_types(), [4, 2, 2, 0, 5, 4, 2, 3, 2]);
    assert!(s.packed_field_names().starts_with("TableNum;TableName;"));
    assert!(s.packed_field_names().ends_with("RecordCount;"));
    assert!(s.is_variable_length());
    assert_eq!(s.fixed_length(), 0);
    let back = Schema::from_encoded(
        0,
        s.encoded_key_field_type(),
        &s.encoded_field_types(),
        &s.packed_field_names(),
    )
    .unwrap();
    assert!(s.same_as(&back));
    assert_eq!(back.field_names(), s.field_names());
    assert_eq!(back.key_name(), "TableNum");
    assert!(back.use_long_key_nodes());
    assert!(!back.use_variable_key_nodes());
    assert!(!back.use_fixed_key_nodes());
}

#[test]
fn fixed_length_schema_and_key_node_selection() {
    let s = Schema::new(
        1,
        FieldType::Fixed10,
        "k",
        vec![FieldType::Int, FieldType::Long, FieldType::Byte],
        ["a", "b", "c"].map(String::from).to_vec(),
        &[],
    )
    .unwrap();
    assert!(!s.is_variable_length());
    assert_eq!(s.fixed_length(), 13);
    assert!(s.use_fixed_key_nodes());
    let mut v = Schema::new(1, FieldType::String, "k", vec![], vec![], &[]).unwrap();
    assert!(v.use_variable_key_nodes());
    assert!(!v.use_fixed_key_nodes());
    let mut byte_key = Schema::new(1, FieldType::Byte, "k", vec![], vec![], &[]).unwrap();
    assert!(byte_key.use_fixed_key_nodes());
    byte_key.force_use_of_variable_length_key_nodes();
    assert!(byte_key.use_variable_key_nodes());
    assert!(!byte_key.use_fixed_key_nodes());
    v.force_use_of_variable_length_key_nodes();
    assert!(!v.use_long_key_nodes());
    // a forced long key also leaves the long family
    let mut l = master_like();
    l.force_use_of_variable_length_key_nodes();
    assert!(!l.use_long_key_nodes());
}

#[test]
fn schema_rejects_bad_input() {
    let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // length mismatch, ';' in a name
    assert!(Schema::new(0, FieldType::Long, "k", vec![FieldType::Int], vec![], &[]).is_err());
    assert!(
        Schema::new(
            0,
            FieldType::Long,
            "k",
            vec![FieldType::Int],
            n(&["a;b"]),
            &[]
        )
        .is_err()
    );
    // sparse out of range / duplicate
    assert!(
        Schema::new(
            0,
            FieldType::Long,
            "k",
            vec![FieldType::Int],
            n(&["a"]),
            &[1]
        )
        .is_err()
    );
    assert!(
        Schema::new(
            0,
            FieldType::Long,
            "k",
            vec![FieldType::Int, FieldType::Int],
            n(&["a", "b"]),
            &[1, 1]
        )
        .is_err()
    );
    // encoded: unsupported extension, names/types mismatch, bad type, no names
    assert!(Schema::from_encoded(0, 3, &[2, 0xff, 2], "k;a;").is_err());
    assert!(Schema::from_encoded(0, 3, &[2, 2], "k;a;").is_err());
    assert!(Schema::from_encoded(0, 3, &[0x0f], "k;a;").is_err());
    assert!(Schema::from_encoded(0, 3, &[2], "").is_err());
    // a second extension block is read as extension type -1 and refused (Java quirk)
    assert!(Schema::from_encoded(0, 3, &[2, 0xff, 1, 0, 0xff, 1, 0], "k;a;").is_err());
}

#[test]
fn schema_names_use_stringtokenizer_semantics() {
    // empty tokens are skipped, so an empty column name vanishes
    let s = Schema::from_encoded(0, 3, &[2, 2], "k;;a;b;").unwrap();
    assert_eq!(s.field_names(), ["a", "b"]);
}

fn sparse_schema() -> Schema {
    Schema::new(
        2,
        FieldType::Long,
        "k",
        vec![
            FieldType::Int,
            FieldType::String,
            FieldType::Long,
            FieldType::Binary,
        ],
        ["a", "b", "c", "d"].map(String::from).to_vec(),
        &[1, 3],
    )
    .unwrap()
}

#[test]
fn sparse_schema_encoding() {
    let s = sparse_schema();
    assert!(s.has_sparse_columns());
    assert!(s.is_sparse_column(1) && s.is_sparse_column(3) && !s.is_sparse_column(0));
    assert_eq!(s.encoded_field_types(), [2, 4, 3, 5, 0xff, 1, 1, 3]);
    let back =
        Schema::from_encoded(2, 3, &s.encoded_field_types(), &s.packed_field_names()).unwrap();
    assert!(s.same_as(&back));
    assert!(back.is_variable_length());
    // out-of-range sparse index in an encoded schema
    assert!(Schema::from_encoded(2, 3, &[2, 0xff, 1, 5], "k;a;").is_err());
    assert!(Schema::from_encoded(2, 3, &[2, 0xff, 1, 0xfe], "k;a;").is_err());
}

#[test]
fn plain_record_round_trip() {
    let s = master_like();
    let rec = Record {
        key: Field::Long(7),
        values: vec![
            Some(Field::string("Program")),
            Some(Field::Int(3)),
            Some(Field::Int(-1)),
            Some(Field::Byte(3)),
            Some(Field::Binary(Some(vec![2, 2, 0]))),
            Some(Field::string("k;a;b;")),
            Some(Field::Int(-1)),
            Some(Field::Long(i64::MIN)),
            Some(Field::Int(0)),
        ],
    };
    let mut out = Vec::new();
    s.write_record(&rec, &mut out).unwrap();
    assert_eq!(out.len(), s.record_length(&rec));
    let (back, next) = s.read_record(Field::Long(7), &out, 0).unwrap();
    assert_eq!(back, rec);
    assert_eq!(next, out.len());
    // wrong column type / count / missing value
    let mut bad = rec.clone();
    bad.values[1] = Some(Field::Long(3));
    assert!(s.write_record(&bad, &mut Vec::new()).is_err());
    bad = rec.clone();
    bad.values.pop();
    assert!(s.write_record(&bad, &mut Vec::new()).is_err());
    bad = rec.clone();
    bad.values[0] = None;
    assert!(s.write_record(&bad, &mut Vec::new()).is_err());
    // truncated data
    assert!(
        s.read_record(Field::Long(7), &out[..out.len() - 1], 0)
            .is_err()
    );
}

#[test]
fn sparse_record_round_trip() {
    let s = sparse_schema();
    let rec = Record {
        key: Field::Long(1),
        values: vec![
            Some(Field::Int(10)),
            None,
            Some(Field::Long(20)),
            Some(Field::Binary(Some(vec![9]))),
        ],
    };
    let mut out = Vec::new();
    s.write_record(&rec, &mut out).unwrap();
    // int, long, sparse count 1, then (index 3, binary)
    assert_eq!(
        out,
        [0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 20, 1, 3, 0, 0, 0, 1, 9]
    );
    assert_eq!(out.len(), s.record_length(&rec));
    let (back, next) = s.read_record(Field::Long(1), &out, 0).unwrap();
    assert_eq!(back, rec);
    assert_eq!(next, out.len());

    // no sparse values present: just the count byte
    let empty = Record {
        key: Field::Long(2),
        values: vec![Some(Field::Int(1)), None, Some(Field::Long(2)), None],
    };
    let mut out = Vec::new();
    s.write_record(&empty, &mut out).unwrap();
    assert_eq!(out.len(), 4 + 8 + 1);
    assert_eq!(out.len(), s.record_length(&empty));

    // a null string in a sparse column is treated as absent
    let null_str = Record {
        key: Field::Long(2),
        values: vec![
            Some(Field::Int(1)),
            Some(Field::String(None)),
            Some(Field::Long(2)),
            None,
        ],
    };
    let mut out2 = Vec::new();
    s.write_record(&null_str, &mut out2).unwrap();
    assert_eq!(out2, out);
    assert_eq!(s.record_length(&null_str), out.len());

    // corrupt sparse index
    let mut bad = out.clone();
    let n = bad.len();
    bad[n - 1] = 1;
    bad.extend_from_slice(&[9, 0, 0, 0, 0]);
    assert!(s.read_record(Field::Long(2), &bad, 0).is_err());
}
