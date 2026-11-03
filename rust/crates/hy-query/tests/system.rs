use hy_query::system::*;
use serde_json::json;
use std::fs;

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hyq-system-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn properties_skip_comments_and_strip_quotes() {
    let dir = tmp("props");
    let path = dir.join("release");
    fs::write(&path, "A=1\n# c=2\n  #d=3\nB = \"x y\" \nnoeq\nC=a=b\r\nD=\"q\"\r").unwrap();
    let got = properties(&path);
    let pairs: Vec<_> = got.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(pairs, [("A", "1"), ("B", "x y"), ("C", "a=b"), ("D", "q")]);
    assert!(properties(&dir.join("none")).is_empty());
}

#[test]
fn children_sorted_descending_and_pattern_limited() {
    let dir = tmp("children");
    for n in ["jdk-21", "jdk-25", "hydra-12", "hydra-x", "other"] {
        fs::create_dir(dir.join(n)).unwrap();
    }
    let names =
        |p: &str| -> Vec<String> { children(&dir, p).iter().map(|x| x.file_name().unwrap().to_string_lossy().into_owned()).collect() };
    assert_eq!(names("jdk*"), ["jdk-25", "jdk-21"]);
    assert_eq!(names("hydra-[0-9]*"), ["hydra-12"]);
}

#[test]
fn native_compatible_reads_headers() {
    let dir = tmp("native");
    let mut pe = vec![0u8; 128];
    pe[..2].copy_from_slice(b"MZ");
    pe[60] = 64;
    pe[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    let good = dir.join("good");
    fs::write(&good, &pe).unwrap();
    pe[68] = 0xaa;
    let arm = dir.join("arm");
    fs::write(&arm, &pe).unwrap();
    assert_eq!(native_compatible(&good), cfg!(windows));
    assert!(!native_compatible(&arm));
    assert!(!native_compatible(&dir));
}

#[test]
fn doctor_leaves() {
    let dir = tmp("doctor");
    fs::write(dir.join("a.json"), "{}").unwrap();
    fs::write(dir.join("a.lock"), "").unwrap();
    fs::write(dir.join("b.json"), "{}").unwrap();
    fs::write(dir.join("c.launch.json"), "{}").unwrap();
    fs::write(dir.join("c.launch.lock"), "").unwrap();
    assert_eq!(instances(&dir), ["a"]);
    fs::write(dir.join("l.json"), "[1]").unwrap();
    assert_eq!(read_json_object(&dir.join("l.json")), json!({}));
    assert_eq!(read_json_object(&dir.join("a.json")), json!({}));
    assert_eq!(dir_size(&dir), 9);
    let value = json!({"k": 1, "a": [{"k": 0}, {"k": "x", "n": {"k": [1]}}, {"k": []}, {"k": null}], "b": {"k": true}});
    assert_eq!(count_key(&value, "k"), 4);
}
