//! A Python (msvcrt/fcntl) holder and the Rust lock exclude each other (same byte-0 range).
//! Skipped when no Python is found (set `HYDRALYSIS_PYTHON` or install C:\Python315).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn python() -> Option<String> {
    let candidates = [
        std::env::var("HYDRALYSIS_PYTHON").unwrap_or_default(),
        r"C:\Python315\python.exe".into(),
    ];
    candidates
        .into_iter()
        .find(|p| !p.is_empty() && std::path::Path::new(p).is_file())
}

#[test]
fn python_holder_blocks_rust_and_rust_holder_blocks_python() {
    let Some(py) = python() else { return };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("i.lock");
    let code = "import sys,os;sys.path.insert(0,sys.argv[2]);from hydralysis import locks;l=locks.LaneLock(sys.argv[1]);\
        print(l.acquire(),flush=True);sys.stdin.readline();l.release()";
    let mut child = Command::new(py.clone())
        .args([
            "-c",
            code,
            lock.to_str().unwrap(),
            root.join("src").to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "True");
    assert!(hy_views::locks::held(&lock));
    assert!(hy_views::locks::locked(&lock, 0.2, "x").is_err());
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    child.wait().unwrap();
    let _g = hy_views::locks::locked(&lock, 2.0, "x").unwrap();
    let out = Command::new(py)
        .args(["-c", "import sys;sys.path.insert(0,sys.argv[2]);from hydralysis import locks;print(locks.held(sys.argv[1]))", lock.to_str().unwrap(), root.join("src").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "True");
}
