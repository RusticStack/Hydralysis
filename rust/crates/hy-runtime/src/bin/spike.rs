//! Stage-1 feasibility spike: spike <agent.dll> <exe> <rva-hex|-> <expect-hex,bytes> [target args]
use hy_runtime::session::{Session, Site};
use std::path::PathBuf;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dll = PathBuf::from(&a[1]);
    let exe = PathBuf::from(&a[2]);
    let sites = if a[3] == "-" {
        vec![]
    } else {
        let rva = u64::from_str_radix(a[3].trim_start_matches("0x"), 16).unwrap();
        let expect: Vec<u8> = a[4]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
        vec![Site { rva, expect }]
    };
    let rest: Vec<String> = a[5..].to_vec();
    let mut s = Session::spawn(&exe, &rest, &sites).expect("spawn");
    if !sites.is_empty() {
        s.inject(&dll).expect("inject");
    }
    s.resume();
    let mut total = 0u64;
    let mut first = None;
    while s.running() {
        total += s.drain(|r| {
            first.get_or_insert(*r);
        });
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    total += s.drain(|r| {
        first.get_or_insert(*r);
    });
    println!("records={total} dropped={} first={first:?}", s.dropped());
}
