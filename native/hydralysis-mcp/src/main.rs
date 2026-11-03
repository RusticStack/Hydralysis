//! hydralysis-mcp: the native MCP host for Hydralysis.
//!
//! Speaks the same stdio MCP as `hydralysis mcp` (hydralysis/mcp.py) with a resident footprint of a few megabytes: the
//! catalog, lanes, output cap and the offline PE tools are native; every other tool body is run by a short-lived
//! Python worker (`python -m hydralysis.worker`) that is started on demand and closed when idle.
//!
//! Environment: HYDRALYSIS_PYTHON (the interpreter of the worker, default `python`), HYDRALYSIS_WORKER_IDLE_S (default 30),
//! HYDRALYSIS_MCP_ENV_TTL_S (default 300, 0 = never cache the environment report).

mod catalog;
mod env;
mod pe;
mod pyjson;
mod server;
mod tools;
mod wire;
mod worker;

use std::io::BufReader;

fn main() {
    let first = std::env::args().nth(1);
    match first.as_deref() {
        Some("--version") | Some("-V") => {
            println!("hydralysis-mcp {}", catalog::Catalog::load().version);
            return;
        }
        Some("--help") | Some("-h") => {
            println!("hydralysis-mcp: stdio MCP server for Hydralysis (see hydralysis/mcp.py). No arguments.");
            return;
        }
        _ => {}
    }
    let worker = worker::Worker::new();
    let server = server::Server::new(Box::new(std::io::stdout()), worker);
    let stdin = std::io::stdin();
    let mut input = BufReader::with_capacity(64 * 1024, stdin.lock());
    server.serve(&mut input);
}
