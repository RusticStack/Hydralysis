//! The session core of the Hydra Engine's Rust client, vendored for `hydralysis-native`.
//!
//! Original: `Ghidra/Features/HeadlessSession/rust/crates/hydra-client` of the Hydra Engine (Apache-2.0), engine
//! commit 674636bd9d5b. Kept: `session.rs`, `error.rs`, `version.rs`. Dropped: the typed command wrappers (`client.rs`),
//! the trace helpers and the JSON digest helpers, which Hydralysis does not use.
//!
//! Changes against the original, each small and additive unless noted:
//! - progress events now reach the installed handler (the original stored them and never called it), as raw lines too
//!   (`set_raw_event_handler`, `event_lines`), so the Python side builds the dict from the engine's own bytes;
//! - `Session::connect` keeps the raw `hello` answer (`hello_raw`);
//! - `send_with` writes a request line the caller built (it gets the id), so Python values are serialised under the GIL
//!   in the order Python's `json.dumps` would use; `abandon` marks the answer as dropped (`_send_request(abandon=True)`);
//! - `close_ref` shuts the connection down through a shared reference.

#![deny(unsafe_code)]

pub mod error;
pub mod session;
pub mod version;

pub use error::{Error, Result, SessionError};
pub use session::{ConnectOptions, Endpoint, Reply, Session};
pub use version::{CLIENT_VERSION, PROTOCOL, PROTOCOL_MIN};
