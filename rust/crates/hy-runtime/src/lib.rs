//! Host side of the Frida-free runtime. See DESIGN.md.
pub mod authorize;
pub mod clock;
#[cfg(windows)]
pub mod identity;
#[cfg(windows)]
pub mod inject;
#[cfg(windows)]
pub mod memory;
pub mod pe_exports;
pub mod sampling;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod threadinfo;
#[cfg(windows)]
pub mod watch;

pub use hy_agent_proto as proto;
