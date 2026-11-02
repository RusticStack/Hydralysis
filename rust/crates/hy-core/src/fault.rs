//! Crash-injection hook: inert unless `HYDRALYSIS_TEST_MODE=1` and `HYDRALYSIS_TEST_FAULT=<name>:<action>` are set.
//!
//! Actions: `exit` (end the process at once, as kill -9 would), `raise` (an error), `torn:<n>` (returns n; the call
//! site writes n bytes and then ends the process).

use crate::error::{Error, Result};

pub fn fault(name: &str) -> Result<Option<usize>> {
    let Ok(spec) = std::env::var("HYDRALYSIS_TEST_FAULT") else { return Ok(None) };
    if spec.is_empty() || std::env::var("HYDRALYSIS_TEST_MODE").as_deref() != Ok("1") {
        return Ok(None);
    }
    let (target, action) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
    if target != name {
        return Ok(None);
    }
    if action == "exit" {
        die();
    }
    if action == "raise" {
        return Err(Error::FaultInjected(name.to_string()));
    }
    if let Some(rest) = action.strip_prefix("torn:")
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(rest.parse().ok());
    }
    Err(Error::value(format!("HYDRALYSIS_TEST_FAULT action must be exit, raise or torn:<n>, got '{action}'")))
}

/// End the process at once (`os._exit(137)`).
pub fn die() -> ! {
    std::process::exit(137)
}
