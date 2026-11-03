//! Binding of `hy_trace::capture`: `capture_stacks` of `hydralysis.trace_watchdog` when `HYDRALYSIS_IMPL=rust`.
//!
//! The target is another process; the capture runs without the GIL (it suspends threads of the target, one at a time, for
//! the register read only). The answer is the same dict, in the same key order, as the Python function returns.

use super::port::fallback;
use hy_trace::capture::{self, Capture, ThreadCapture};
use hy_trace::unwind::Frame;
use pyo3::exceptions::PyIndexError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

const NOTE: &str = "no write into the target; threads were suspended only while registers were read; frames by the unwind tables";

fn frame_dict<'py>(py: Python<'py>, frame: &Frame) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("pc", frame.pc)?;
    dict.set_item("at", frame.at.as_deref())?;
    dict.set_item("how", frame.how)?;
    Ok(dict)
}

fn thread_dict<'py>(py: Python<'py>, thread: &ThreadCapture) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    match thread {
        ThreadCapture::Unreadable { tid, reason } => {
            dict.set_item("tid", tid)?;
            dict.set_item("state", "unreadable")?;
            dict.set_item("reason", reason)?;
        }
        ThreadCapture::Read {
            tid,
            captured,
            frames,
            suspended_before,
        } => {
            dict.set_item("tid", tid)?;
            dict.set_item("state", if *captured { "captured" } else { "unreadable" })?;
            let list = PyList::empty(py);
            for frame in frames {
                list.append(frame_dict(py, frame)?)?;
            }
            dict.set_item("frames", list)?;
            dict.set_item("suspended_before", suspended_before)?;
        }
    }
    Ok(dict)
}

/// `capture_stacks(pid, depth, scan_bytes)`: every thread stack of PID. A PID or limit outside the unsigned 32-bit and
/// native size ranges is a `TraceFallback`; truncated unwind data raises `IndexError`, as the Python walk does.
#[pyfunction]
fn watchdog_capture_stacks<'py>(
    py: Python<'py>,
    pid: i64,
    depth: i64,
    scan_bytes: i64,
) -> PyResult<Bound<'py, PyDict>> {
    let (Ok(pid), Ok(depth), Ok(scan_bytes)) = (
        u32::try_from(pid),
        usize::try_from(depth),
        usize::try_from(scan_bytes),
    ) else {
        return Err(fallback("pid or limits outside the range the port models"));
    };
    if depth > 4096 || scan_bytes > 1 << 24 {
        return Err(fallback("limits beyond what the port models"));
    }
    let captured = py.detach(|| capture::capture_stacks(pid, depth, scan_bytes));
    let captured =
        captured.map_err(|_| PyIndexError::new_err("unwind codes run past the unwind info"))?;
    let dict = PyDict::new(py);
    match captured {
        Capture::Refused { reason } => {
            dict.set_item("state", "refused")?;
            dict.set_item("reason", reason)?;
            dict.set_item("threads", PyList::empty(py))?;
        }
        Capture::Captured {
            pid,
            threads,
            modules,
        } => {
            dict.set_item("state", "captured")?;
            dict.set_item("pid", pid)?;
            let list = PyList::empty(py);
            for thread in &threads {
                list.append(thread_dict(py, thread)?)?;
            }
            dict.set_item("threads", list)?;
            dict.set_item("modules", modules)?;
            dict.set_item("note", NOTE)?;
        }
    }
    Ok(dict)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(watchdog_capture_stacks, module)?)?;
    Ok(())
}
