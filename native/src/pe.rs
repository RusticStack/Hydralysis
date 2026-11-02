//! PyO3 binding for the Rust PE-side tools (`hy-query` / `hy-pe` / `hy-disasm`).
//!
//! `NativeImage` mirrors the text methods of `hydralysis.pe.Image`; `HYDRALYSIS_IMPL=rust` makes the Python class
//! delegate here so the same inputs can be diffed byte for byte (tests/test_rust_parity.py).

use hy_query::{Image, PeError, prologue, tools};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn py(e: PeError) -> PyErr {
    match e {
        PeError::Io(e) => PyIOError::new_err(e.to_string()),
        PeError::Overflow(m) => pyo3::exceptions::PyOverflowError::new_err(m),
        other => PyValueError::new_err(other.to_string()),
    }
}

#[pyclass(module = "hydralysis_native", name = "NativeImage")]
pub struct NativeImage {
    inner: Image,
}

#[pymethods]
impl NativeImage {
    #[staticmethod]
    fn from_bytes(name: &str, data: &Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner = Image::from_vec(name, data.as_bytes().to_vec()).map_err(py)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        Ok(Self { inner: Image::open(path).map_err(py)? })
    }

    #[setter]
    fn set_address_resolution(&mut self, json_text: Option<String>) {
        self.inner.address_resolution = json_text;
    }

    fn header(&self) -> String {
        self.inner.header()
    }
    fn fingerprint_json(&self) -> String {
        prologue::fingerprint_json(&self.inner).to_string()
    }
    fn rva_to_offset(&self, rva: i64) -> Option<usize> {
        self.inner.rva_to_offset(rva)
    }
    fn available(&self, rva: i64) -> usize {
        self.inner.available(rva)
    }
    fn read_rva<'p>(&self, py_: Python<'p>, rva: i64, size: i64) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(py_, self.inner.read_rva(rva, size).map_err(py)?))
    }
    fn loaded_bytes<'p>(&self, py_: Python<'p>, rva: i64, size: i64, load_base: u64) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(py_, &self.inner.loaded_bytes(rva, size, load_base).map_err(py)?))
    }
    #[pyo3(signature = (rva, limit=80))]
    fn string_at(&self, rva: i64, limit: usize) -> Option<String> {
        self.inner.string_at_limit(rva, limit)
    }
    #[pyo3(signature = (rva, count=40))]
    fn disasm(&self, rva: i64, count: i64) -> PyResult<String> {
        tools::disasm(&self.inner, rva, count).map_err(py)
    }
    #[pyo3(signature = (target, limit=50))]
    fn callers(&self, target: i64, limit: i64) -> PyResult<String> {
        tools::callers(&self.inner, target, limit).map_err(py)
    }
    #[pyo3(signature = (target, limit=40))]
    fn xrefs(&self, target: i64, limit: i64) -> PyResult<String> {
        tools::xrefs(&self.inner, target, limit).map_err(py)
    }
    #[pyo3(signature = (pattern, limit=30))]
    fn find_strings(&self, pattern: &str, limit: i64) -> PyResult<String> {
        tools::find_strings(&self.inner, pattern, limit).map_err(py)
    }
    fn sections_text(&self) -> String {
        tools::sections_text(&self.inner)
    }
    #[pyo3(signature = (limit=80, pattern=""))]
    fn imports_text(&self, limit: i64, pattern: &str) -> PyResult<String> {
        tools::imports_text(&self.inner, limit, pattern).map_err(py)
    }
    #[pyo3(signature = (limit=80))]
    fn exports_text(&self, limit: i64) -> String {
        tools::exports_text(&self.inner, limit)
    }
    #[pyo3(signature = (pattern, limit=20))]
    fn sigscan(&self, pattern: &str, limit: i64) -> PyResult<String> {
        tools::sigscan(&self.inner, pattern, limit).map_err(py)
    }
    #[pyo3(signature = (rva, limit=30))]
    fn callees(&self, rva: i64, limit: i64) -> PyResult<String> {
        tools::callees(&self.inner, rva, limit).map_err(py)
    }
    fn inspect(&self, rva: i64) -> PyResult<String> {
        tools::inspect(&self.inner, rva).map_err(py)
    }
    fn function_of(&self, rva: i64) -> PyResult<String> {
        tools::function_of(&self.inner, rva).map_err(py)
    }
}

#[pyfunction]
fn parse_expect_rs(text: &str) -> PyResult<Vec<Option<u8>>> {
    prologue::parse_expect(text).map_err(py)
}

#[pyfunction]
fn find_pattern_rs(haystack: &Bound<'_, PyBytes>, pattern: Vec<Option<u8>>, limit: usize) -> PyResult<Vec<usize>> {
    prologue::find_pattern(haystack.as_bytes(), &pattern, limit).map_err(py)
}

#[pyfunction]
fn parse_rva_rs(text: &str, image_base: u64) -> PyResult<i64> {
    prologue::parse_rva(text, image_base).map_err(py)
}

fn parse_json(text: &str) -> PyResult<serde_json::Value> {
    serde_json::from_str(text).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// `decompile_result.summarize` on a JSON object text; returns the summary object text.
#[pyfunction]
fn decompile_summarize_rs(reply: &str) -> PyResult<String> {
    Ok(serde_json::Value::Object(hy_query::decompile::summarize(&parse_json(reply)?)).to_string())
}

#[pyfunction]
fn decompile_fragments_rs(value: &str) -> PyResult<String> {
    let v = parse_json(value)?;
    let (kept, note) = hy_query::decompile::fragments(Some(&v));
    Ok(serde_json::json!([kept, note]).to_string())
}

#[pyfunction]
fn decompile_limitations_rs(reply: &str) -> PyResult<Vec<String>> {
    Ok(hy_query::decompile::limitations(&parse_json(reply)?).into_iter().map(String::from).collect())
}

#[pyfunction]
fn decompile_coverage_rs(reply: &str) -> PyResult<String> {
    Ok(hy_query::decompile::coverage(&parse_json(reply)?).to_string())
}

#[pyfunction]
fn decompile_merge_rs(response: &str, reply: &str) -> PyResult<Option<String>> {
    Ok(hy_query::decompile::merge(&parse_json(response)?, &parse_json(reply)?).map(|v| v.to_string()))
}

#[pyfunction]
fn decompile_from_error_rs(message: &str) -> Option<String> {
    hy_query::decompile::from_error(message).map(|v| v.to_string())
}

/// `analysis.validate_options`: the validated options as JSON text; ValueError with the exact message, or
/// NotImplementedError when this input needs the Python implementation.
#[pyfunction]
#[pyo3(signature = (action, options=None, record=false))]
fn validate_options_rs(action: &str, options: Option<&str>, record: bool) -> PyResult<String> {
    use hy_query::analysis::{Invalid, validate_options};
    let parsed = match options {
        None => None,
        Some(t) => match parse_json(t)? {
            serde_json::Value::Object(m) => Some(m),
            _ => return Err(pyo3::exceptions::PyNotImplementedError::new_err("options is not an object")),
        },
    };
    match validate_options(action, parsed.as_ref(), record) {
        Ok(v) => Ok(v.to_string()),
        Err(Invalid::Value(m)) => Err(PyValueError::new_err(m)),
        Err(Invalid::Fallback) => Err(pyo3::exceptions::PyNotImplementedError::new_err("python only")),
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeImage>()?;
    module.add_function(wrap_pyfunction!(parse_expect_rs, module)?)?;
    module.add_function(wrap_pyfunction!(find_pattern_rs, module)?)?;
    module.add_function(wrap_pyfunction!(parse_rva_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_summarize_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_fragments_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_limitations_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_coverage_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_merge_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_from_error_rs, module)?)?;
    module.add_function(wrap_pyfunction!(validate_options_rs, module)?)?;
    Ok(())
}
