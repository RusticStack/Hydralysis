//! PyO3 binding for the Rust PE-side tools (`hy-query` / `hy-pe` / `hy-disasm`).
//!
//! `NativeImage` mirrors the text methods of `hydralysis.pe.Image`; `HYDRALYSIS_IMPL=rust` makes the Python class
//! delegate here so the same inputs can be diffed byte for byte (tests/test_rust_parity.py).

use hy_query::{prologue, tools, Image, PeError};
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
        Ok(Self {
            inner: Image::open(path).map_err(py)?,
        })
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
        Ok(PyBytes::new(
            py_,
            self.inner.read_rva(rva, size).map_err(py)?,
        ))
    }
    fn loaded_bytes<'p>(
        &self,
        py_: Python<'p>,
        rva: i64,
        size: i64,
        load_base: u64,
    ) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py_,
            &self.inner.loaded_bytes(rva, size, load_base).map_err(py)?,
        ))
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
fn find_pattern_rs(
    haystack: &Bound<'_, PyBytes>,
    pattern: Vec<Option<u8>>,
    limit: usize,
) -> PyResult<Vec<usize>> {
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
    Ok(hy_query::decompile::limitations(&parse_json(reply)?)
        .into_iter()
        .map(String::from)
        .collect())
}

#[pyfunction]
fn decompile_coverage_rs(reply: &str) -> PyResult<String> {
    Ok(hy_query::decompile::coverage(&parse_json(reply)?).to_string())
}

#[pyfunction]
fn decompile_merge_rs(response: &str, reply: &str) -> PyResult<Option<String>> {
    Ok(
        hy_query::decompile::merge(&parse_json(response)?, &parse_json(reply)?)
            .map(|v| v.to_string()),
    )
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
    use hy_query::analysis::{validate_options, Invalid};
    let parsed = match options {
        None => None,
        Some(t) => match parse_json(t)? {
            serde_json::Value::Object(m) => Some(m),
            _ => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(
                    "options is not an object",
                ))
            }
        },
    };
    match validate_options(action, parsed.as_ref(), record) {
        Ok(v) => Ok(v.to_string()),
        Err(Invalid::Value(m)) => Err(PyValueError::new_err(m)),
        Err(Invalid::Fallback) => Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "python only",
        )),
    }
}

/// `export_worker.replay` over an existing output file: the progress as JSON, or ValueError with the Python text.
#[pyfunction]
fn export_replay_rs(
    path: &str,
    job: &str,
    build: &str,
    mode: &str,
    provenance: &str,
    max_output: u64,
    max_row: usize,
) -> PyResult<String> {
    let provenance = parse_json(provenance)?;
    let p = hy_query::export::replay_file(
        std::path::Path::new(path),
        job,
        build,
        mode,
        &provenance,
        max_output,
        max_row,
    )
    .map_err(PyValueError::new_err)?;
    Ok(serde_json::json!({"keys": p.keys, "completed": p.completed, "succeeded": p.succeeded, "failed": p.failed,
                          "truncated": p.truncated}).to_string())
}

/// `body_hash`; None when Python must answer.
#[pyfunction]
#[pyo3(signature = (response, image=None))]
fn export_body_hash_rs(
    response: &str,
    image: Option<PyRef<'_, NativeImage>>,
) -> PyResult<Option<String>> {
    Ok(
        match hy_query::export::body_hash(&parse_json(response)?, image.as_ref().map(|i| &i.inner))
        {
            hy_query::export::BodyHash::Done(v) => Some(v.to_string()),
            hy_query::export::BodyHash::Unsupported => None,
        },
    )
}

#[pyfunction]
fn export_decompile_row_rs(response: &str) -> PyResult<String> {
    Ok(hy_query::export::decompile_row(&parse_json(response)?).to_string())
}

#[pyfunction]
fn export_partial_rs(response: &str) -> PyResult<bool> {
    Ok(hy_query::export::partial(&parse_json(response)?))
}

#[pyfunction]
fn export_keys_sha256_rs(keys: Vec<String>) -> String {
    hy_query::export::keys_sha256(&keys.iter().map(String::as_str).collect::<Vec<_>>())
}

#[pyfunction]
fn export_parity_rs(
    snapshot: &str,
    limit: i64,
    progress_keys: Vec<String>,
    succeeded: i64,
    failed: i64,
) -> PyResult<Option<String>> {
    let keys: Vec<&str> = progress_keys.iter().map(String::as_str).collect();
    Ok(
        hy_query::export::parity(&parse_json(snapshot)?, limit, &keys, succeeded, failed)
            .map(|v| v.to_string()),
    )
}

#[pyfunction]
fn export_sha256_file_rs(path: &str) -> PyResult<String> {
    hy_query::export::sha256_file(std::path::Path::new(path))
        .map_err(|e| PyIOError::new_err(e.to_string()))
}

#[pyfunction]
fn export_code_sha256_rs(package: &str, names: Vec<String>) -> PyResult<String> {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    hy_query::export::code_sha256(std::path::Path::new(package), &names)
        .map_err(|e| PyIOError::new_err(e.to_string()))
}

/// `crossbuild.match`: a JSON list of [source rva, destination rva, method] in Python's order; None when a row
/// is not in the shape the Rust code reads (Python answers).
#[pyfunction]
fn crossbuild_match_rs(source: &str, destination: &str) -> PyResult<Option<String>> {
    use hy_query::crossbuild::{match_builds, rows_from_json};
    let (Some(s), Some(d)) = (
        rows_from_json(&parse_json(source)?),
        rows_from_json(&parse_json(destination)?),
    ) else {
        return Ok(None);
    };
    let pairs = match_builds(&s, &d);
    let out: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(k, (o, m))| serde_json::json!([k, o, m]))
        .collect();
    Ok(Some(serde_json::Value::Array(out).to_string()))
}

pyo3::create_exception!(
    hydralysis_native,
    ClientRefusal,
    pyo3::exceptions::PyException
);

struct PyDispatch(Py<PyAny>);

impl hy_query::client::Dispatch for PyDispatch {
    fn call(
        &self,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<String, hy_query::client::DispatchError> {
        use hy_query::client::DispatchError;
        Python::attach(|py| match self.0.bind(py).call1((tool, args.to_string())) {
            Ok(v) => v.extract::<String>().map_err(|e| DispatchError {
                kind: "TypeError".into(),
                message: e.to_string(),
                caught: false,
                fatal: Some(Box::new(e)),
            }),
            Err(e) => {
                let kind = e
                    .get_type(py)
                    .name()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let message = e.value(py).str().map(|s| s.to_string()).unwrap_or_default();
                let caught = e.is_instance_of::<PyValueError>(py)
                    || e.is_instance_of::<PyIOError>(py)
                    || e.is_instance_of::<pyo3::exceptions::PyKeyError>(py)
                    || e.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py);
                Err(DispatchError {
                    kind,
                    message,
                    caught,
                    fatal: Some(Box::new(e)),
                })
            }
        })
    }
}

/// `hydralysis.client.Client` over a Python dispatch callable `(tool, args_json) -> text`; answers are JSON text.
#[pyclass(module = "hydralysis_native")]
pub struct NativeClient {
    inner: hy_query::client::Client<PyDispatch>,
}

fn client_err(py: Python<'_>, e: hy_query::client::ClientError) -> PyErr {
    use hy_query::client::ClientError;
    match e {
        ClientError::Fatal(b) => match b.downcast::<PyErr>() {
            Ok(err) => *err,
            Err(_) => pyo3::exceptions::PyRuntimeError::new_err("dispatch failed"),
        },
        ClientError::Plain { kind, message } => match kind {
            "IndexError" => pyo3::exceptions::PyIndexError::new_err(message),
            "ValueError" => PyValueError::new_err(message),
            _ => pyo3::exceptions::PyRuntimeError::new_err(message),
        },
        ClientError::Rustic(r) => {
            let err = ClientRefusal::new_err((r.message, r.result.map(|v| v.to_string())));
            if let Some(src) = r.source.and_then(|b| b.downcast::<PyErr>().ok()) {
                err.set_cause(py, Some(*src));
            }
            err
        }
    }
}

fn to_map(text: &str) -> PyResult<serde_json::Map<String, serde_json::Value>> {
    match parse_json(text)? {
        serde_json::Value::Object(m) => Ok(m),
        _ => Err(PyValueError::new_err("expected a JSON object")),
    }
}

#[pymethods]
impl NativeClient {
    #[new]
    fn new(dispatch: Py<PyAny>) -> Self {
        Self {
            inner: hy_query::client::Client::new(PyDispatch(dispatch)),
        }
    }
    fn call(&self, py: Python<'_>, tool: &str, args: &str) -> PyResult<String> {
        let a = self
            .inner
            .call(tool, &to_map(args)?)
            .map_err(|e| client_err(py, e))?;
        Ok(a.into_value().to_string())
    }
    #[pyo3(signature = (target, action, address, options))]
    fn try_query(
        &self,
        py: Python<'_>,
        target: &str,
        action: &str,
        address: &str,
        options: &str,
    ) -> PyResult<String> {
        let r = self
            .inner
            .try_query(target, action, address, to_map(options)?)
            .map_err(|e| client_err(py, e))?;
        Ok(r.unwrap_or(serde_json::Value::Null).to_string())
    }
    fn fingerprint(&self, py: Python<'_>, exe: &str) -> PyResult<String> {
        Ok(self
            .inner
            .fingerprint(exe)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn read<'p>(
        &self,
        py: Python<'p>,
        exe: &str,
        address: &str,
        size: i64,
    ) -> PyResult<Bound<'p, PyBytes>> {
        let b = self
            .inner
            .read(exe, address, size)
            .map_err(|e| client_err(py, e))?;
        Ok(PyBytes::new(py, &b))
    }
    #[pyo3(signature = (exe, rows, sha256=None))]
    fn check_prologues(
        &self,
        py: Python<'_>,
        exe: &str,
        rows: &str,
        sha256: Option<&str>,
    ) -> PyResult<String> {
        let rows = match parse_json(rows)? {
            serde_json::Value::Array(a) => a,
            _ => return Err(PyValueError::new_err("rows must be a list")),
        };
        Ok(self
            .inner
            .check_prologues(exe, &rows, sha256)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn disasm(&self, py: Python<'_>, exe: &str, address: &str, count: i64) -> PyResult<String> {
        Ok(self
            .inner
            .disasm(exe, address, count)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn inspect(&self, py: Python<'_>, exe: &str, address: &str) -> PyResult<String> {
        Ok(self
            .inner
            .inspect(exe, address)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn sigscan(&self, py: Python<'_>, exe: &str, pattern: &str, limit: i64) -> PyResult<String> {
        Ok(self
            .inner
            .sigscan(exe, pattern, limit)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn query(
        &self,
        py: Python<'_>,
        target: &str,
        action: &str,
        address: &str,
        options: &str,
    ) -> PyResult<String> {
        Ok(self
            .inner
            .query(target, action, address, to_map(options)?)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn runtime(&self, py: Python<'_>, action: &str, options: &str) -> PyResult<String> {
        Ok(self
            .inner
            .runtime(action, parse_json(options)?)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
    fn evidence(&self, py: Python<'_>, args: &str) -> PyResult<String> {
        Ok(self
            .inner
            .evidence(&to_map(args)?)
            .map_err(|e| client_err(py, e))?
            .to_string())
    }
}

#[pyfunction]
fn proc_identity_rs(pid: u32, started_ms: i64) -> bool {
    hy_query::proc::identity(pid, started_ms)
}

#[pyfunction]
fn proc_stop_rs(pid: u32, started_ms: i64) -> PyResult<()> {
    hy_query::proc::stop(pid, started_ms).map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[pyfunction]
fn proc_terminate_tree_rs(pid: u32) -> PyResult<()> {
    hy_query::proc::terminate_tree(pid).map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[pyfunction]
fn system_properties_rs(path: &str) -> Vec<(String, String)> {
    hy_query::system::properties(std::path::Path::new(path))
        .into_iter()
        .collect()
}

#[pyfunction]
fn system_children_rs(root: &str, pattern: &str) -> Vec<String> {
    hy_query::system::children(std::path::Path::new(root), pattern)
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

#[pyfunction]
fn system_native_compatible_rs(path: &str) -> bool {
    hy_query::system::native_compatible(std::path::Path::new(path))
}

#[pyfunction]
fn system_machine_rs() -> Option<String> {
    hy_query::system::machine()
}

#[pyfunction]
fn system_read_json_object_rs(path: &str) -> String {
    hy_query::system::read_json_object(std::path::Path::new(path)).to_string()
}

#[pyfunction]
fn system_instances_rs(state: &str) -> Vec<String> {
    hy_query::system::instances(std::path::Path::new(state))
}

#[pyfunction]
fn system_dir_size_rs(folder: &str) -> u64 {
    hy_query::system::dir_size(std::path::Path::new(folder))
}

#[pyfunction]
fn system_count_key_rs(value: &str, key: &str) -> PyResult<u64> {
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(hy_query::system::count_key(&parsed, key))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeImage>()?;
    module.add_class::<NativeClient>()?;
    module.add("ClientRefusal", module.py().get_type::<ClientRefusal>())?;
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
    module.add_function(wrap_pyfunction!(export_replay_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_body_hash_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_decompile_row_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_partial_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_keys_sha256_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_parity_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_sha256_file_rs, module)?)?;
    module.add_function(wrap_pyfunction!(export_code_sha256_rs, module)?)?;
    module.add_function(wrap_pyfunction!(crossbuild_match_rs, module)?)?;
    module.add_function(wrap_pyfunction!(proc_identity_rs, module)?)?;
    module.add_function(wrap_pyfunction!(proc_stop_rs, module)?)?;
    module.add_function(wrap_pyfunction!(proc_terminate_tree_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_properties_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_children_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_native_compatible_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_machine_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_read_json_object_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_instances_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_dir_size_rs, module)?)?;
    module.add_function(wrap_pyfunction!(system_count_key_rs, module)?)?;
    Ok(())
}
