//! Binding of `hy_trace::hashes`: the hash functions, the dictionary and the constant scan behind
//! `hydralysis.trace_hashes` when `HYDRALYSIS_IMPL=rust`.

use super::port::{fallback, map_error, or_fallback};
use hy_trace::hashes::{
    self, annotate_constants, Algorithm, Codec, CrcParams, Dictionary, Encoding, FnvVariant, Fold,
    SectionBytes,
};
use hy_trace::pyfmt::{parse_int_base0, IntParse};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use std::collections::BTreeSet;

fn get<'py>(spec: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(spec.get_item(key)?.filter(|v| !v.is_none()))
}

fn get_u64(spec: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    get(spec, key)?
        .map(|v| or_fallback(v.extract::<u64>()))
        .transpose()
}

fn get_i64(spec: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<i64>> {
    get(spec, key)?
        .map(|v| or_fallback(v.extract::<i64>()))
        .transpose()
}

fn get_bool(spec: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    get(spec, key)?
        .map(|v| or_fallback(v.extract::<bool>()))
        .transpose()
}

fn get_str(spec: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    get(spec, key)?
        .map(|v| or_fallback(v.extract::<String>()))
        .transpose()
}

/// An `Algorithm.spec` dict of the Python side:
/// `{name, bits, fold, encoding, codec: fnv|crc32|crc|murmur3, ...codec parameters}`.
fn algorithm_of(spec: &Bound<'_, PyDict>) -> PyResult<Algorithm> {
    let name = get_str(spec, "name")?.ok_or_else(|| fallback("an algorithm without a name"))?;
    let bits = get_i64(spec, "bits")?.ok_or_else(|| fallback("an algorithm without a width"))?;
    let fold = get_str(spec, "fold")?
        .as_deref()
        .and_then(Fold::parse)
        .ok_or_else(|| fallback("fold"))?;
    let encoding = get_str(spec, "encoding")?
        .as_deref()
        .and_then(Encoding::parse)
        .ok_or_else(|| fallback("encoding"))?;
    let codec = match get_str(spec, "codec")?.as_deref() {
        Some("fnv") => {
            let variant = match get_str(spec, "variant")?.as_deref() {
                Some("1") => FnvVariant::V1,
                Some("1a") => FnvVariant::V1a,
                _ => return Err(fallback("FNV variant")),
            };
            let width = get_i64(spec, "width")?.unwrap_or(bits);
            Codec::Fnv {
                variant,
                bits: width,
                basis: get_u64(spec, "basis")?,
                prime: get_u64(spec, "prime")?,
            }
        }
        Some("crc32") => Codec::Crc32,
        Some("crc") => {
            let mut params = CrcParams::with_width(get_i64(spec, "width")?.unwrap_or(bits));
            if let Some(v) = get_u64(spec, "poly")? {
                params.poly = v;
            }
            if let Some(v) = get_u64(spec, "init")? {
                params.init = v;
            }
            if let Some(v) = get_u64(spec, "xorout")? {
                params.xorout = v;
            }
            if let Some(v) = get_bool(spec, "refin")? {
                params.refin = v;
            }
            if let Some(v) = get_bool(spec, "refout")? {
                params.refout = v;
            }
            Codec::Crc(params)
        }
        Some("murmur3") => Codec::Murmur3 {
            seed: get_u64(spec, "seed")?.unwrap_or(0),
        },
        _ => return Err(fallback("codec")),
    };
    Ok(Algorithm {
        name,
        bits,
        codec,
        fold,
        encoding,
    })
}

/// One hash function, built once from its spec: the fast path of `Algorithm.__call__`.
#[pyclass(name = "HashFn", module = "hydralysis_native")]
pub struct HashFn {
    algorithm: Algorithm,
}

#[pymethods]
impl HashFn {
    #[new]
    fn new(spec: &Bound<'_, PyDict>) -> PyResult<Self> {
        Ok(Self {
            algorithm: algorithm_of(spec)?,
        })
    }

    /// The hash of already-encoded bytes.
    fn hash_bytes(&self, data: &[u8]) -> PyResult<u64> {
        self.algorithm.codec.hash(data).map_err(map_error)
    }

    /// The hash of text: fold, encode, hash.
    fn hash_text(&self, text: &str) -> PyResult<u64> {
        self.algorithm.hash_text(text).map_err(map_error)
    }
}

/// The names of a dictionary with their sources and the `(algorithm, hash)` index, in Rust.
#[pyclass(name = "NativeDictionary", module = "hydralysis_native")]
pub struct NativeDictionary {
    inner: Dictionary,
}

#[pymethods]
impl NativeDictionary {
    /// ALGORITHMS: the specs of the distinct algorithms; LISTED: the dictionary's algorithm names as given.
    #[new]
    fn new(algorithms: &Bound<'_, PyList>, listed: Vec<String>) -> PyResult<Self> {
        let algorithms = algorithms
            .iter()
            .map(|item| {
                algorithm_of(
                    item.cast::<PyDict>()
                        .map_err(|_| fallback("algorithm spec"))?,
                )
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: Dictionary::new(algorithms, listed),
        })
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn add(&mut self, name: &Bound<'_, PyAny>, source: &Bound<'_, PyAny>) -> PyResult<()> {
        let name = text_arg(name)?;
        let source = text_arg(source)?;
        self.inner.add(&name, &source).map_err(map_error)
    }

    /// Add every name of NAMES (a list of text) under SOURCE; returns how many were added.
    fn add_many(
        &mut self,
        py: Python<'_>,
        names: &Bound<'_, PyAny>,
        source: &Bound<'_, PyAny>,
    ) -> PyResult<usize> {
        let source = text_arg(source)?;
        let names = names
            .try_iter()?
            .map(|item| text_arg(&item?))
            .collect::<PyResult<Vec<String>>>()?;
        let inner = &mut self.inner;
        py.detach(|| inner.add_many(names.iter().map(String::as_str), &source))
            .map_err(map_error)
    }

    fn resolve<'py>(
        &self,
        py: Python<'py>,
        algorithm: &str,
        hash: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let answer = self.inner.resolve(algorithm, hash).map_err(map_error)?;
        super::port::from_value(py, &answer.to_value())
    }

    fn collisions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let list = PyList::empty(py);
        for answer in self.inner.collisions() {
            list.append(super::port::from_value(py, &answer.to_value())?)?;
        }
        Ok(list.into_any())
    }

    fn digest(&mut self) -> String {
        self.inner.digest()
    }

    /// `[(name, [sources])]`, names sorted.
    fn entries(&self) -> Vec<(String, Vec<String>)> {
        self.inner.entries()
    }

    /// `annotate_constants`: for each number, `(status, [answer dicts])`.
    fn annotate<'py>(
        &self,
        py: Python<'py>,
        numbers: Vec<u64>,
        algorithms: Vec<(String, i64)>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let notes = annotate_constants(&self.inner, &numbers, &algorithms).map_err(map_error)?;
        let out = PyList::empty(py);
        for note in notes {
            let answers = PyList::empty(py);
            for answer in &note.answers {
                answers.append(super::port::from_value(py, &answer.to_value())?)?;
            }
            out.append((note.status, answers))?;
        }
        Ok(out.into_any())
    }

    /// `interpretation(...)` without the Python-side shaping: `(header dict, rows list)`.
    fn interpret<'py>(
        &mut self,
        py: Python<'py>,
        algorithm: &str,
        values: Vec<u64>,
        parent: Option<String>,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let revision = self
            .inner
            .interpretation(algorithm, &values, parent.as_deref())
            .map_err(map_error)?;
        self.shape(py, &revision)
    }

    /// `interpret_events`: resolve the hashed payload FIELDS of EVENTS; `(header dict, annotations list)`.
    fn interpret_events<'py>(
        &mut self,
        py: Python<'py>,
        algorithm: &str,
        events: &Bound<'py, PyList>,
        fields: Vec<String>,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let mut wanted = BTreeSet::new();
        let mut notes: Vec<(Bound<'py, PyAny>, &str, u64)> = Vec::new();
        for event in events.iter() {
            let event = event
                .cast_into::<PyDict>()
                .map_err(|_| fallback("an event that is not a dict"))?;
            let payload = match event.get_item("payload")? {
                Some(p) if p.is_truthy()? => p
                    .cast_into::<PyDict>()
                    .map_err(|_| fallback("a payload that is not a dict"))?,
                _ => continue,
            };
            let event_id = event
                .get_item("event_id")?
                .unwrap_or_else(|| py.None().into_bound(py));
            for field in &fields {
                let Some(value) = payload.get_item(field)? else {
                    continue;
                };
                if value.is_instance_of::<PyDict>() || value.is_instance_of::<PyList>() {
                    continue;
                }
                if let Some(number) = hash_of(&value)? {
                    wanted.insert(number);
                    notes.push((event_id.clone(), field.as_str(), number));
                }
            }
        }
        let values: Vec<u64> = wanted.into_iter().collect();
        let revision = self
            .inner
            .interpretation(algorithm, &values, None)
            .map_err(map_error)?;
        let by_hash: std::collections::HashMap<u64, &hashes::Resolution> =
            revision.rows.iter().map(|r| (r.hash, r)).collect();
        let annotations = PyList::empty(py);
        for (event_id, field, number) in notes {
            let row = by_hash[&number];
            let entry = PyDict::new(py);
            entry.set_item("event_id", event_id)?;
            entry.set_item("field", field)?;
            entry.set_item("raw", hashes::format_hash(number))?;
            entry.set_item("status", row.status())?;
            entry.set_item("names", super::port::from_value(py, &row.names_value())?)?;
            annotations.append(entry)?;
        }
        let (header, _rows) = self.shape(py, &revision)?;
        Ok((header, annotations.into_any()))
    }
}

impl NativeDictionary {
    fn shape<'py>(
        &self,
        py: Python<'py>,
        revision: &hashes::Interpretation,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let header = PyDict::new(py);
        for (key, value) in revision.header() {
            header.set_item(key, super::port::from_value(py, &value)?)?;
        }
        header.set_item("counts", super::port::from_value(py, &revision.counts())?)?;
        let rows = PyList::empty(py);
        for row in &revision.rows {
            rows.append(super::port::from_value(py, &row.to_value())?)?;
        }
        Ok((header.into_any(), rows.into_any()))
    }
}

fn text_arg(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    let text = obj
        .cast::<PyString>()
        .map_err(|_| fallback("a name or source that is not text"))?;
    or_fallback(text.to_str().map(str::to_owned))
}

/// `parse_hash(value)` where a failure means "not a hash": `Some(number)` or `None`. Shapes whose Python
/// `str()` could be a number in some way the port does not follow are a fallback.
fn hash_of(value: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
    if value.is_instance_of::<PyBool>() {
        return Ok(None);
    }
    if value.is_instance_of::<PyInt>() {
        return Ok(value.extract::<u64>().ok());
    }
    if let Ok(text) = value.cast::<PyString>() {
        let text = or_fallback(text.to_str())?;
        return match parse_int_base0(text) {
            IntParse::Value(v) => Ok(u64::try_from(v).ok()),
            IntParse::Invalid => Ok(None),
            IntParse::NotAscii => Err(fallback("non-ASCII digits")),
        };
    }
    // float, None, tuple, bytes: their `str()` is never an integer literal
    if value.is_none()
        || value.is_instance_of::<PyFloat>()
        || value.is_instance_of::<PyTuple>()
        || value.is_instance_of::<PyBytes>()
    {
        return Ok(None);
    }
    Err(fallback(
        "a payload value of a type the hash parse does not model",
    ))
}

/// `scan_constants` over an image's bytes. SECTIONS: `(name bytes, virtual address, raw pointer, raw size,
/// characteristics)`; HASHES: `(value, bits)`; BOUNDS: `image._bounds` or None; FUNCTIONS: `[(start, end)]` or None.
/// Returns `(hit dicts, truncated)`.
#[pyfunction]
#[pyo3(signature = (data, sections, hashes, limit, bounds, functions))]
pub fn scan_constants<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyBytes>,
    sections: Vec<(Vec<u8>, u64, usize, usize, u64)>,
    hashes: Vec<(u64, i64)>,
    limit: usize,
    bounds: Option<Bound<'py, PyAny>>,
    functions: Option<Vec<(u64, u64)>>,
) -> PyResult<(Bound<'py, PyAny>, bool)> {
    let bytes = data.as_bytes();
    let views: Vec<SectionBytes<'_>> = sections
        .into_iter()
        .map(|(name, virtual_address, pointer, size, characteristics)| {
            let start = pointer.min(bytes.len());
            let end = pointer.saturating_add(size).min(bytes.len());
            let trimmed = name
                .iter()
                .rposition(|&b| b != 0)
                .map_or(&name[..0], |last| &name[..=last]);
            SectionBytes {
                name: String::from_utf8_lossy(trimmed).into_owned(),
                virtual_address,
                raw: &bytes[start..end],
                executable: characteristics & 0x2000_0000 != 0,
            }
        })
        .collect();
    // `image._bounds(rva)` is Python: it runs with the GIL held; an exception means "no function to name".
    let mut callback = |rva: u64| -> Option<(u64, u64)> {
        let bounds = bounds.as_ref()?;
        let answer = bounds.call1((rva,)).ok()?;
        if answer.is_none() {
            return None;
        }
        answer.extract::<(u64, u64)>().ok()
    };
    let (hits, truncated) =
        hashes::scan_constants(&views, &hashes, limit, functions.as_deref(), &mut callback)
            .map_err(map_error)?;
    let list = PyList::empty(py);
    for hit in &hits {
        list.append(super::port::from_value(py, &hit.to_value())?)?;
    }
    Ok((list.into_any(), truncated))
}

fn opt_u64(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<u64>> {
    match value {
        None => Ok(None),
        Some(v) if v.is_none() => Ok(None),
        Some(v) => or_fallback(v.extract::<u64>()).map(Some),
    }
}

/// `trace_hashes.fnv(data, bits, variant=, basis=, prime=)`.
#[pyfunction]
#[pyo3(signature = (data, bits, variant="1a", basis=None, prime=None))]
fn fnv(
    data: &[u8],
    bits: i64,
    variant: &str,
    basis: Option<&Bound<'_, PyAny>>,
    prime: Option<&Bound<'_, PyAny>>,
) -> PyResult<u64> {
    let variant = match variant {
        "1a" => FnvVariant::V1a,
        "1" => FnvVariant::V1,
        _ => {
            // the width is checked first, then the variant
            hashes::fnv(data, bits, FnvVariant::V1a, None, None).map_err(map_error)?;
            return Err(map_error(hy_trace::Error::hash(
                "bad_variant",
                "FNV variant is 1 or 1a",
            )));
        }
    };
    hashes::fnv(data, bits, variant, opt_u64(basis)?, opt_u64(prime)?).map_err(map_error)
}

/// `trace_hashes.crc_generic(data, width=, poly=, init=, xorout=, refin=, refout=)`.
#[pyfunction]
#[pyo3(signature = (data, width=32, poly=None, init=None, xorout=None, refin=true, refout=true))]
fn crc_generic(
    data: &[u8],
    width: i64,
    poly: Option<&Bound<'_, PyAny>>,
    init: Option<&Bound<'_, PyAny>>,
    xorout: Option<&Bound<'_, PyAny>>,
    refin: bool,
    refout: bool,
) -> PyResult<u64> {
    let defaults = CrcParams::with_width(width);
    let params = CrcParams {
        width,
        poly: opt_u64(poly)?.unwrap_or(defaults.poly),
        init: opt_u64(init)?.unwrap_or(defaults.init),
        xorout: opt_u64(xorout)?.unwrap_or(defaults.xorout),
        refin,
        refout,
    };
    hashes::crc_generic(data, &params).map_err(map_error)
}

/// `trace_hashes.murmur3_32(data, seed=0)`.
#[pyfunction]
#[pyo3(signature = (data, seed=None))]
fn murmur3_32(data: &[u8], seed: Option<&Bound<'_, PyAny>>) -> PyResult<u64> {
    Ok(hashes::murmur3_32(data, opt_u64(seed)?.unwrap_or(0)))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(fnv, module)?)?;
    module.add_function(wrap_pyfunction!(crc_generic, module)?)?;
    module.add_function(wrap_pyfunction!(murmur3_32, module)?)?;
    module.add_class::<HashFn>()?;
    module.add_class::<NativeDictionary>()?;
    module.add_function(wrap_pyfunction!(scan_constants, module)?)?;
    Ok(())
}
