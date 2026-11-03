//! Python bindings for `hy_runtime::decode` (`runtime_decode.py` under `HYDRALYSIS_IMPL=rust`).
//!
//! The specs and captures are read straight from the Python objects (borrowed `&str`, no intermediate document) and the
//! answers are built straight as Python lists and dicts, with the key order the Python module builds. A `ValueError` is
//! the one Python itself raises, with its message; any shape the port does not model (a subclass, a tuple, a float where
//! Python calls `int()`, an integer beyond 64 bits, a non-finite float, a lone surrogate, ...) raises `Unmodelled` and the
//! Python function answers.

use crate::convert::unmodelled;
use hy_runtime::decode::{
    self as core, MAX_ARG, MAX_CAPTURES, MAX_FIELD_OFFSET, MAX_LABEL, MAX_NAMES, MAX_OFFSET, MAX_SIZE, Raw, Scalar, ShortBuffer,
};
use pyo3::exceptions::PyValueError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString};

type Obj<'py> = Bound<'py, PyAny>;

fn invalid<T>(message: String) -> PyResult<T> {
    Err(PyValueError::new_err(message))
}

/// A plain Python value of one of the exact JSON-like types; anything else is `Unmodelled`.
enum Plain<'py> {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(Bound<'py, PyString>),
    List(Bound<'py, PyList>),
    Dict(Bound<'py, PyDict>),
}

impl Plain<'_> {
    /// Python truthiness of the value.
    fn truthy(&self) -> PyResult<bool> {
        Ok(match self {
            Plain::Null => false,
            Plain::Bool(b) => *b,
            Plain::Int(n) => *n != 0,
            Plain::Float(f) => *f != 0.0,
            Plain::Str(s) => !text(s)?.is_empty(),
            Plain::List(l) => !l.is_empty(),
            Plain::Dict(d) => !d.is_empty(),
        })
    }
}

fn plain<'py>(obj: &Obj<'py>) -> PyResult<Plain<'py>> {
    if obj.is_none() {
        return Ok(Plain::Null);
    }
    if let Ok(s) = obj.cast_exact::<PyString>() {
        return Ok(Plain::Str(s.clone()));
    }
    if obj.is_exact_instance_of::<PyInt>() {
        return int128(obj).map(Plain::Int);
    }
    if let Ok(d) = obj.cast_exact::<PyDict>() {
        return Ok(Plain::Dict(d.clone()));
    }
    if let Ok(l) = obj.cast_exact::<PyList>() {
        return Ok(Plain::List(l.clone()));
    }
    if obj.is_exact_instance_of::<PyBool>() {
        return Ok(Plain::Bool(obj.is_truthy()?));
    }
    if obj.is_exact_instance_of::<PyFloat>() {
        return Ok(Plain::Float(obj.extract::<f64>()?));
    }
    Err(unmodelled())
}

/// An exact `int` of at most 64 bits (signed or unsigned).
fn int128(obj: &Obj<'_>) -> PyResult<i128> {
    if let Ok(n) = obj.extract::<i64>() {
        return Ok(i128::from(n));
    }
    obj.extract::<u64>().map(i128::from).map_err(|_| unmodelled())
}

/// The text of a `str`; a lone surrogate is not modelled.
fn text<'a>(s: &'a Bound<'_, PyString>) -> PyResult<&'a str> {
    s.to_str().map_err(|_| unmodelled())
}

/// `str(value)` for a value that must already be a `str`.
fn exact_str<'py>(obj: &Obj<'py>) -> PyResult<Bound<'py, PyString>> {
    obj.cast_exact::<PyString>().cloned().map_err(|_| unmodelled())
}

/// `Some` for an exact `str`, `None` for any non-`str`; a `str` subclass is not modelled.
fn str_or_none<'py>(obj: &Obj<'py>) -> PyResult<Option<Bound<'py, PyString>>> {
    match obj.cast_exact::<PyString>() {
        Ok(s) => Ok(Some(s.clone())),
        Err(_) if obj.is_instance_of::<PyString>() => Err(unmodelled()),
        Err(_) => Ok(None),
    }
}

/// `int(value)` for the one shape modelled: an exact `int` that fits `i64`.
fn int_of(obj: &Obj<'_>) -> PyResult<i64> {
    match plain(obj)? {
        Plain::Int(n) => i64::try_from(n).map_err(|_| unmodelled()),
        _ => Err(unmodelled()),
    }
}

fn exact_dict<'py>(obj: &Obj<'py>) -> PyResult<Bound<'py, PyDict>> {
    obj.cast_exact::<PyDict>().cloned().map_err(|_| unmodelled())
}

fn exact_list<'py>(obj: &Obj<'py>) -> PyResult<Bound<'py, PyList>> {
    obj.cast_exact::<PyList>().cloned().map_err(|_| unmodelled())
}

/// The bytes of a `bytes` argument; a `bytearray` or `memoryview` is left to Python.
fn bytes_of<'a>(data: &'a Obj<'_>) -> PyResult<&'a [u8]> {
    data.cast_exact::<PyBytes>().map(|b| b.as_bytes()).map_err(|_| unmodelled())
}

// ---- normalize ---------------------------------------------------------------------------------------------------------

/// The values of one capture dict, by key.
#[derive(Default)]
struct Slots<'py> {
    arg: Option<Obj<'py>>,
    reg: Option<Obj<'py>>,
    deref: Option<Obj<'py>>,
    size: Option<Obj<'py>>,
    kind: Option<Obj<'py>>,
    fields: Option<Obj<'py>>,
    names: Option<Obj<'py>>,
    label: Option<Obj<'py>>,
}

fn accepts_message(index: usize) -> String {
    format!("capture {index} accepts arg or reg, deref, size, as, fields, names, label")
}

/// Sort the entries of a capture dict into their slots; an unknown key is the `accepts` error.
fn slots_of<'py>(index: usize, item: &Bound<'py, PyDict>) -> PyResult<Slots<'py>> {
    let mut slots = Slots::default();
    for (key, value) in item.iter() {
        let Ok(key) = key.cast_exact::<PyString>() else {
            if key.is_instance_of::<PyString>() {
                return Err(unmodelled());
            }
            return invalid(accepts_message(index));
        };
        let slot = match text(key)? {
            "arg" => &mut slots.arg,
            "reg" => &mut slots.reg,
            "deref" => &mut slots.deref,
            "size" => &mut slots.size,
            "as" => &mut slots.kind,
            "fields" => &mut slots.fields,
            "names" => &mut slots.names,
            "label" => &mut slots.label,
            _ => return invalid(accepts_message(index)),
        };
        *slot = Some(value);
    }
    Ok(slots)
}

/// The accepted `deref` list (the very list object, as Python keeps it), or a fresh empty one.
fn deref_of<'py>(py: Python<'py>, index: usize, deref: Option<&Obj<'py>>) -> PyResult<Bound<'py, PyList>> {
    let error = || invalid(format!("capture {index} deref is up to 4 offsets: read a pointer at each"));
    let Some(deref) = deref else { return Ok(PyList::empty(py)) };
    let Ok(list) = deref.cast_exact::<PyList>() else {
        plain(deref)?;
        return error();
    };
    if list.len() > 4 {
        return error();
    }
    for offset in list.iter() {
        match plain(&offset)? {
            Plain::Int(n) if (0..i128::from(MAX_OFFSET)).contains(&n) => {}
            _ => return error(),
        }
    }
    Ok(list.clone())
}

struct Field<'py> {
    name: Bound<'py, PyString>,
    offset: i64,
    scalar: Scalar,
}

/// The struct fields of a capture, validated; `fields or []`.
fn fields_of<'py>(index: usize, fields: Option<&Obj<'py>>) -> PyResult<Vec<Field<'py>>> {
    let error = || invalid(format!("capture {index} struct fields need name, offset and a scalar type"));
    let listed = match fields {
        None => return Ok(Vec::new()),
        Some(value) => match plain(value)? {
            Plain::List(list) => list,
            other if !other.truthy()? => return Ok(Vec::new()),
            _ => return Err(unmodelled()),
        },
    };
    let mut out = Vec::with_capacity(listed.len());
    for field in listed.iter() {
        let Ok(field) = field.cast_exact::<PyDict>() else {
            plain(&field)?;
            return error();
        };
        let type_name = match field.get_item(intern!(field.py(), "type"))? {
            None => String::new(),
            Some(value) => text(&exact_str(&value)?)?.to_owned(),
        };
        let name = match field.get_item(intern!(field.py(), "name"))? {
            Some(name) => str_or_none(&name)?,
            None => None,
        };
        let (Some(name), Some(scalar)) = (name, core::scalar(&type_name)) else { return error() };
        let offset = match field.get_item(intern!(field.py(), "offset"))? {
            None => 0,
            Some(value) => int_of(&value)?,
        };
        if offset.abs() > MAX_FIELD_OFFSET {
            return Err(unmodelled());
        }
        out.push(Field { name, offset, scalar });
    }
    Ok(out)
}

/// `str(value)` for the values a `names` entry holds in practice.
fn name_text<'py>(py: Python<'py>, value: &Obj<'py>) -> PyResult<Obj<'py>> {
    Ok(match plain(value)? {
        Plain::Str(_) => value.clone(),
        Plain::Int(n) => PyString::new(py, &n.to_string()).into_any(),
        Plain::Bool(true) => PyString::new(py, "True").into_any(),
        Plain::Bool(false) => PyString::new(py, "False").into_any(),
        Plain::Null => PyString::new(py, "None").into_any(),
        _ => return Err(unmodelled()),
    })
}

/// The normalised `names` dict: every key as `str(int(key, 0))`.
fn names_of<'py>(py: Python<'py>, index: usize, names: Option<&Obj<'py>>) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    let Some(names) = names else { return Ok(out) };
    match plain(names)? {
        Plain::Dict(listed) => {
            if listed.len() > MAX_NAMES {
                return invalid(format!("capture {index} names maps values to names"));
            }
            for (key, value) in listed.iter() {
                let number = core::parse_int_base0(text(&exact_str(&key)?)?).ok_or_else(unmodelled)?;
                out.set_item(PyString::new(py, &number.to_string()), name_text(py, &value)?)?;
            }
            Ok(out)
        }
        other if !other.truthy()? => Ok(out),
        _ => invalid(format!("capture {index} names maps values to names")),
    }
}

/// `str(label)[:64]`.
fn label_of<'py>(py: Python<'py>, label: Option<&Obj<'py>>) -> PyResult<Obj<'py>> {
    let Some(label) = label else { return Ok(intern!(py, "").clone().into_any()) };
    let label = exact_str(label)?;
    let full = text(&label)?;
    if full.chars().nth(MAX_LABEL).is_none() {
        return Ok(label.into_any());
    }
    Ok(PyString::new(py, &full.chars().take(MAX_LABEL).collect::<String>()).into_any())
}

fn normalize_one<'py>(py: Python<'py>, index: usize, item: &Obj<'py>) -> PyResult<Obj<'py>> {
    let Ok(item) = item.cast_exact::<PyDict>() else {
        plain(item)?;
        return invalid(accepts_message(index));
    };
    let slots = slots_of(index, item)?;
    let arg = slots.arg.filter(|a| !a.is_none());
    let reg = slots.reg.filter(|r| !r.is_none());
    if let Some(reg) = &reg {
        let valid = arg.is_none() && matches!(plain(reg)?, Plain::Str(s) if core::is_register_name(text(&s)?));
        if !valid {
            return invalid(format!("capture {index}: reg is one register name (e.g. ecx, rdx), instead of arg"));
        }
    } else {
        let in_range = match &arg {
            Some(arg) => matches!(plain(arg)?, Plain::Int(n) if (0..=i128::from(MAX_ARG)).contains(&n)),
            None => false,
        };
        if !in_range {
            return invalid(format!("capture {index} needs arg 0..7 or reg"));
        }
    }
    let deref = deref_of(py, index, slots.deref.as_ref())?;
    let kind_given = match &slots.kind {
        None => intern!(py, "hex").clone(),
        Some(kind) => exact_str(kind)?,
    };
    let kind_text = text(&kind_given)?;
    let mut fields = Vec::new();
    let needed: i64;
    let kind: Obj<'py>;
    let mut scalar_kind = false;
    if kind_text == "struct" {
        fields = fields_of(index, slots.fields.as_ref())?;
        if fields.is_empty() {
            return invalid(format!("capture {index} struct needs fields"));
        }
        needed = fields.iter().map(|f| f.offset + f.scalar.size() as i64).max().unwrap_or(0);
        kind = kind_given.clone().into_any();
    } else if matches!(kind_text, "utf8" | "utf16" | "hex") {
        needed = 0;
        kind = kind_given.clone().into_any();
    } else if let Some(scalar) = core::scalar(kind_text) {
        needed = scalar.size() as i64;
        kind = PyString::intern(py, scalar.name()).into_any();
        scalar_kind = true;
    } else {
        return invalid(format!("capture {index}: unknown decoder {kind_text}"));
    }
    let size = match &slots.size {
        None if needed != 0 => needed,
        None => 256,
        Some(size) => int_of(size)?,
    };
    if !(needed <= size && size <= MAX_SIZE) || size < 1 {
        return invalid(format!("capture {index} size must be 1..4096 and cover its decoder"));
    }
    let names = names_of(py, index, slots.names.as_ref())?;
    let label = label_of(py, slots.label.as_ref())?;
    let field_rows = PyList::empty(py);
    for field in &fields {
        let row = PyDict::new(py);
        row.set_item(intern!(py, "name"), &field.name)?;
        row.set_item(intern!(py, "offset"), field.offset)?;
        row.set_item(intern!(py, "type"), PyString::intern(py, field.scalar.name()))?;
        field_rows.append(row)?;
    }
    let out = PyDict::new(py);
    out.set_item(intern!(py, "arg"), arg.unwrap_or_else(|| py.None().into_bound(py)))?;
    out.set_item(intern!(py, "reg"), reg.unwrap_or_else(|| py.None().into_bound(py)))?;
    out.set_item(intern!(py, "deref"), &deref)?;
    out.set_item(intern!(py, "size"), size)?;
    out.set_item(intern!(py, "as"), kind)?;
    out.set_item(intern!(py, "fields"), field_rows)?;
    out.set_item(intern!(py, "names"), names)?;
    out.set_item(intern!(py, "label"), label)?;
    out.set_item(intern!(py, "value_only"), deref.is_empty() && scalar_kind && size <= 8)?;
    Ok(out.into_any())
}

/// `runtime_decode.normalize`.
#[pyfunction]
pub fn decode_normalize<'py>(py: Python<'py>, captures: &Obj<'py>) -> PyResult<Obj<'py>> {
    let items = match plain(captures)? {
        Plain::Null => return Ok(PyList::empty(py).into_any()),
        Plain::List(list) if list.len() <= MAX_CAPTURES => list,
        _ => return invalid(format!("capture must be a list of at most {MAX_CAPTURES} argument captures")),
    };
    let out = PyList::empty(py);
    for (index, item) in items.iter().enumerate() {
        out.append(normalize_one(py, index, &item)?)?;
    }
    Ok(out.into_any())
}

// ---- decode ------------------------------------------------------------------------------------------------------------

/// What a normalised capture spec decodes its buffer as.
enum Decoder<'py> {
    Utf8,
    Utf16,
    Hex,
    Struct(Vec<Field<'py>>),
    Scalar(Scalar),
}

/// A normalised capture spec, read from its dict.
struct Spec<'py> {
    dict: Bound<'py, PyDict>,
    decoder: Decoder<'py>,
}

impl<'py> Spec<'py> {
    fn read(spec: &Obj<'py>) -> PyResult<Self> {
        let dict = exact_dict(spec)?;
        let py = dict.py();
        let kind = dict.get_item(intern!(py, "as"))?.ok_or_else(unmodelled)?;
        let kind = exact_str(&kind)?;
        let decoder = match text(&kind)? {
            "utf8" => Decoder::Utf8,
            "utf16" => Decoder::Utf16,
            "hex" => Decoder::Hex,
            "struct" => {
                let listed = dict.get_item(intern!(py, "fields"))?.ok_or_else(unmodelled)?;
                let mut fields = Vec::new();
                for field in exact_list(&listed)?.iter() {
                    let field = exact_dict(&field)?;
                    let name = field.get_item(intern!(py, "name"))?.ok_or_else(unmodelled)?;
                    let offset = int_of(&field.get_item(intern!(py, "offset"))?.ok_or_else(unmodelled)?)?;
                    let kind = field.get_item(intern!(py, "type"))?.ok_or_else(unmodelled)?;
                    let scalar = Scalar::from_canonical(text(&exact_str(&kind)?)?).ok_or_else(unmodelled)?;
                    if offset < 0 {
                        return Err(unmodelled());
                    }
                    fields.push(Field { name: exact_str(&name)?, offset, scalar });
                }
                Decoder::Struct(fields)
            }
            other => Decoder::Scalar(Scalar::from_canonical(other).ok_or_else(unmodelled)?),
        };
        Ok(Self { dict, decoder })
    }
}

/// Why a buffer did not decode.
enum Failure {
    /// Python's `struct.error`.
    Short(ShortBuffer),
    /// Not modelled (or a Python error to pass on).
    Raise(PyErr),
}

impl From<PyErr> for Failure {
    fn from(error: PyErr) -> Self {
        Failure::Raise(error)
    }
}

impl From<ShortBuffer> for Failure {
    fn from(error: ShortBuffer) -> Self {
        Failure::Short(error)
    }
}

/// `0x` followed by lower-case hex digits (`hex(value)`).
fn pointer_text(value: u64) -> String {
    format!("{value:#x}")
}

fn raw_object<'py>(py: Python<'py>, raw: Raw) -> PyResult<Obj<'py>> {
    Ok(match raw {
        Raw::Int(n) => n.into_pyobject(py)?.into_any(),
        Raw::Uint(n) => n.into_pyobject(py)?.into_any(),
        Raw::Float(f) => PyFloat::new(py, f).into_any(),
        Raw::Bool(b) => PyBool::new(py, b).to_owned().into_any(),
        Raw::Pointer(p) => PyString::new(py, &pointer_text(p)).into_any(),
    })
}

/// `str(value)` of a scalar read, as `decode` keys its `names` lookup (a pointer is keyed by its integer value).
fn name_key(raw: Raw) -> String {
    match raw {
        Raw::Pointer(n) | Raw::Uint(n) => n.to_string(),
        other => shown(other),
    }
}

/// `str(value)` of a scalar read, as `layout_values` shows it (a pointer is its `0x` text).
fn shown(raw: Raw) -> String {
    match raw {
        Raw::Int(n) => n.to_string(),
        Raw::Uint(n) => n.to_string(),
        Raw::Float(f) => core::float_repr(f),
        Raw::Bool(true) => "True".to_owned(),
        Raw::Bool(false) => "False".to_owned(),
        Raw::Pointer(p) => pointer_text(p),
    }
}

fn decode_spec<'py>(py: Python<'py>, spec: &Spec<'py>, data: &[u8]) -> Result<Obj<'py>, Failure> {
    Ok(match &spec.decoder {
        Decoder::Utf8 => PyString::new(py, &core::utf8_text(data)).into_any(),
        Decoder::Utf16 => PyString::new(py, &core::utf16_text(data)).into_any(),
        Decoder::Hex => PyString::new(py, &core::hex_spaced(data)).into_any(),
        Decoder::Struct(fields) => {
            let row = PyDict::new(py);
            for field in fields {
                let offset = usize::try_from(field.offset).map_err(|_| unmodelled())?;
                if offset + field.scalar.size() <= data.len() {
                    row.set_item(&field.name, raw_object(py, core::unpack(field.scalar, data, offset)?)?)?;
                }
            }
            row.into_any()
        }
        Decoder::Scalar(kind) => {
            let raw = core::unpack(*kind, data, 0)?;
            let value = raw_object(py, raw)?;
            let names = spec.dict.get_item(intern!(py, "names"))?.ok_or_else(unmodelled)?;
            let names = exact_dict(&names)?;
            if names.is_empty() {
                return Ok(value);
            }
            let row = PyDict::new(py);
            row.set_item(intern!(py, "value"), value)?;
            row.set_item(intern!(py, "name"), names.get_item(name_key(raw))?)?;
            row.into_any()
        }
    })
}

fn lift(failure: Failure) -> PyErr {
    match failure {
        Failure::Short(_) => unmodelled(),
        Failure::Raise(error) => error,
    }
}

/// `runtime_decode.decode`.
#[pyfunction]
pub fn decode_value<'py>(py: Python<'py>, spec: &Obj<'py>, data: &Obj<'py>) -> PyResult<Obj<'py>> {
    decode_spec(py, &Spec::read(spec)?, bytes_of(data)?).map_err(lift)
}

/// One capture of an event: its row in the decoded list.
fn event_row<'py>(py: Python<'py>, spec: &Obj<'py>, captured: &Obj<'py>) -> PyResult<Bound<'py, PyDict>> {
    let spec = Spec::read(spec)?;
    let row = PyDict::new(py);
    match spec.dict.get_item(intern!(py, "reg"))? {
        Some(reg) if reg.is_truthy()? => row.set_item(intern!(py, "reg"), reg)?,
        _ => row.set_item(intern!(py, "arg"), spec.dict.get_item(intern!(py, "arg"))?.ok_or_else(unmodelled)?)?,
    }
    let label = spec.dict.get_item(intern!(py, "label"))?.ok_or_else(unmodelled)?;
    if !text(&exact_str(&label)?)?.is_empty() {
        row.set_item(intern!(py, "label"), label)?;
    }
    let captured = match plain(captured) {
        Ok(Plain::Dict(dict)) => dict,
        Ok(other) if !other.truthy()? => {
            row.set_item(intern!(py, "error"), intern!(py, "not captured"))?;
            return Ok(row);
        }
        _ => return Err(unmodelled()),
    };
    if let Some(error) = captured.get_item(intern!(py, "error"))?.filter(|e| e.is_truthy().unwrap_or(true)) {
        row.set_item(intern!(py, "error"), error)?;
        return Ok(row);
    }
    row.set_item(intern!(py, "pointer"), captured.get_item(intern!(py, "pointer"))?)?;
    let hex = match captured.get_item(intern!(py, "hex"))? {
        None => Vec::new(),
        Some(text_value) => core::from_hex(text(&exact_str(&text_value)?)?).ok_or_else(unmodelled)?,
    };
    match decode_spec(py, &spec, &hex) {
        Ok(value) => row.set_item(intern!(py, "value"), value)?,
        Err(Failure::Short(short)) => row.set_item(intern!(py, "error"), format!("decode: {short}"))?,
        Err(Failure::Raise(error)) => return Err(error),
    }
    Ok(row)
}

/// `runtime_decode.decode_event`.
#[pyfunction]
pub fn decode_event<'py>(py: Python<'py>, specs: &Obj<'py>, captures: &Obj<'py>) -> PyResult<Obj<'py>> {
    let specs = exact_list(specs)?;
    let captures = match plain(captures)? {
        Plain::List(list) => Some(list),
        other if !other.truthy()? => None,
        _ => return Err(unmodelled()),
    };
    let out = PyList::empty(py);
    if let Some(captures) = captures {
        for (spec, captured) in specs.iter().zip(captures.iter()) {
            out.append(event_row(py, &spec, &captured)?)?;
        }
    }
    Ok(out.into_any())
}

/// `runtime_decode.layout_values`.
#[pyfunction]
pub fn decode_layout_values<'py>(py: Python<'py>, fields: &Obj<'py>, data: &Obj<'py>) -> PyResult<Obj<'py>> {
    let data = bytes_of(data)?;
    let out = PyList::empty(py);
    for field in exact_list(fields)?.iter() {
        let field = exact_dict(&field)?;
        let type_value = field.get_item(intern!(py, "type"))?;
        let type_text = match &type_value {
            None => None,
            Some(value) => Some(exact_str(value)?),
        };
        let kind = core::scalar(match &type_text {
            None => "",
            Some(value) => text(value)?,
        });
        let offset = int_of(&field.get_item(intern!(py, "offset"))?.ok_or_else(unmodelled)?)?;
        let declared = match field.get_item(intern!(py, "size"))? {
            None => 0,
            Some(value) => match plain(&value)? {
                other if !other.truthy()? => 0,
                _ => int_of(&value)?,
            },
        };
        let size = if declared != 0 { declared } else { kind.map_or(0, |k| k.size() as i64) };
        if offset < 0 || size < 0 {
            return Err(unmodelled());
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX)).min(data.len());
        let chunk = &data[start..end];
        let row = PyDict::new(py);
        row.set_item(intern!(py, "name"), field.get_item(intern!(py, "name"))?)?;
        row.set_item(intern!(py, "offset"), PyString::new(py, &format!("{offset:#x}")))?;
        row.set_item(intern!(py, "type"), type_value)?;
        if let Some(enum_name) = field.get_item(intern!(py, "enum"))?.filter(|e| e.is_truthy().unwrap_or(true)) {
            row.set_item(intern!(py, "type"), enum_name)?;
        }
        match kind.filter(|k| chunk.len() >= k.size()) {
            Some(kind) => {
                let raw = core::unpack(kind, chunk, 0).map_err(|_| unmodelled())?;
                let value = raw_object(py, raw)?;
                row.set_item(intern!(py, "value"), &value)?;
                if let Some(names) = field.get_item(intern!(py, "names"))? {
                    if let Ok(names) = names.cast_exact::<PyDict>() {
                        let shown = shown(raw);
                        let named = match names.get_item(&shown)? {
                            Some(named) => named,
                            None => PyString::new(py, &format!("(no member {shown})")).into_any(),
                        };
                        row.set_item(intern!(py, "name"), named)?;
                    } else if names.is_instance_of::<PyDict>() {
                        return Err(unmodelled());
                    }
                }
            }
            None => row.set_item(intern!(py, "bytes"), core::hex_spaced(chunk))?,
        }
        out.append(row)?;
    }
    Ok(out.into_any())
}
