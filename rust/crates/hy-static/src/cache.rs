//! A process-local, byte-budgeted cache of what the plane parsed per program.
//!
//! Rebuilding the function index on every call made `function` and `functions` slower than the warm engine. The
//! cache keeps, per program, the [`Meta`] (identity, memory blocks, file-bytes ids) and, once a function question
//! was asked, the [`FunctionData`] rows. Both are plain memory: **no file handle is kept**, so Windows can rename,
//! replace or delete the project at any time (the next call finds the files different and starts over).
//!
//! * Key: the canonical project path and the program path.
//! * Validation before every use is `stat` only ([`Meta::unchanged`]): size and write time of the database, the index,
//!   its journal (must stay absent), the properties file, and the write time of the folder holding the database
//!   versions and of `idata`, which change when a version, a journal or a save file appears. Any difference drops the
//!   entry; the files are then read again, and a project with a save in progress is declined like a first read.
//! * Budget: entries are charged by an estimate of the bytes they hold; the least recently used go first. Function
//!   rows that alone exceed the whole budget are not kept and the plane declines function questions for that program
//!   version (the engine answers) rather than rebuild them on every call; so does a budget of 0. The default is 64
//!   MiB; `HYDRALYSIS_STATIC_CACHE_MB` sets it for the global cache (0 turns function questions over to the engine).

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{Error, Result};
use crate::index::FunctionData;
use crate::program::{Meta, StaticProgram};

/// The default budget of the global cache.
pub const DEFAULT_BUDGET: usize = 64 << 20;

/// What the cache did, for tests and reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Programs held.
    pub entries: usize,
    /// Estimated bytes held.
    pub bytes: usize,
    /// The budget.
    pub budget: usize,
    /// Uses answered from a held entry.
    pub hits: u64,
    /// Uses that read the files.
    pub misses: u64,
    /// Entries dropped for the budget.
    pub evictions: u64,
    /// Entries dropped because a watched file changed.
    pub invalidations: u64,
    /// Times the function rows of a program were built.
    pub builds: u64,
}

struct Slot {
    key: String,
    meta: Arc<Meta>,
    functions: Option<Arc<FunctionData>>,
    /// The function rows were built and do not fit the budget on their own: the plane declines function questions
    /// for this program version instead of building them again on every call.
    too_big: bool,
    used: u64,
}

impl Slot {
    fn size(&self) -> usize {
        self.meta.size() + self.functions.as_ref().map_or(0, |f| f.size())
    }
}

#[derive(Default)]
struct Inner {
    slots: Vec<Slot>,
    budget: usize,
    tick: u64,
    stats: Stats,
}

impl Inner {
    fn bytes(&self) -> usize {
        self.slots.iter().map(Slot::size).sum()
    }

    /// Drop the least recently used entries until the held bytes fit; an entry that alone does not fit goes too.
    fn fit(&mut self) {
        while !self.slots.is_empty() && self.bytes() > self.budget {
            let oldest = (0..self.slots.len()).min_by_key(|&i| self.slots[i].used).unwrap_or(0);
            self.slots.remove(oldest);
            self.stats.evictions += 1;
        }
    }
}

/// The cache. [`global`] is the one the Python binding uses; tests make their own.
pub struct Cache {
    inner: Mutex<Inner>,
}

/// What a lookup found.
struct Held {
    meta: Arc<Meta>,
    functions: Option<Arc<FunctionData>>,
    too_big: bool,
}

impl Cache {
    /// A cache holding at most `budget` estimated bytes.
    pub fn new(budget: usize) -> Self {
        Self { inner: Mutex::new(Inner { budget, ..Inner::default() }) }
    }

    /// Change the budget; entries over it are dropped now.
    pub fn set_budget(&self, budget: usize) {
        let mut inner = self.lock();
        inner.budget = budget;
        inner.fit();
    }

    /// Drop everything.
    pub fn clear(&self) {
        self.lock().slots.clear();
    }

    /// Counters and sizes.
    pub fn stats(&self) -> Stats {
        let inner = self.lock();
        Stats { entries: inner.slots.len(), bytes: inner.bytes(), budget: inner.budget, ..inner.stats }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain data; keep using it.
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn key(project: &Path, program: &str) -> Result<String> {
        let canonical = std::fs::canonicalize(project).map_err(|e| Error::unsupported(format!("project path: {e}")))?;
        let program = program.strip_prefix('/').unwrap_or(program);
        Ok(format!("{}\u{0}{}", canonical.display(), program))
    }

    /// The held entry for `key` when its files still look as they did, else nothing (and the entry is dropped).
    fn lookup(&self, key: &str) -> Option<Held> {
        let held = {
            let mut inner = self.lock();
            inner.tick += 1;
            let tick = inner.tick;
            let slot = inner.slots.iter_mut().find(|s| s.key == key)?;
            slot.used = tick;
            Held { meta: Arc::clone(&slot.meta), functions: slot.functions.clone(), too_big: slot.too_big }
        };
        // `stat` outside the lock.
        let fresh = held.meta.unchanged();
        let mut inner = self.lock();
        if fresh {
            inner.stats.hits += 1;
            Some(held)
        } else {
            if let Some(at) = inner.slots.iter().position(|s| s.key == key && Arc::ptr_eq(&s.meta, &held.meta)) {
                inner.slots.remove(at);
                inner.stats.invalidations += 1;
            }
            None
        }
    }

    fn store_meta(&self, key: String, meta: Arc<Meta>) {
        let mut inner = self.lock();
        inner.stats.misses += 1;
        inner.tick += 1;
        let used = inner.tick;
        inner.slots.retain(|s| s.key != key);
        inner.slots.push(Slot { key, meta, functions: None, too_big: false, used });
        inner.fit();
    }

    /// Keep `functions` for the entry, or, when meta and rows together exceed the whole budget, remember that they do
    /// not fit. Returns whether they were kept.
    fn store_functions(&self, key: &str, meta: &Arc<Meta>, functions: Arc<FunctionData>) -> bool {
        let mut inner = self.lock();
        inner.stats.builds += 1;
        inner.tick += 1;
        let used = inner.tick;
        let fits = meta.size() + functions.size() <= inner.budget;
        if let Some(slot) = inner.slots.iter_mut().find(|s| s.key == key && Arc::ptr_eq(&s.meta, meta)) {
            slot.used = used;
            if fits {
                slot.functions = Some(functions);
            } else {
                slot.too_big = true;
            }
            inner.fit();
        }
        fits
    }

    /// The program's [`Meta`], from the cache when its files are unchanged, else by reading them.
    fn meta(&self, project: &Path, program: &str) -> Result<(String, Held, Option<StaticProgram>)> {
        let key = Self::key(project, program)?;
        if let Some(held) = self.lookup(&key) {
            return Ok((key, held, None));
        }
        let opened = StaticProgram::open(project, program)?;
        let meta = Arc::clone(opened.meta());
        self.store_meta(key.clone(), Arc::clone(&meta));
        Ok((key, Held { meta, functions: None, too_big: false }, Some(opened)))
    }

    /// Open `program` of `project` for questions that read the file (references, bytes, symbols): the lazy reader
    /// over the cached [`Meta`], so no table that only describes the program is read again.
    ///
    /// # Errors
    ///
    /// As [`StaticProgram::open`].
    pub fn open(&self, project: &Path, program: &str) -> Result<StaticProgram> {
        let (_, held, opened) = self.meta(project, program)?;
        match opened {
            Some(opened) => Ok(opened),
            None => StaticProgram::open_with(held.meta),
        }
    }

    /// The function rows of `program`, from the cache or built (and kept when they fit the budget).
    ///
    /// # Errors
    ///
    /// As [`StaticProgram::open`]; `Unsupported` when rows must be built and the database file is over `build_max`
    /// bytes; `Failed` when the files changed while the rows were built.
    pub fn functions(&self, project: &Path, program: &str, build_max: u64) -> Result<(Arc<Meta>, Arc<FunctionData>)> {
        let (key, held, opened) = self.meta(project, program)?;
        let meta = held.meta;
        if let Some(functions) = held.functions {
            return Ok((meta, functions));
        }
        if held.too_big || self.lock().budget == 0 {
            return Err(Error::unsupported("function rows do not fit the cache budget; the engine answers"));
        }
        if meta.located().stamp.len > build_max {
            return Err(Error::unsupported("program database too large to index here; the engine is faster"));
        }
        let opened = match opened {
            Some(opened) => opened,
            None => StaticProgram::open_with(Arc::clone(&meta))?,
        };
        let functions = Arc::new(FunctionData::build(&opened)?);
        drop(opened);
        if !meta.unchanged() {
            return Err(Error::failed("the project files changed while the function rows were built"));
        }
        if !self.store_functions(&key, &meta, Arc::clone(&functions)) {
            return Err(Error::unsupported("function rows do not fit the cache budget; the engine answers"));
        }
        Ok((meta, functions))
    }
}

/// The process-wide cache, sized by `HYDRALYSIS_STATIC_CACHE_MB` (default 64).
pub fn global() -> &'static Cache {
    static GLOBAL: OnceLock<Cache> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        let mb = std::env::var("HYDRALYSIS_STATIC_CACHE_MB").ok().and_then(|v| v.trim().parse::<usize>().ok());
        Cache::new(mb.map_or(DEFAULT_BUDGET, |mb| mb << 20))
    })
}
