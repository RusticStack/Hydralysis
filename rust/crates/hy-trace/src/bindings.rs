//! Linking script-VM events to the native function events they invoked, ported from
//! `hydralysis.trace_bindings.link_events` (spec 15.8).
//!
//! A VM event carries the name of the script function it called. The invoked native is the first `core.function.enter` on
//! the same thread generation, after it in the thread's own order and within a window of events, whose `rva` is the bound
//! thunk or implementation. A call whose native was not seen is listed as unlinked, never dropped.
//!
//! The binding reads the Python events into compact [`LinkEvent`]s (a few integers each; no text, no copies of the
//! events) and turns the [`Link`]s this module returns back into Python lists, fetching `event_id` and the script
//! function name from the original events by index.

use std::collections::HashMap;

/// [`LinkEvent::script`] of an event that calls no script function.
pub const NO_SCRIPT: u32 = u32::MAX;
/// [`LinkEvent::script`] of a script call whose name is not in the binding table.
pub const UNBOUND: u32 = u32::MAX - 1;

/// The resolved rows of a binding table: for each script name the RVAs a native entry may carry.
#[derive(Debug, Default, Clone)]
pub struct BindingTable {
    slots: HashMap<String, u32>,
    wanted: Vec<Vec<i64>>,
}

impl BindingTable {
    /// Add a resolved row; rows with the same name share one set of RVAs.
    pub fn insert(&mut self, script_name: &str, native_rva: i64, implementation_rva: i64) {
        let next = u32::try_from(self.wanted.len()).expect("fewer than 2^32 binding names");
        let slot = *self.slots.entry(script_name.to_owned()).or_insert(next);
        if slot == next {
            self.wanted.push(Vec::new());
        }
        let set = &mut self.wanted[slot as usize];
        for rva in [native_rva, implementation_rva] {
            if !set.contains(&rva) {
                set.push(rva);
            }
        }
    }

    /// The slot of a script name, or `None` when no resolved row carries it.
    #[must_use]
    pub fn slot(&self, script_name: &str) -> Option<u32> {
        self.slots.get(script_name).copied()
    }
}

/// The fields of one trace event that `link_events` reads. Only events with a `seq` are part of any thread order.
#[derive(Debug, Clone, Copy)]
pub struct LinkEvent {
    /// `event["seq"]`.
    pub seq: i64,
    /// The RVA of a `core.function.enter` event whose `rva` is an integer; `None` for every other event.
    pub entry_rva: Option<i64>,
    /// Position of the event in the caller's list.
    pub index: u32,
    /// Identity of the event's thread generation: two events share a thread iff their ids are equal.
    pub thread: u32,
    /// Rank of `str(thread_gen)` among all the thread generations (equal text, equal rank).
    pub rank: u32,
    /// A [`BindingTable`] slot, [`UNBOUND`] or [`NO_SCRIPT`].
    pub script: u32,
}

/// What became of one script call; `from` and `to` are [`LinkEvent::index`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// The call and the native entry it invoked.
    Linked { from: u32, to: u32 },
    /// The script function is not in the binding table.
    NotBound { from: u32 },
    /// No matching native entry within the window on the same thread.
    NotSeen { from: u32 },
}

/// `link_events(events, table, window=window)`: the outcome of every script call, in thread order.
///
/// Events are ordered by `(str(thread_gen), seq)` (stable, as Python's sort is) and each script call looks at the next
/// `window` events of that order for its native entry.
#[must_use]
pub fn link_events(mut events: Vec<LinkEvent>, table: &BindingTable, window: usize) -> Vec<Link> {
    if !events.is_sorted_by_key(|e| (e.rank, e.seq)) {
        events.sort_by_key(|e| (e.rank, e.seq));
    }
    let mut links = Vec::new();
    for (position, event) in events.iter().enumerate() {
        let wanted = match event.script {
            NO_SCRIPT => continue,
            UNBOUND => {
                links.push(Link::NotBound { from: event.index });
                continue;
            }
            slot => &table.wanted[slot as usize],
        };
        let end = position.saturating_add(1).saturating_add(window).min(events.len());
        let found =
            events[position + 1..end].iter().find(|f| f.thread == event.thread && f.entry_rva.is_some_and(|rva| wanted.contains(&rva)));
        links.push(match found {
            Some(found) => Link::Linked { from: event.index, to: found.index },
            None => Link::NotSeen { from: event.index },
        });
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(index: u32, seq: i64, thread: u32, script: u32, entry_rva: Option<i64>) -> LinkEvent {
        LinkEvent { seq, entry_rva, index, thread, rank: thread, script }
    }

    fn table() -> BindingTable {
        let mut table = BindingTable::default();
        table.insert("get_health", 0x1300, 0x1400);
        table
    }

    #[test]
    fn a_traced_script_call_links_to_its_native_event() {
        let table = table();
        let events = vec![
            event(0, 1, 1, table.slot("get_health").unwrap(), None),
            event(1, 2, 2, NO_SCRIPT, Some(0x1300)),
            event(2, 3, 1, NO_SCRIPT, Some(0x1400)),
            event(3, 5, 1, UNBOUND, None),
        ];
        assert_eq!(link_events(events, &table, 8), [Link::Linked { from: 0, to: 2 }, Link::NotBound { from: 3 }],);
    }

    #[test]
    fn the_window_bounds_the_search() {
        let mut table = BindingTable::default();
        table.insert("f", 1, 1);
        let slot = table.slot("f").unwrap();
        let events = vec![event(0, 1, 1, slot, None), event(1, 2, 1, NO_SCRIPT, Some(9)), event(2, 3, 1, NO_SCRIPT, Some(1))];
        assert_eq!(link_events(events.clone(), &table, 1), [Link::NotSeen { from: 0 }]);
        assert_eq!(link_events(events, &table, 2), [Link::Linked { from: 0, to: 2 }]);
    }

    #[test]
    fn events_are_ordered_by_thread_rank_then_seq_and_ties_keep_input_order() {
        let table = table();
        let slot = table.slot("get_health").unwrap();
        // Input order: thread 2's entry first, then the call and the entry on thread 1 out of seq order.
        let mut events = vec![event(0, 9, 2, NO_SCRIPT, Some(0x1300)), event(1, 7, 1, NO_SCRIPT, Some(0x1400)), event(2, 4, 1, slot, None)];
        events[0].rank = 1;
        events[1].rank = 0;
        events[2].rank = 0;
        assert_eq!(link_events(events, &table, 8), [Link::Linked { from: 2, to: 1 }]);
    }

    #[test]
    fn rows_with_one_name_share_their_rvas() {
        let mut table = BindingTable::default();
        table.insert("f", 1, 2);
        table.insert("f", 3, 3);
        let slot = table.slot("f").unwrap();
        for rva in [1, 2, 3] {
            let events = vec![event(0, 1, 1, slot, None), event(1, 2, 1, NO_SCRIPT, Some(rva))];
            assert_eq!(link_events(events, &table, 8), [Link::Linked { from: 0, to: 1 }], "rva {rva}");
        }
        assert_eq!(table.slot("g"), None);
    }
}
