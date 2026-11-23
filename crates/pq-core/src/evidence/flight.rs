//! In-process single-flight per collection identity.
//!
//! Duplicate concurrent requests for the same collection share one in-flight
//! collection: the first caller (leader) runs the collector; the others block
//! and then read the persisted observation. No cross-process leases in v1
//! (the `collection_state` lease columns are reserved).

use crate::evidence::error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

pub(crate) struct FlightTable {
    slots: Mutex<HashMap<[u8; 32], Arc<Slot>>>,
}

enum FlightResult {
    Persisted(i64),
    Panicked,
}

struct Slot {
    state: Mutex<Option<FlightResult>>,
    cv: Condvar,
    /// Live guards joined to this flight (leader + followers).
    participants: std::sync::atomic::AtomicUsize,
}

/// Guard for a participant of a flight. Leaders must call
/// [`FlightGuard::complete`]; the Drop impl covers panics/early-returns by
/// releasing waiters with an error so nothing blocks forever.
pub(crate) struct FlightGuard {
    table: FlightTableRef,
    key: [u8; 32],
    slot: Arc<Slot>,
    pub(crate) leader: bool,
    done: bool,
}

struct FlightTableRef(Arc<FlightTable>);

impl FlightTable {
    pub(crate) fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Join the flight for `key`. Returns a leader guard when this call
    /// created the flight, a follower guard otherwise. The decision is made
    /// atomically with slot creation under the table lock: a fresh insert is
    /// a leader; an existing slot (a flight genuinely in progress — slots are
    /// removed only at completion) is a flight to follow.
    pub(crate) fn enter(self: &Arc<Self>, key: [u8; 32]) -> FlightGuard {
        let mut slots = self.slots.lock().expect("flight table mutex");
        let mut is_leader = false;
        let slot = match slots.entry(key) {
            std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let s = Arc::new(Slot {
                    state: Mutex::new(None),
                    cv: Condvar::new(),
                    participants: std::sync::atomic::AtomicUsize::new(0),
                });
                e.insert(s.clone());
                is_leader = true;
                s
            }
        };
        slot.participants
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        FlightGuard {
            table: FlightTableRef(self.clone()),
            key,
            slot,
            leader: is_leader,
            done: false,
        }
    }

    /// Introspection (tests + operational observability): how many guards
    /// are joined to the flight for `key` right now.
    pub(crate) fn participants(&self, key: [u8; 32]) -> usize {
        self.slots
            .lock()
            .expect("flight table mutex")
            .get(&key)
            .map(|s| s.participants.load(std::sync::atomic::Ordering::SeqCst))
            .unwrap_or(0)
    }

    fn remove(&self, key: [u8; 32]) {
        self.slots.lock().expect("flight table mutex").remove(&key);
    }
}

impl FlightGuard {
    /// Leader: record the persisted observation id and release all waiters.
    pub(crate) fn complete(mut self, observation_id: i64) {
        {
            let mut state = self.slot.state.lock().expect("flight slot mutex");
            *state = Some(FlightResult::Persisted(observation_id));
        }
        self.slot.cv.notify_all();
        self.done = true;
        self.table.0.remove(self.key);
    }

    /// Follower: block until the leader completes; returns the observation id
    /// the leader persisted.
    pub(crate) fn wait(mut self) -> Result<i64> {
        let mut state = self.slot.state.lock().expect("flight slot mutex");
        loop {
            match state.as_ref() {
                Some(FlightResult::Persisted(id)) => {
                    let id = *id;
                    self.done = true;
                    return Ok(id);
                }
                Some(FlightResult::Panicked) => {
                    self.done = true;
                    return Err(Error::CollectionLeaderPanicked);
                }
                None => {
                    state = self
                        .slot
                        .cv
                        .wait(state)
                        .expect("flight slot mutex poisoned")
                }
            }
        }
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.slot
            .participants
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if self.leader && !self.done {
            // Panic or early return path: release waiters.
            {
                let mut state = self.slot.state.lock().expect("flight slot mutex");
                if state.is_none() {
                    *state = Some(FlightResult::Panicked);
                }
            }
            self.slot.cv.notify_all();
            self.table.0.remove(self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    #[test]
    fn first_participant_is_leader_followers_block() {
        let table = Arc::new(FlightTable::new());
        let g1 = table.enter(key(1));
        assert!(g1.leader);
        let g2 = table.enter(key(1));
        assert!(!g2.leader);
        // Different key: another leader.
        let g3 = table.enter(key(2));
        assert!(g3.leader);
        g1.complete(42);
        assert_eq!(g2.wait().unwrap(), 42);
        drop(g3); // unreferenced flight; Drop cleans the table
    }

    #[test]
    fn leader_panic_releases_waiters_with_error() {
        let table = Arc::new(FlightTable::new());
        let leader = table.enter(key(3));
        assert!(leader.leader);
        let table2 = table.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let follower = table2.enter(key(3));
            entered_tx.send(follower.leader).unwrap();
            follower.wait()
        });
        assert_eq!(entered_rx.recv(), Ok(false)); // follower joined the flight
        drop(leader); // panic simulation: Drop releases waiters
        match handle.join() {
            Ok(Err(Error::CollectionLeaderPanicked)) => {}
            other => panic!("expected CollectionLeaderPanicked, got {other:?}"),
        }
        // Table is clean; a new flight can start.
        let g = table.enter(key(3));
        assert!(g.leader);
        g.complete(7);
    }

    #[test]
    fn completed_flight_is_removed_from_table() {
        let table = Arc::new(FlightTable::new());
        let g = table.enter(key(4));
        g.complete(1);
        let g2 = table.enter(key(4));
        assert!(g2.leader);
        g2.complete(2);
    }
}
