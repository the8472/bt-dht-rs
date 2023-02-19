use std::collections::{HashMap, hash_map};
use std::net::SocketAddr;
use super::Id;
use std::time::{SystemTime, Duration};
use crate::dht::{PendingQuery, QueryType};
use rand::{thread_rng, Rng};

struct MismatchOracleEntry {
    confirmed_id: Id,
    last_seen: SystemTime,
    confirmed_id_changes: i32,
}

pub(super) struct IdMismatchOracle {
    by_socket_address: HashMap<SocketAddr, MismatchOracleEntry>,
}

const STALE_THRESHOLD: Duration = Duration::from_secs(3600); // 1h
const DEBOUNCE: Duration = Duration::from_secs(3 * 60); // 3min
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

impl IdMismatchOracle {
    pub(super) fn new() -> IdMismatchOracle {
        IdMismatchOracle { by_socket_address: HashMap::new() }
    }

    pub fn insert(&mut self, address: SocketAddr, observed_id: Id, now: SystemTime) {
        self.by_socket_address.entry(address).and_modify(|existing| {
            if existing.confirmed_id != observed_id {
                existing.confirmed_id_changes += 1;
            } else if now.duration_since(existing.last_seen).unwrap() > DEBOUNCE {
                existing.confirmed_id_changes -= 1;
            }
            existing.last_seen = now;
            existing.confirmed_id = observed_id;
        }).or_insert(MismatchOracleEntry {
            confirmed_id: observed_id,
            last_seen: now,
            confirmed_id_changes: 0,
        });
    }

    pub fn cleanup(&mut self, now: SystemTime) {
        self.by_socket_address.retain(|_, entry| {
            let age = now.duration_since(entry.last_seen).unwrap();
            age < STALE_THRESHOLD && entry.confirmed_id_changes >= -2
        });
    }

    /// Returns a tuple containing the last observed id and a boolean
    /// indicating whether it is known to be unstable, i.e.
    /// whether a confirmed change has been observed before
    pub fn check(&self, address: SocketAddr) -> Option<(Id, bool)> {
        self.by_socket_address.get(&address).map(|entry| {
            (entry.confirmed_id, entry.confirmed_id_changes > 0)
        })
    }
}

struct TimeoutOracleEntry {
    last_update: SystemTime,
    failure_count: i32,
}

pub struct UnreachableOracle {
    by_socket_address: HashMap<(SocketAddr, QueryType), TimeoutOracleEntry>,
    last_cleanup_time: SystemTime
}

impl UnreachableOracle {
    pub fn new() -> UnreachableOracle {
        UnreachableOracle { by_socket_address: HashMap::new(), last_cleanup_time: SystemTime::UNIX_EPOCH }
    }

    pub(super) fn timeout(&mut self, query: &PendingQuery, now: SystemTime) {
        self.by_socket_address.entry((query.address, query.query)).and_modify(|existing| {
            existing.failure_count = existing.failure_count.saturating_add(1);
            existing.last_update = now;
        }).or_insert(TimeoutOracleEntry {
            last_update: now,
            failure_count: 1
        });
    }

    pub(super) fn success(&mut self, query: &PendingQuery, now: SystemTime) {
        self.by_socket_address.entry((query.address, query.query)).and_modify(|existing| {
            if now.duration_since(existing.last_update).unwrap() > DEBOUNCE {
                existing.failure_count = existing.failure_count.saturating_sub(1);
                existing.last_update = now;
            }
        });
    }

    pub fn cleanup(&mut self, now: SystemTime) {
        if self.last_cleanup_time > now - CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup_time = now;
        let stale_time = now - STALE_THRESHOLD;
        self.by_socket_address.retain(|_, entry| {
            entry.failure_count >= -2 && entry.last_update < stale_time
        });
    }

    /// Stochastically returns true if the remote address is known to not respond to this query type
    ///
    /// Probability increases with number of failures.
    pub(super) fn  should_skip(&self, query_type: QueryType, addr: SocketAddr) -> bool {
        if let Some(entry) = self.by_socket_address.get(&(addr, query_type)) {
            if entry.failure_count > 1 {
                let rnd = thread_rng().gen::<f32>();
                return rnd > (-1.0 * (entry.failure_count - 1) as f32).exp2()
            }
        }

        false
    }
}