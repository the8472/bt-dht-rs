use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::net::{UdpSocket, SocketAddr};
use std::time::{Duration, SystemTime};
use log::*;

use crate::dht::{BUCKET_SIZE, Contact, Dht, Id, LOOKUP_CONCURRENCY, LookupType, PendingQuery, TransactionId, Lookup};
use rand::random;
use crate::dht::oracle::IdMismatchOracle;
use crate::dht::message::Response;

pub struct TargetedLookup {
    pub id: u64,
    lookup_type: LookupType,
    target: Id,
    candidates: BTreeMap<Id, Contact>,
    pub queries: HashSet<TransactionId>,
    visited: HashSet<SocketAddr>,
    closest_set: Vec<Id>,
    pub(super) responded: Vec<Contact>,
    created: SystemTime,
    and_then: Option<Box<dyn FnOnce(&mut Self, &mut Dht)>>,
}

impl TargetedLookup {
    pub fn targeted_find_node(now: SystemTime, target_id: Id) -> Self {
        TargetedLookup {
            id: random(),
            lookup_type: LookupType::FindNode,
            target: target_id,
            created: now,
            queries: HashSet::new(),
            candidates: BTreeMap::new(),
            visited: HashSet::new(),
            closest_set: Vec::new(),
            responded: Vec::new(),
            and_then: None,
        }
    }
}

impl Lookup for TargetedLookup {

    fn tick(&mut self, dht: &mut Dht, soft_timeout_ms: u64) -> Result<bool, Box<dyn Error>> {

        self.closest_set.sort();
        self.closest_set.dedup();
        self.closest_set.truncate(BUCKET_SIZE);

        let query_count_excluding_soft_timeout = dht.active_queries_excluding_stalled(self.queries.iter().copied());

        let mut to_send = LOOKUP_CONCURRENCY.saturating_sub(query_count_excluding_soft_timeout);

        while to_send > 0 {
            // TODO also account for in-flight requests when calculating the potential closest set
            //  i.e. determine whether a candidate would actually improve things compared to closest set + those in flight
            match (self.closest_set.iter().rev().next(), self.candidates.keys().next()) {
                (Some(least_closest), Some(candidate)) if self.closest_set.len() >= BUCKET_SIZE && least_closest < candidate => {
                    break;
                }
                _ => {}
            }

            if let Some((distance, contact)) = self.candidates.pop_first() {
                trace!("t:{} d:{}", self.target, distance);

                if let Some((confirmed_id, _)) = dht.id_mismatch_oracle.check(contact.address) {
                    if confirmed_id != contact.id {
                        continue;
                    }
                }

                // no point in querying ourselves, we always can manipulate our local state directly
                if contact.id == dht.id {
                    continue;
                }

                self.visited.insert(contact.address);

                let mut query = Dht::send_find_node(dht.id, self.target, contact.address, Some(contact.id), &dht.socket)?;
                to_send -= 1;
                query.lookup_id = Some(self.id);
                assert!(self.queries.insert(query.transaction_id));
                dht.register_query(query);
            } else {
                break
            }
        }

        if self.queries.is_empty() {
            let now = SystemTime::now();
            debug!("lookup for {} done after {:?}", self.target, now.duration_since(self.created).unwrap());
            if let Some(mut callback) = self.and_then.take() {
                callback(self, dht);
            }
            return Ok(true)
        }

        Ok(false)
    }

    fn responded(&mut self, query: &PendingQuery, contact: Contact, response: &Response) {
        let distance = self.target.distance(&contact.id);
        self.closest_set.push(distance);
        self.responded.push(contact);
    }

    fn remove_query(&mut self, query: &PendingQuery) {
        assert!(self.queries.remove(&query.transaction_id), "attempted to remove query that was not associated with this lookup");
    }

    fn add_contacts(&mut self, contacts: &mut dyn Iterator<Item=Contact>, source: Option<&Contact>, _query: Option<&PendingQuery>) {
        for contact in contacts {
            if contact.is_bogon() || self.visited.contains(&contact.address) {
                continue;
            }

            let distance = self.target.distance(&contact.id);
            self.candidates.insert(distance, contact);
        }
    }

    fn and_then(&mut self, callback: Box<dyn FnOnce(&mut Self, &mut Dht)>) where Self: Sized {
        assert!(self.and_then.replace(callback).is_none())
    }
}
