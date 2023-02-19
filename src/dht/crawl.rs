use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet, HashMap, Bound, VecDeque, BTreeSet};
use crate::dht::{Prefix, Id, Contact, TransactionId, PendingQuery, Lookup, LOOKUP_CONCURRENCY, Dht, BUCKET_SIZE, QueryType};
use std::net::{IpAddr, Ipv4Addr};
use std::error::Error;
use std::mem;
use std::time::SystemTime;
use crate::dht::message::Response;
use log::{info, warn};
use crate::dht::oracle::{IdMismatchOracle, UnreachableOracle};


const CANDIDATES_SIZE: usize = BUCKET_SIZE * 4;

#[derive(Debug)]
enum SourceSet {
    Addr(IpAddr),
    Set(BTreeSet<IpAddr>),
}

impl SourceSet {
    fn len(&self) -> usize {
        match self {
            Self::Addr(_) => 1,
            Self::Set(set) => set.len()
        }
    }

    fn iter(&self) -> impl Iterator<Item=&'_ IpAddr> {
        match self {
            Self::Addr(addr) => Some(addr).into_iter().chain(None.into_iter().flatten()),
            Self::Set(set) => None.into_iter().chain(Some(set.iter()).into_iter().flatten())
        }
    }

    fn into_iter(self) -> impl Iterator<Item=IpAddr> {
        match self {
            Self::Addr(addr) => Some(addr).into_iter().chain(None.into_iter().flatten()),
            Self::Set(set) => None.into_iter().chain(Some(set.into_iter()).into_iter().flatten())
        }
    }

    fn insert(&mut self, addrs: impl Iterator<Item=IpAddr>) {
        let existing = mem::replace(self, Self::Set(BTreeSet::new()));
        *self = Self::Set(existing.into_iter().chain(addrs).collect());
    }
}

#[derive(Debug)]
struct ContactWithSources {
    contact: Contact,
    last_suggested: SystemTime,
    sources: SourceSet,
}

#[derive(Debug)]
struct Bucket {
    responded: Vec<(Id, IpAddr)>,
    unprocessed_candidates: Vec<ContactWithSources>,
    candidates: VecDeque<ContactWithSources>,
    visited: HashSet<(Id, IpAddr)>,
    candidates_need_sort: bool
}

impl Bucket {
    fn empty() -> Self {
        Bucket {
            responded: Vec::new(),
            unprocessed_candidates: Vec::new(),
            candidates: VecDeque::new(),
            visited: HashSet::new(),
            candidates_need_sort: false
        }
    }

    fn insert(&mut self, contact: Contact, source: IpAddr) {
        // TODO improve ip vs. id dedup
        if self.visited.contains(&(contact.id, contact.address.ip())) {
            return;
        }
        if self.responded.iter().any(|(id, addr)| &contact.address.ip() == addr) {
            return;
        }
        self.candidates_need_sort = true;
        self.unprocessed_candidates.push(ContactWithSources { contact, last_suggested: SystemTime::now(), sources: SourceSet::Addr(source)});
        // if let Some(existing) = self.candidates.iter_mut().find(|c| c.contact == contact) {
        //     existing.sources.insert(source);
        //     existing.last_suggested = SystemTime::now();
        // } else {
        //     self.candidates.push_back();
        // }

        // let ary = &self.candidates[self.candidates.len().saturating_sub(2)..];
        // if ary.len() == 2 && ary[0].id < ary[1].id {
        //     // sort in reverse since we want to pop low values off the end
        //     self.candidates.sort_unstable_by_key(|e| Reverse(e.id));
        // }
    }

    fn process_candidates(&mut self, force: bool) {
        if !force && self.unprocessed_candidates.len() < self.candidates.len() {
            return;
        }
        self.candidates_need_sort = true;

        let cand = mem::take(&mut self.candidates);

        let mut map = HashMap::new();

        for c in cand.into_iter().chain(mem::take(&mut self.unprocessed_candidates).into_iter()) {
            match map.try_insert(c.contact.clone(), c) {
                Ok(_) => {}
                Err(mut occupied) => {
                    occupied.entry.get_mut().sources.insert(occupied.value.sources.into_iter())
                }
            }
        }

        self.candidates = map.into_values().collect();
    }

    fn sort_candidates(&mut self) {
        if !self.candidates_need_sort {
            return;
        }
        self.candidates_need_sort = false;
        // - sort restricted entries to the front (false is smaller)
        // - source count
        // - then smaller IDs to the front since we sweep the keyspace from 0x00... to 0xFF...
        self.candidates.make_contiguous().sort_unstable_by_key(|e| (!e.contact.is_restricted(), Reverse(e.sources.len().next_power_of_two()), e.contact.id));
    }


    fn responded(&mut self, contact: Contact) {
        self.responded.push((contact.id, contact.address.ip()));
    }

    fn split(mut self, left_prefix: &Prefix, right_prefix: &Prefix) -> (Bucket, Bucket) {

        self.process_candidates(true);

        assert!(self.unprocessed_candidates.is_empty(), "preprocessing required");
        let mut left_candidates: Vec<_> = Vec::from(self.candidates);
        let right_candidates: VecDeque<_> = left_candidates.drain_filter(|c| right_prefix.covers(&c.contact.id)).collect();

        let mut left = Bucket {
            responded: self.responded,
            unprocessed_candidates: Vec::new(),
            candidates: VecDeque::from(left_candidates),
            visited: self.visited,
            candidates_need_sort: true
        };

        let right = Bucket {
            responded: left.responded.drain_filter(|(id, _)| right_prefix.covers(id)).collect(),
            unprocessed_candidates: Vec::new(),
            candidates: right_candidates,
            visited: left.visited.drain_filter(|(id, _)| right_prefix.covers(id)).collect(),
            candidates_need_sort: true,
        };

        (left, right)
    }
}

#[derive(Debug)]
pub struct Crawl {
    buckets: BTreeMap<Prefix, Bucket>,
    cursor: Id,
    info_hashes: HashMap<Id, usize>,
    queries: HashMap<TransactionId, (Id, Prefix)>,
    pub(super) id: u64,
    // callback: Option<fn(&mut Self, dht: &mut Dht)>,
    sent: u64,
    recv: u64,
}

impl Crawl {
    pub(crate) fn new() -> Self {

        let mut buckets = BTreeMap::new();
        buckets.insert(Prefix::ALL, Bucket::empty());

        Crawl {
            buckets,
            cursor: Id::MIN,
            info_hashes: HashMap::new(),
            queries: HashMap::new(),
            id: rand::random(),
            // callback: None,
            sent: 0,
            recv: 0,
        }
    }

    pub fn drain_hashes(&mut self) -> impl Iterator<Item=Id> + '_ {
        self.info_hashes.drain().map(|(id, _)| id)
    }

    pub fn print_state(&self) {
        println!("    cursor: {} inflight:{} sent:{} recv:{}, ", self.cursor, self.queries.len(), self.sent, self.recv);
        if self.queries.len() > 0 {
            println!("flight_min: {}", self.queries.values().min_by_key(|v| v.0).unwrap().0);
            println!("flight_max: {}", self.queries.values().max_by_key(|v| v.0).unwrap().0);
        }
        for (prefix, bucket) in &self.buckets {
            println!("{}/{} resp:{} cand:{} cand2:{} vis:{}", prefix.base, prefix.bits, bucket.responded.len(), bucket.candidates.len(), bucket.unprocessed_candidates.len(), bucket.visited.len());
        }
    }

    fn bucket_for_id(&mut self, id: Id) -> (&Prefix, &mut Bucket) {
        let range = self.buckets.range_mut((Bound::Unbounded, Bound::Included(Prefix::from_id(id))));

        range.last().expect("the buckets should always cover the active range of the lookup")
    }

    /// Advance cursor if possible. Returns false if end is reached.
    fn advance_cursor(&mut self) -> bool {
        let new_prefix = match self.buckets.range((Bound::Excluded(Prefix::from_id(self.cursor)), Bound::Unbounded)).next() {
            Some((prefix, _)) => *prefix,
            None => return false
        };

        self.cursor = new_prefix.min_id();

        // remove preceding buckets
        while let Some((prefix, bucket)) = self.buckets.first_key_value() {
            if prefix.min_id() >= new_prefix.min_id() {
                break;
            }

            self.buckets.pop_first().expect("loop condition implied there should be an entry");
        }

        true
    }

    fn populate_from_routing_table(&mut self, dht: &Dht) {
        let (prefix, bucket) = self.bucket_for_id(self.cursor);
        for (rt_prefix, rt_bucket) in dht.routing_table.iter() {
            if !(rt_prefix.covers(&prefix.min_id()) || prefix.covers(&rt_prefix.min_id())) {
                continue;
            }

            for entry in &rt_bucket.entries {
                if prefix.covers(&entry.contact.id) {
                    bucket.insert(entry.contact.clone(), IpAddr::V4(Ipv4Addr::new(0,0,0,0)));
                }
            }
        }
    }

    fn split_bucket(&mut self, id: Id) {
        let mut split_cursor = id;

        loop {
            let (&prefix, bucket) = self.bucket_for_id(split_cursor);
            if bucket.responded.len() <= BUCKET_SIZE {
                return;
            }

            let bucket = self.buckets.remove(&prefix).unwrap();

            let Some((left_prefix, right_prefix)) = prefix.split() else {
                warn!("crawl failed to split prefix {:?}, responded {:?}", prefix, bucket.responded);
                return;
            };

            let (left, right) = bucket.split(&left_prefix, &right_prefix);

            let left_count = left.responded.len();

            assert!(self.buckets.insert(left_prefix, left).is_none());
            assert!(self.buckets.insert(right_prefix, right).is_none());

            // keep splitting in case all entries got allocated to one side
            if left_count > BUCKET_SIZE {
                split_cursor = left_prefix.min_id();
            } else {
                split_cursor = right_prefix.min_id();
            }
        }
    }
}

impl Lookup for Crawl {
    fn tick(&mut self, dht: &mut Dht, soft_timeout_ms: u64) -> Result<bool, Box<dyn Error>> {

        for bucket in self.buckets.values_mut() {
            bucket.process_candidates(false);
        }

        loop {
            let query_count = self.queries.len();
            let adjusted_query_count = dht.active_queries_excluding_stalled(self.queries.keys().copied());

            if adjusted_query_count >= LOOKUP_CONCURRENCY {
                break;
            }
            let cursor = self.cursor;
            let (&prefix, current_bucket) = self.bucket_for_id(cursor);
            assert_eq!(prefix.min_id(), cursor, "crawl cursor should match current bucket prefix lower bound");

            if current_bucket.candidates.is_empty() && !self.queries.values().any(|(id, _)| prefix.covers(id)) {
                if self.advance_cursor() {
                    // TODO: this doesn't seem to be enough
                    self.populate_from_routing_table(dht);
                    continue;
                } else if self.queries.is_empty() {
                    return Ok(true)
                }
            }

            // try current or next buckets. the current bucket may have exhausted its candidates but we haven't advanced the cursor yet due to in-flight requests
            'candidate_search: for (bucket_prefix, bucket) in self.buckets.range_mut((Bound::Included(prefix), Bound::Unbounded)) {
                bucket.sort_candidates();
                while let Some(candidate) = bucket.candidates.pop_front() {
                    // skip current bucket if the best candidate is similar to an in-flight request
                    // this is necessary because it won't be in the responded-set yet
                    if self.queries.keys().any(|tid| {
                        let q = dht.get_query(tid);
                        q.address.ip() == candidate.contact.address.ip() || q.expected_id.expect("all crawl queries should have an expected id") == candidate.contact.id

                    }) {
                        bucket.candidates.push_front(candidate);
                        continue 'candidate_search;
                    }

                    if bucket.visited.contains(&(candidate.contact.id, candidate.contact.address.ip())) {
                        continue;
                    }
                    if let Some((seen_id, _)) = dht.id_mismatch_oracle.check(candidate.contact.address) {
                        if candidate.contact.id != seen_id {
                            continue;
                        }
                    }

                    if dht.unreachable_oracle.should_skip(QueryType::SampleInfohashes,candidate.contact.address) {
                        // consider it visited so we don't try again
                        bucket.visited.insert((candidate.contact.id, candidate.contact.address.ip()));
                        continue;
                    }

                    if candidate.contact.id == dht.id {
                        continue;
                    }
                    if bucket.responded.iter().any(|r| r.1 == candidate.contact.address.ip() || r.0 == candidate.contact.id) {
                        continue;
                    }

                    bucket.visited.insert((candidate.contact.id, candidate.contact.address.ip()));

                    let split = bucket_prefix.split();
                    let lower = match split {
                        Some((ref left, _)) => left,
                        None => bucket_prefix
                    };

                    // balance between exhaustive sweeping and need to fill buckets evenly
                    // this is load-bearing
                    let target = if lower.covers(&candidate.contact.id) {
                        bucket_prefix.min_id()
                    } else {
                        bucket_prefix.random_id()
                    };


                    let mut query = Dht::send_sample_infohashes(dht.id, target, candidate.contact.address, Some(candidate.contact.id), &dht.socket, candidate.sources.iter())?;
                    query.lookup_id = Some(self.id);
                    assert!(self.queries.insert(query.transaction_id, (target, bucket_prefix.clone())).is_none());
                    dht.register_query(query);
                    self.sent += 1;
                    break 'candidate_search;
                }
            }

            let new_query_count = self.queries.len();
            if new_query_count == query_count {
                if self.queries.is_empty() {
                    warn!("no candidates found for crawl\n {:?}", self);
                }
                break;
            }
        }

        // if self.queries.len() > 0 {
        //     let inflight_max = self.queries.values().max_by_key(|q| q.0).unwrap();
        //
        //     for (bucket_prefix, bucket) in self.buckets.iter_mut() {
        //         if bucket_prefix.min_id() <= inflight_max.0 {
        //             continue;
        //         }
        //         if self.queries.values().any(|(query_id, query_prefix)| {
        //             query_prefix.covers(&bucket_prefix.min_id()) || bucket_prefix.covers(&query_prefix.min_id())
        //         }) {
        //             continue
        //         }
        //
        //         bucket.trim_candidates(&dht.id_mismatch_oracle, &dht.unreachable_oracle);
        //     }
        // }

        Ok(false)
    }

    fn responded(&mut self, query: &PendingQuery, contact: Contact, response: &Response) {
        self.recv += 1;
        let (prefix, bucket) = self.bucket_for_id(contact.id);
        bucket.responded(contact);
        let split_id = prefix.min_id();

        if bucket.responded.len() > BUCKET_SIZE {
            self.split_bucket(split_id);
        }

        let mut dedup = HashSet::new();

        for sample in response.samples() {
            if !dedup.insert(sample) {
                continue;
            }
            self.info_hashes.entry(sample).and_modify(|e| *e += 1).or_insert(1);
            // TODO: either batch or remove self.info_hashes
        }
        
    }

    fn remove_query(&mut self, query: &PendingQuery) {
        assert!(self.queries.remove(&query.transaction_id).is_some());
    }

    fn add_contacts(&mut self, contacts: &mut dyn Iterator<Item=Contact>, source: Option<&Contact>, from_query: Option<&PendingQuery>) {
        let contacts: Vec<_> = contacts.collect();

        if contacts.iter().any(|c| {
            c.is_bogon()
        }) {
            info!("crawl: contact set from {:?} contained bogon {}", source, contacts.iter().filter(|c| c.is_bogon()).map(|c| format!("{:?}", c.address)).intersperse(", ".to_owned()).collect::<String>());
            return;
        }

        for contact in contacts {
            if contact.id < self.cursor {
                continue;
            }

            let (_, bucket) = self.bucket_for_id(contact.id);


            let source_ip = source.map(|s| s.address.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::new(0,0,0,0)));
            bucket.insert(contact, source_ip);
        }
    }

    fn and_then(&mut self, callback: Box<dyn FnOnce(&mut Self, &mut Dht)>) where Self: Sized {
        todo!()
    }
}