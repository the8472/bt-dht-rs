use std::any::{Any, TypeId};
use std::array::TryFromSliceError;
use std::cmp::{max, min, Reverse};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::{cmp, io};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::ops::Bound::Included;
use std::time::{Duration, Instant, SystemTime};

use hdrhistogram::Histogram;
use log::{debug, error, trace, info, warn};
use serde_bytes::Bytes;
use lazy_static::lazy_static;
use mio::net::UdpSocket;

use lookups::TargetedLookup;
use message::*;
use oracle::IdMismatchOracle;
use std::sync::atomic::{AtomicU32, Ordering};
use std::ops::Deref;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::Iter;
use std::str::FromStr;
use blake2::digest::Mac;
use crc::{Crc, CRC_32_ISCSI};
use crate::dht::oracle::UnreachableOracle;
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use socket2::{Domain, SockAddr, Socket, Type};
use crate::crawl::Crawl;
use crate::dht::token::{check_token, gen_token};

pub mod message;
mod utils;
mod lookups;
pub mod crawl;
mod oracle;
mod token;

const BUCKET_SIZE: usize = 8;
const LOOKUP_CONCURRENCY: usize = 3;
const VERSION: &[u8] = b"cr\0\0";
const BUCKET_ENTRY_REFRESH: Duration = Duration::from_secs(60 * 10);
// linux conntrack default for 60s for a single UDP exchange, 120 for a stream
// TODO: find some paper surveying timeouts in the wild. some routers likely have even
//  higher timeouts
const NAT_TIMEOUT: Duration = Duration::from_secs(150);
const MAX_ANNOUNCE_AGE: Duration = Duration::from_secs(60 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const IP_DEDUP_INTERVAL: Duration = Duration::from_secs(60);
const EXTERNAL_ADDRESS_QUORUM: usize = 32;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum QueryType {
    Ping,
    FindNode,
    SampleInfohashes
}


#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone, Hash)]
pub struct Id(pub [u8; 20]);

impl Id {
    const MIN: Id = Id([0u8 ; 20]);

    pub fn random() -> Self {
        Id(rand::random())
    }

    pub fn distance(&self, other: &Id) -> Self {
        let mut distance = self.0;
        for i in 0..20 {
            distance[i] ^= other.0[i];
        }

        Id(distance)
    }

    pub fn to_restricted_id(&self, addr: IpAddr) -> Id {
        let mut ip = [0u8; 8];

        let num = match addr {
            IpAddr::V4(v4) => {
                (&mut ip[0..4]).copy_from_slice(&v4.octets());
                4
            }
            IpAddr::V6(v6) => {
                ip.copy_from_slice(&v6.octets()[0..8]);
                8
            }
        };

        let mut new_id = *self;

        static V4_MASK: [u8; 4] = [ 0x03, 0x0f, 0x3f, 0xff ];
        static V6_MASK: [u8; 8] = [ 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff ];
        const CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

        let mask = if num == 4 { V4_MASK.as_slice() } else { V6_MASK.as_slice() };

        for i in 0..num {
            ip[i] &= mask[i];
        }

        let r = new_id.0[19] & 0x7;
        ip[0] |= r << 5;

        let crc = CRC32C.checksum(&ip[0..num]);

        // only take the top 21 bits from crc
        new_id.0[0] = (crc >> 24) as u8 & 0xff;
        new_id.0[1] = (crc >> 16) as u8 & 0xff;
        new_id.0[2] = ((crc >> 8) as u8 & 0xf8) | (new_id.0[2] & 0x7);
        new_id
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0))
    }
}

impl TryFrom<&[u8]> for Id {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let inner: [u8; 20] = value.try_into()?;
        Ok(Id(inner))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
struct Contact {
    address: SocketAddr,
    id: Id
}

impl Contact {
    fn from_bytes<'a>(raw: &'a [u8]) -> Result<impl Iterator<Item=Contact> + Clone + 'a, &'static str> {
        if raw.len() % 26 != 0 {
            return Err("nodes length must be a multiple of 26");
        }

        Ok(raw.array_chunks::<26>().map(|raw| {
            let ip: [u8; 4] = raw[20..24].try_into().expect("we sliced correctly");
            let ip = Ipv4Addr::from(ip);
            let port = (raw[24] as u16) << 8 | raw[25] as u16;
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            Contact {id: Id(raw[0..20].try_into().expect("we sliced correctly")), address: addr}
        }))
    }

    fn to_bytes(contacts: Vec<Contact>) -> Vec<u8> {
        // FIXME: this should use an on-stack arrayvec
        let mut raw = Vec::with_capacity(contacts.len() * 26);
        for contact in contacts {
            raw.extend_from_slice(&contact.id.0[..]);
            match contact.address {
                SocketAddr::V4(v4) => raw.extend_from_slice(v4.ip().octets().as_slice()),
                _ => unimplemented!()
            }
            raw.extend_from_slice(contact.address.port().to_be_bytes().as_slice());
        }
        raw
    }

    /// Use incoherent_match if you want misfits
    fn partial_or_full_match(&self, other: &Self) -> bool {
        self.address.ip() == other.address.ip() || self.id == other.id
    }

    fn incoherent_match(&self, other: &Self) -> bool {
        return self.partial_or_full_match(other) && self != other
    }

    fn is_bogon(&self) -> bool {
        if self.address.port() == 0 {
            return true;
        }
        let ip = self.address.ip();
        // TODO make this configurable for testing so loopback works
        match ip {
            IpAddr::V4(ip) => ip.octets()[0] == 0 || ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() || ip.is_reserved() || ip.is_link_local() || ip.is_private(),
            IpAddr::V6(ip) => ip.is_loopback() || ip.is_multicast() || ip.is_unspecified()
        }
    }

    fn is_restricted(&self) -> bool {
        // TODO this could be implemented a bit more efficiently than comparing those 20 bytes
        self.id.to_restricted_id(self.address.ip()) == self.id
    }
}

struct StoredPeer {
    contact: Contact,
    last_seen: SystemTime,
}

impl StoredPeer {
    fn serialize_into(&self, out: &mut Vec<u8>) {
        match self.contact.address {
            SocketAddr::V4(v4) => out.extend_from_slice(v4.ip().octets().as_slice()),
            _ => unimplemented!()
        }
        out.extend_from_slice(self.contact.address.port().to_be_bytes().as_slice());
    }
}


#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone, Debug)]
struct Prefix {
    base: Id,
    bits: u8
}

impl Prefix {
    const ALL: Prefix = Prefix {
        base: Id([0; 20]),
        bits: 0
    };

    const MIN: Prefix = Prefix::ALL;

    fn from_id(id: Id) -> Self {
        Prefix {base: id, bits: 160}
    }

    fn covers(&self, id: &Id) -> bool {
        let bytes = (self.bits/8) as usize;
        let whole_byte_prefix_matches = self.base.0[0..bytes] == id.0[0..bytes];
        let significant_bits = (self.bits % 8) as usize;
        let bits_match = if significant_bits != 0 {
            let mask = (0xff00 >> significant_bits) as u8;
            significant_bits == 0 || self.base.0[bytes] & mask == id.0[bytes] & mask
        } else {
            true
        };

        whole_byte_prefix_matches && bits_match
    }

    fn random_id(&self) -> Id {
        let mut random_id = Id::random();

        let bytes = (self.bits/8) as usize;
        random_id.0[0..bytes].copy_from_slice(&self.base.0[0..bytes]);
        let bits = (self.bits % 8) as usize;
        if bits != 0 {
            let mask = (0xff00 >> bits) as u8;
            random_id.0[bytes] = self.base.0[bytes] & mask | random_id.0[bytes] & !mask;
        }

        random_id
    }

    fn min_id(&self) -> Id {
        self.base
    }

    fn parent(&self) -> Option<Prefix> {
        if self.bits == 0 {
            return None;
        }
        let mut p = self.clone();

        p.bits -= 1;
        let byte = (p.bits / 8) as usize;
        let bit = (p.bits % 8) as usize;
        p.base.0[byte] &= !(0x80 >> bit);

        Some(p)
    }

    fn is_sibling(&self, other: &Prefix) -> bool {
        match self.parent() {
            Some(parent) => self.bits == other.bits && parent.covers(&other.base),
            None => false
        }
    }

    fn split(self) -> Option<(Self, Self)> {
        if self.bits >= 160 {
            return None
        }

        let mut left = self;
        let mut right = self;

        let byte = (self.bits / 8) as usize;
        let bit = (self.bits % 8) as usize;

        left.bits = self.bits + 1;
        right.bits = self.bits + 1;
        left.base.0[byte] &= !(0x80 >> bit);
        right.base.0[byte] |= 0x80 >> bit;

        Some((left, right))
    }

}

struct BucketEntry {
    contact: Contact,
    created: SystemTime,
    last_seen: SystemTime,
    last_response: SystemTime,
    last_queried: SystemTime,
    failures: u8
}

impl BucketEntry {
    fn verified(&self) -> bool {
        self.last_response != SystemTime::UNIX_EPOCH
    }

    fn dead(&self) -> bool {
        self.failures > 4
    }

    fn merge(&mut self, other: BucketEntry) {
        debug_assert!(self.contact == other.contact);
        self.last_response = max(self.last_response, other.last_response);
        self.last_seen = max(self.last_seen, other.last_seen);
        self.last_queried = max(self.last_queried, other.last_queried);
        self.created = min(self.created, other.created);
        self.failures = max(self.failures, other.failures);
    }
}

impl Debug for BucketEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("").field(&self.contact.id).field(&self.contact.address).finish()
    }
}

#[derive(Debug)]
struct Bucket {
    entries: Vec<BucketEntry>,
    replacements: Vec<BucketEntry>,
    last_maintenance: SystemTime,
}

impl Bucket {
    fn empty() -> Self {
        Bucket {
            entries: Vec::with_capacity(BUCKET_SIZE),
            replacements: Vec::with_capacity(BUCKET_SIZE),
            last_maintenance: SystemTime::UNIX_EPOCH
        }
    }

    fn add_unverified_contact(&mut self, contact: Contact) {
        let now = SystemTime::now();
        let entry = BucketEntry {
            created: now,
            last_seen: now,
            contact,
            last_response: SystemTime::UNIX_EPOCH,
            last_queried: SystemTime::UNIX_EPOCH,
            failures: 0
        };

        self.add_entry(entry);
    }

    fn add_verified_contact(&mut self, to_add: Contact, sent_at: SystemTime) {
        let now = SystemTime::now();

        let entry = BucketEntry {
            contact: to_add,
            created: sent_at,
            last_seen: now,
            last_response: now,
            last_queried: sent_at,
            failures: 0
        };
        self.add_entry(entry);
    }

    fn sent(&mut self, sent_at: SystemTime, addr: SocketAddr, id: Id) {
        let contact = Contact {id, address: addr};
        if let Some(existing) = self.entries.iter_mut().find(|e| e.contact == contact) {
            existing.last_queried = max(existing.last_queried, sent_at);
        }
    }

    fn timeout(&mut self, addr: SocketAddr, id: Id) {
        let contact = Contact {id, address: addr};
        if let Some(existing) = self.entries.iter_mut().find(|e| e.contact == contact) {
            existing.failures = existing.failures.saturating_add(1);
        }
        // yeet replacements that timed out, e.g. when we tried to ping one to make it verified
        self.replacements.retain(|r| r.contact != contact );
    }

    fn add_entry(&mut self, entry: BucketEntry) {
        for existing in self.entries.iter_mut() {
            if existing.contact.incoherent_match(&entry.contact) {
                return;
            }
            if existing.contact == entry.contact {
                // adding a verified contact happens on a response -> reset failure count
                if entry.verified() && entry.last_response > existing.last_response {
                    existing.failures = min(existing.failures, entry.failures);
                }
                self.replacements.retain(|rep| !rep.contact.partial_or_full_match(&entry.contact));
                existing.merge(entry);
                return;
            }
        }

        if self.entries.len() >= BUCKET_SIZE || !entry.verified() {
            // replacements are ephemeral. yeet existing one if it overlaps
            // TODO: we probably should prefer verified ones over unverified
            // TODO: size limits, but we temporarily want replacements to grow larger so we can defer bucket splitting to the next tick
            self.replacements.retain(|existing| !existing.contact.partial_or_full_match(&entry.contact));
            self.replacements.push(entry);
            return;
        }

        self.entries.push(entry);
    }

    fn check_invariants(&self) {
        if self.entries.iter().any(|e| !e.verified()) {
            panic!("rt contained non-verified contact");
        }
        if self.entries.iter().any(|e| e.contact.is_bogon()) {
            panic!("rt contained bogon {:?}", self.entries.iter().filter(|e| e.contact.is_bogon()).collect::<Vec<_>>());
        }
    }

    fn discard_spoofs(&mut self, oracle: &IdMismatchOracle) {
        let filter = |e: &BucketEntry| {
            if let Some((verified_id, _)) = oracle.check(e.contact.address) {
                verified_id == e.contact.id
            } else {
                true
            }
        };

        self.entries.retain(filter);
        self.replacements.retain(filter);
    }

    fn split(self, left_prefix: &Prefix, right_prefix: &Prefix) -> (Bucket, Bucket) {
        let previous_maintenance = self.last_maintenance;

        let mut left = Bucket {
            entries: self.entries,
            replacements: self.replacements,
            last_maintenance: SystemTime::UNIX_EPOCH,
        };
        let mut right = Bucket {
            entries: left.entries.drain_filter(|e| right_prefix.covers(&e.contact.id)).collect(),
            replacements: left.replacements.drain_filter(|e| right_prefix.covers(&e.contact.id)).collect(),
            last_maintenance: SystemTime::UNIX_EPOCH,
        };

        debug_assert!(left.entries.iter().all(|e| left_prefix.covers(&e.contact.id)));
        debug_assert!(left.replacements.iter().all(|e| left_prefix.covers(&e.contact.id)));

        left.uplift_replacements();
        right.uplift_replacements();

        if left.entries.len() >= BUCKET_SIZE {
            right.last_maintenance = previous_maintenance
        }
        if right.entries.len() >= BUCKET_SIZE {
            right.last_maintenance = previous_maintenance
        }

        (left, right)
    }

    fn merge(mut self, sibling: Self) -> Bucket {
        self.entries.extend(sibling.entries.into_iter());
        self.replacements.extend(sibling.replacements.into_iter());
        self.last_maintenance = max(self.last_maintenance, sibling.last_maintenance);
        self.entries.retain(|e| !e.dead());

        self
    }


    /// Discards one dead entry. Does not discard if the bucket is not full and
    /// there are no promotable replacements.
    ///
    /// This generally is enough since the method get called on every tick and we
    /// don't want to empty buckets during network loss.
    fn discard_dead(&mut self) {
        if !self.replacements.iter().any(BucketEntry::verified) && self.entries.len() < BUCKET_SIZE {
            return
        }

        let idx = self.entries.iter().position(BucketEntry::dead);
        if let Some(idx) = idx {
            self.entries.swap_remove(idx);
        }
    }

    /// If the main bucket is not full and we have any verified replacements then promote them
    /// directly.
    fn uplift_replacements(&mut self) {
        let len = self.replacements.len();

        for i in (0..len).rev() {
            if self.entries.len() >= BUCKET_SIZE {
                break;
            }
            if self.replacements[i].verified() {
                let replacement = self.replacements.swap_remove(i);
                self.add_entry(replacement);
            }
        }
    }

    fn uplift_restricted(&mut self) {
        if self.entries.len() < BUCKET_SIZE {
            return;
        }
        if let Some(replaceable) = self.entries.iter().position(|e| !e.contact.is_restricted()) {
            if let Some(replacement) = self.replacements.iter().position(|r| r.verified() && r.contact.is_restricted()) {
                let replacement = self.replacements.swap_remove(replacement);
                self.entries[replaceable] = replacement;
            }
        }
    }

    fn trim(&mut self) {
        if self.entries.len() > BUCKET_SIZE {
            // restricted -> false -> restricted entries to the front
            // older = smaller timestamp -> sort the younger ones to the end -> keep old entries
            self.entries.sort_unstable_by_key(|e| (!e.contact.is_restricted(), e.created));
            self.entries.truncate(BUCKET_SIZE);
        }

        if self.entries.len() == BUCKET_SIZE && self.replacements.len() > BUCKET_SIZE {
            // we want to keep fresh replacements
            // since younger = higher timestamp -> reverse sort -> older ones at the end
            self.replacements.sort_unstable_by_key(|e| (!e.contact.is_restricted(), Reverse(e.last_seen)));
            self.replacements.truncate(BUCKET_SIZE);
        }
    }
}

type TransactionId = [u8; 4];

lazy_static! {
    static ref TRANSACTION_KEY: [u8; 10] = rand::random();
    static ref TOKEN_KEY: [u8; 16] = rand::random();
}

static TRANSACTION_COUNTER: AtomicU32 = AtomicU32::new(0);

fn transaction_id() -> [u8; 4] {
    let counter = TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    skip32::encode(TRANSACTION_KEY.deref(), counter).to_be_bytes()
}

struct PendingQuery {
    transaction_id: TransactionId,
    query: QueryType,
    address: SocketAddr,
    expected_id: Option<Id>,
    sent_at: SystemTime,
    lookup_id: Option<u64>,
}

enum LookupType {
    FindNode,
    GetPeers,
    GetValue
}


trait Lookup: Any {
    fn tick(&mut self, dht: &mut Dht, soft_timeout_ms: u64) -> Result<bool, Box<dyn Error>>;

    fn responded(&mut self, query: &PendingQuery, contact: Contact, response: &Response);

    /// Remove a pending query. For any reason, could be a response or a timeout.
    /// Successfully parsed responses have their `responded` method invoked *in addition*
    /// to this method.
    fn remove_query(&mut self, query: &PendingQuery);

    fn add_contacts(&mut self, contacts: &mut dyn Iterator<Item=Contact>, source: Option<&Contact>, from_query: Option<&PendingQuery>);

    fn and_then(&mut self, callback: Box<dyn FnOnce(&mut Self, &mut Dht)>) where Self: Sized;
}

pub struct Dht {
    id: Id,
    routing_table: BTreeMap<Prefix, Bucket>,
    last_ip_dedup_at: SystemTime,
    pending_queries: HashMap<TransactionId, PendingQuery>,
    lookups: HashMap<u64, Box<dyn Lookup>>,
    response_histogram: Histogram<u32>,
    id_mismatch_oracle: IdMismatchOracle,
    unreachable_oracle: UnreachableOracle,
    announce_storage: BTreeMap<Id, Vec<StoredPeer>>,
    external_address_indications: HashMap<IpAddr, IpAddr>,
    socket: UdpSocket,
}

impl Dht {
    pub fn new() -> io::Result<Self> {
        let mut routing_table = BTreeMap::new();
        routing_table.insert(Prefix::ALL, Bucket::empty());
        let mut hist = Histogram::<u32>::new_with_bounds(1, 10 * 1000, 2).unwrap();
        hist.record(1000).unwrap();


        let probe_socket = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0").unwrap())?;
        probe_socket.connect(SocketAddr::from_str("8.8.8.8:3000").unwrap())?;
        let default_address = probe_socket.local_addr()?;
        drop(probe_socket);
        let addr = SockAddr::from(SocketAddr::new(default_address.ip(), 8845));

        let main_socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        main_socket.set_reuse_address(true)?;
        main_socket.bind(&addr)?;
        main_socket.set_nonblocking(true)?;
        let main_socket = unsafe { UdpSocket::from_raw_fd(main_socket.into_raw_fd()) };

        Ok(Dht {
            id: Id::random(),
            routing_table,
            last_ip_dedup_at: SystemTime::UNIX_EPOCH,
            pending_queries: HashMap::new(),
            lookups: HashMap::new(),
            response_histogram: hist,
            id_mismatch_oracle: IdMismatchOracle::new(),
            unreachable_oracle: UnreachableOracle::new(),
            announce_storage: BTreeMap::new(),
            socket: main_socket,
            external_address_indications: HashMap::new()
        })
    }

    pub fn socket(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn bootstrap(&mut self, and_then: Option<Box<dyn FnOnce(&mut TargetedLookup, &mut Dht)>>) -> Result<(), Box<dyn Error>> {
        const BOOTSTRAP_ADDR: &str = "router.bittorrent.com:6881";
        let addr = ToSocketAddrs::to_socket_addrs(BOOTSTRAP_ADDR)?.next().expect("address resolved");
        let mut query = Self::send_find_node(self.id, self.id, addr, None, &self.socket)?;

        let now = SystemTime::now();

        let mut bootstrap_lookup = TargetedLookup::targeted_find_node(now, self.id);

        query.lookup_id = Some(bootstrap_lookup.id);
        bootstrap_lookup.queries.insert(query.transaction_id);

        // TODO: remove callbacks, just schedule tasks before bootstrap and let them sit idle when they don't have enough contacts to start
        if let Some(callback) = and_then {
            bootstrap_lookup.and_then(callback);
        }
        self.register_query(query);
        self.lookups.insert(bootstrap_lookup.id, Box::new(bootstrap_lookup));

        let home_bucket = self.bucket_covering_id_mut(self.id);
        home_bucket.last_maintenance = now;

        Ok(())
    }

    pub fn get_task<T: Any>(&mut self, task_id: u64) -> Option<&mut T> {
        self.lookups.get_mut(&task_id).and_then(|lookup| <dyn Any>::downcast_mut::<T>(lookup.as_mut() as &mut dyn Any))
    }

    pub(in self) fn get_query(&self, tid: &TransactionId) -> &PendingQuery {
        self.pending_queries.get(tid).expect("passed a query ID that doesn't exist in the dht")
    }

    pub fn crawl(&mut self) -> u64 {

        let mut fill_lookup = TargetedLookup::targeted_find_node(SystemTime::now(), Id::MIN);

        let crawl_task = crawl::Crawl::new();

        let crawl_id = crawl_task.id;

        fill_lookup.and_then(Box::new(move |lookup, dht: &mut Dht| {
            let mut crawl_task = crawl_task;

            // TODO: maybe we can remove this now that tick() takes a `Dht`. tasks can self-populate
            // first we dump the routing table into the crawl so it can start splitting its buckets properly (it FIFOs contacts per bucket)
            crawl_task.add_contacts(&mut dht.routing_table.values().flat_map(|bucket| bucket.entries.iter().map(|b| b.contact.clone())), None, None);

            // only after splitting it should then use the MIN_ID (0000...) contacts
            let mut min_contacts: Vec<_> = lookup.responded.iter().cloned().collect();
            // largest IDs first so the crawl can keep splitting further and only visits the lowest known contacts once it is done splitting
            min_contacts.sort_unstable_by_key(|c| Reverse(c.id));
            crawl_task.add_contacts(&mut min_contacts.into_iter(), None, None);
            dht.lookups.insert(crawl_task.id, Box::new(crawl_task));
        }));

        fill_lookup.add_contacts(&mut self.routing_table.values().flat_map(|bucket| bucket.entries.iter().map(|b| b.contact.clone())), None, None);

        self.lookups.insert(fill_lookup.id, Box::new(fill_lookup));

        crawl_id
    }

    pub fn recv_message(&mut self, buf: &[u8], from_address: SocketAddr) {

        trace!("{:>21} -> {}", from_address, utils::strip(buf));

        if buf.len() < 15 || from_address.port() == 0 {
            info!("message too short or port is zero, discarding");
            return;
        }

        let message = match serde_bencoded::from_bytes::<Message>(&buf) {
            Ok(message) => message,
            Err(e) => {
                info!("decode error {} {}", e, String::from_utf8_lossy(buf));
                return;
            }
        };

        match message.message_type {
            MessageType::Response => self.response(message, from_address),
            MessageType::Request => self.request(message, from_address),
            MessageType::Error => self.error(message, from_address)
        }
    }

    pub fn network_tick(&mut self) -> Result<(), Box<dyn Error>> {
        let mut recv_buf = [0u8; 4096];

        loop {
            match self.socket.recv_from(&mut recv_buf) {
                Ok((received, addr)) => {
                    let recv_buf = &recv_buf[0..received];
                    self.recv_message(recv_buf, addr);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                    // timeout, do nothing, just tick
                    break;
                },
                Err(e) => {
                    eprintln!("encountered recv error {}", e);
                    Err(e)?;
                }
            }
        }

        Ok(())
    }

    pub fn tick(&mut self, poll: &mut mio::Poll) -> Result<(), Box<dyn Error>> {
        let now = Instant::now();
        let system_now = SystemTime::now();

        #[derive(PartialEq, Eq)]
        struct Stats {
            buckets: usize,
            entries: usize,
            replacements: usize,
            pending: usize,
            lookups: usize,
        }

        impl Stats {
            fn new(dht: &Dht) -> Stats {
                Stats {
                    buckets: dht.routing_table.len(),
                    entries: dht.routing_table.values().map(|bucket| bucket.entries.len()).sum(),
                    replacements: dht.routing_table.values().map(|bucket| bucket.replacements.len()).sum(),
                    pending: dht.pending_queries.len(),
                    lookups: dht.lookups.len(),
                }
            }
        }

        let initial_stats = Stats::new(&self);

        if self.derive_id() {
            // ID changed, rediscover our neighborhood
            let mut lookup = TargetedLookup::targeted_find_node(system_now, self.id);
            for (prefix, bucket) in self.routing_table.iter() {
                lookup.add_contacts(&mut bucket.entries.iter().filter(|e| !e.dead()).map(|e| e.contact.clone()), None, None);
            }
            self.bucket_covering_id_mut(self.id).last_maintenance = system_now;
            self.lookups.insert(lookup.id, Box::new(lookup));
        }

        // timeout pending queries
        let timeouts = self.pending_queries.iter().filter(|(_, v)| {
            system_now.duration_since(v.sent_at).unwrap() > QUERY_TIMEOUT
        }).map(|(k, _)| *k).collect::<Vec<_>>();

        for timed_out in timeouts {
            let query = self.remove_query(&timed_out);
            self.unreachable_oracle.timeout(&query, system_now);
            if let Some(expected_id) = query.expected_id {
                let bucket = self.bucket_covering_id_mut(expected_id);
                bucket.timeout(query.address, expected_id);
            }
        }

        self.ip_dedup(system_now);

        // do home bucket splitting
        // TODO: relaxed splitting
        loop {
            let (home_prefix, home_bucket) = self.routing_table.range((Included(Prefix::MIN), Included(Prefix::from_id(self.id)))).last().expect("there always is a home bucket");
            if home_bucket.entries.len() >= BUCKET_SIZE {
                let prefix = *home_prefix;
                let home_bucket = self.routing_table.remove(&prefix).unwrap();
                match prefix.split() {
                    Some((left, right)) => {
                        let (left_bucket, right_bucket) = home_bucket.split(&left, &right);
                        self.routing_table.insert(left, left_bucket);
                        self.routing_table.insert(right, right_bucket);
                    }
                    None => {
                        warn!("could not split home bucket {:?}", home_bucket);
                    }
                }
            } else {
                break;
            }
        }


        let mut need_maintenance = Vec::new();
        let mut added_queries = Vec::new();

        // routing table maintenance
        for (prefix, bucket) in self.routing_table.iter_mut() {
            bucket.check_invariants();
            bucket.discard_spoofs(&self.id_mismatch_oracle);
            bucket.discard_dead();
            bucket.uplift_replacements();
            bucket.uplift_restricted();
            // this has to happen after bucket splitting
            bucket.trim();

            for entry in bucket.entries.iter_mut() {
                if system_now.duration_since(entry.last_seen).unwrap() > BUCKET_ENTRY_REFRESH &&
                    system_now.duration_since(entry.last_queried).unwrap() > BUCKET_ENTRY_REFRESH {
                    let query = Self::send_ping(self.id, entry.contact.address, Some(entry.contact.id), &self.socket)?;
                    entry.last_queried = system_now;
                    added_queries.push(query);
                }
            }

            if bucket.entries.len() >= BUCKET_SIZE {
                continue;
            }
            // don't do maintenance queries if there's a verification ping in flight
            if bucket.replacements.iter().any(|r| system_now.duration_since(r.last_queried).unwrap() < QUERY_TIMEOUT) {
                continue;
            }

            // at this point the bucket is not full and all verified replacements have been uplifted
            // thus any remaining replacement needs a ping before it can be moved to the main bucket

            // don't immediately ping replacements after we learned about them from incoming traffic. They may be behind a NAT and later won't respond
            // due to expired port mappings. So we only ping them after some delay
            if let Some(replacement) = bucket.replacements.iter_mut().rfind(|r| system_now.duration_since(r.last_seen).unwrap() > NAT_TIMEOUT) {
                replacement.last_queried = system_now;
                // send ping to promote an entry
                let query = Self::send_ping(self.id, replacement.contact.address, Some(replacement.contact.id), &self.socket)?;
                added_queries.push(query);
            } else if bucket.replacements.is_empty() && system_now.duration_since(bucket.last_maintenance).unwrap_or(Duration::ZERO) > Duration::from_secs(60 * 10) {
                need_maintenance.push(prefix.random_id());
                // add some smear to avoid thundering herds. add the query timeout as baseline since a lookup will take at least that long
                bucket.last_maintenance = system_now + QUERY_TIMEOUT + Duration::from_millis(thread_rng().gen_range(0..10000));
            }
        }

        for query in added_queries {
            self.register_query(query);
        }

        for target in need_maintenance {
            let mut fill_lookup = TargetedLookup::targeted_find_node(system_now, target);

            fill_lookup.add_contacts(&mut self.routing_table.values().flat_map(|b| b.entries.iter()).map(|e| e.contact.clone()), None, None);

            assert!(self.lookups.insert(fill_lookup.id, Box::new(fill_lookup)).is_none());
        }

        self.merge_buckets();

        self.drive_lookups()?;
        self.id_mismatch_oracle.cleanup(system_now);
        self.unreachable_oracle.cleanup(system_now);

        for values in self.announce_storage.values_mut() {
            values.retain(|v| system_now.duration_since(v.last_seen).unwrap() < MAX_ANNOUNCE_AGE);
        }
        self.announce_storage.retain(|_, v| v.len() > 0);


        let end_stats = Stats::new(self);

        if initial_stats != end_stats {
            trace!("buck:{} entr:{} rep:{} pending:{} lookups:{}", end_stats.buckets, end_stats.entries, end_stats.replacements, end_stats.pending, end_stats.lookups);
        }

        // TODO: calculate wakeup time so caller can sleep longer

        Ok(())
    }

    pub fn print_routing_table(&self) {
        println!("## Routing table:");
        for (prefix, bucket) in &self.routing_table {
            let is_home = if prefix.covers(&self.id) {'H'} else { ' ' };
            println!("{}/{} {} e:{} r:{}", prefix.base, prefix.bits, is_home, bucket.entries.len(), bucket.replacements.len());
        }
    }

    pub fn print_lookups(&self) {
        println!("## Lookups");
        for (id, lookup) in &self.lookups {
            println!("id:{id} type: {:?}", lookup.type_id());
            if let Some(crawl) = <dyn Any>::downcast_ref::<Crawl>(lookup.as_ref() as &dyn Any) {
                crawl.print_state();
            }
        }
    }

    fn drive_lookups(&mut self) -> Result<(), Box<dyn Error>> {
        let timeout = self.response_histogram.value_at_quantile(0.95);
        let mut done = Vec::new();

        // TODO: use an option here so we can fail more loudly when something tries to access the
        //  lookups while they're taken out here
        let mut lookups = std::mem::take(&mut self.lookups);

        // TODO: figure out what to do on errors. maybe check the socket for network issues
        //  before continuing?
        let result: Result<(), Box<dyn Error>> = try {
            for (&id, lookup) in lookups.iter_mut() {
                if lookup.tick(  self, timeout)? {
                    done.push(id);
                }
            }
        };


        let new_lookups = std::mem::replace(&mut self.lookups, lookups);

        // TODO: do away with this. without callbacks that create lookups this wouldn't be needed and we could assert instead
        // or only call callbacks after the task is done
        for (id, lookup) in new_lookups {
            assert!(self.lookups.insert(id, lookup).is_none());
        }

        for done in done {
            assert!(self.lookups.remove(&done).is_some());
            assert!(!self.pending_queries.values().any(|q| q.lookup_id == Some(done)));
        }

        result
    }

    fn ip_dedup(&mut self, now: SystemTime) {
        if self.last_ip_dedup_at + IP_DEDUP_INTERVAL > now {
            return;
        }
        self.last_ip_dedup_at = now;
        let mut ips = HashSet::with_capacity(self.routing_table.len() * BUCKET_SIZE);

        for bucket in self.routing_table.values_mut() {
            bucket.entries.retain(|e| {
                ips.insert(e.contact.address.ip())
            });
        }
    }

    fn merge_buckets(&mut self) {
        let mut iter = self.routing_table.iter();
        let mut a = iter.next();
        let mut b = None;

        while let (Some(left), Some(right)) = (a, iter.next()) {
            let non_home_buckets = !left.0.covers(&self.id) && !right.0.covers(&self.id);
            // Less is required so that the home bucket can have one free slot which will trigger splits when filled
            let non_lossy_merge  = left.1.entries.len() + right.1.entries.len() < BUCKET_SIZE;

            if left.0.is_sibling(right.0) && (non_home_buckets || non_lossy_merge) {
                b = Some(right);
                break;
            }
            a = Some(right);
        }

        if let (Some(a), Some(b)) = (a, b) {
            let (key_a, key_b) = (*a.0, *b.0);
            let parent = key_a.parent().expect(&format!("mergable buckets should have a parent prefix {:?} {:?}", key_a, key_b));
            assert_eq!(Some(parent), key_b.parent());
            let a = self.routing_table.remove(&key_a).unwrap();
            let b = self.routing_table.remove(&key_b).unwrap();

            debug!("merging {:?} {:?} lengths: {} {} id: {} cover? {}", key_a, key_b, a.entries.len(), b.entries.len(), self.id, parent.covers(&self.id));

            let merged = a.merge(b);
            assert!(self.routing_table.insert(parent, merged).is_none());
        }
    }


    /// Returns true if the id changed
    fn derive_id(&mut self) -> bool {
        if self.external_address_indications.len() < EXTERNAL_ADDRESS_QUORUM {
            return false;
        }

        let mut changed = false;

        let set: HashSet<_> = self.external_address_indications.values().into_iter().collect();

        if set.len() == 1 {
            let consensus = set.into_iter().next().expect("we just checked the length");
            let old_id = self.id;
            let new_id = old_id.to_restricted_id(*consensus);
            if old_id != new_id {
                info!("External address update: {}  Changing node ID {} -> {}", consensus, old_id, new_id);
                self.id = new_id;
                changed = true;
            }
        }

        self.external_address_indications.clear();
        changed
    }

    fn active_queries_excluding_stalled(&self, query_ids: impl Iterator<Item=TransactionId>) -> usize {
        let now = SystemTime::now();

        query_ids.map(|tid| self.pending_queries.get(&tid).unwrap()).map(|e| {
            let age = now.duration_since(e.sent_at).unwrap();
            let millis = age.as_millis();
            // TODO: the histogram only records responses, not (fairly generous) timeouts.
            //  we probably want some separate accounting for packet loss rate and be less aggressive when it is high
            let percentile = self.response_histogram.quantile_below(millis as u64);
            1.0 - percentile
        }).sum::<f64>().ceil() as usize
    }

    fn send_find_node(self_id: Id, target: Id, addr: SocketAddr, expected_id: Option<Id>, socket: &UdpSocket) -> Result<PendingQuery, Box<dyn Error>> {
        let query = PendingQuery {
            transaction_id: transaction_id(),
            query: QueryType::FindNode,
            expected_id,
            sent_at: SystemTime::now(),
            address: addr,
            lookup_id: None
        };

        let msg = Message {
            transaction_id: &query.transaction_id,
            message_type: MessageType::Request,
            version: Some(Bytes::new(VERSION)),
            request: Some(Request { id: self_id.0.as_ref(), target: Some(Bytes::new(target.0.as_ref())), info_hash: None, port: None, token: None }),
            response: None,
            query_type: message::QueryType::FindNode,
            external_address: None,
        };

        Self::send_message(&msg, addr, socket, "")?;
        Ok(query)
    }
    
    fn send_sample_infohashes<'a>(self_id: Id, target: Id, addr: SocketAddr, expected_id: Option<Id>, socket: &UdpSocket, sources: impl Iterator<Item=&'a IpAddr>) -> Result<PendingQuery, Box<dyn Error>> {
        let query = PendingQuery {
            transaction_id: transaction_id(),
            query: QueryType::SampleInfohashes,
            expected_id,
            sent_at: SystemTime::now(),
            address: addr,
            lookup_id: None
        };

        let msg = Message {
            transaction_id: &query.transaction_id,
            message_type: MessageType::Request,
            version: Some(Bytes::new(VERSION)),
            request: Some(Request { id: self_id.0.as_ref(), target: Some(Bytes::new(target.0.as_ref())), info_hash: None, port: None, token: None }),
            response: None,
            query_type: message::QueryType::SampleInfohashes,
            external_address: None
        };

        Self::send_message(&msg, addr, socket, sources.map(|s| s.to_string()).intersperse(", ".to_owned()).collect::<String>())?;
        Ok(query)
    }

    fn send_ping(self_id: Id, addr: SocketAddr, expected_id: Option<Id>, socket: &UdpSocket) -> Result<PendingQuery, Box<dyn Error>> {
        let query = PendingQuery {
            transaction_id: transaction_id(),
            query: QueryType::Ping,
            expected_id,
            sent_at: SystemTime::now(),
            address: addr,
            lookup_id: None,
        };

        let msg = Message {
            transaction_id: &query.transaction_id,
            message_type: MessageType::Request,
            version: Some(Bytes::new(VERSION)),
            request: Some(Request { id: self_id.0.as_ref(), ..Default::default() }),
            response: None,
            query_type: message::QueryType::Ping,
            external_address: None,
        };

        Self::send_message(&msg, addr, socket, "")?;

        Ok(query)
    }

    fn send_ping_reply(self_id: Id, addr: SocketAddr, transaction_id: &[u8], socket: &UdpSocket) {
        let compact_addr = CompactSockAddr::from_sock_addr(addr);
        let msg = Message {
            transaction_id,
            message_type: MessageType::Response,
            version: Some(Bytes::new(VERSION)),
            request: None,
            response: Some(Response { id: &self_id.0, ..Default::default() }),
            query_type: message::QueryType::None,
            external_address: Some(&Bytes::new(compact_addr.as_slice()))
        };

        Self::send_message(&msg, addr, socket, "");
    }

    fn send_find_node_reply(&self, addr: SocketAddr, transaction_id: &[u8], target: Id) {
        let nodes = self.get_nodes_for_reply(target);
        let compact_addr = CompactSockAddr::from_sock_addr(addr);
        let msg = Message {
            transaction_id,
            message_type: MessageType::Response,
            version: Some(Bytes::new(VERSION)),
            request: None,
            response: Some(Response { id: &self.id.0, nodes: Some(Bytes::new(nodes.as_slice())), ..Default::default() }),
            query_type: message::QueryType::None,
            external_address: Some(&Bytes::new(compact_addr.as_slice()))
        };

        Self::send_message(&msg, addr, &self.socket, "");
    }

    fn get_nodes_for_reply(&self, target: Id) -> Vec<u8> {
        const MAX_NODES: usize = 16;

        let mut nodes = Vec::with_capacity(MAX_NODES);

        // FIXME: use some k-smallest implementation
        for bucket in self.routing_table.values() {
            if bucket.entries.is_empty() {
                continue;
            }
            nodes.extend(bucket.entries.iter().map(|e| e.contact.clone()));
            nodes.sort_unstable_by_key(|n| n.id.distance(&target));
            nodes.truncate(MAX_NODES);
        }

        Contact::to_bytes(nodes)
    }

    fn get_values_for_reply(&self, target: Id) -> Vec<u8> {
        let mut values = Vec::new();
        const MAX_VALUES: usize = 16;

        if let Some(entries) = self.announce_storage.get(&target) {
            let offset = rand::thread_rng().gen_range(0..entries.len());
            for i in 0..min(MAX_VALUES, entries.len()) {
                let index = (offset + i) % entries.len();
                let entry = &entries[index];
                entry.serialize_into(&mut values);
            }
        }

        values
    }

    fn send_message(msg: &Message, addr: SocketAddr, socket: &UdpSocket, extra: impl Display) -> std::io::Result<()> {
        let serialized = serde_bencode::to_bytes(&msg).expect("message to serialize");

        trace!("{:>21} <- {} {}", addr, utils::strip(serialized.as_slice()), extra);

        // TODO: handle wouldblock
        let bytes = match socket.send_to(&serialized, addr) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("failed to send to {}: {}", addr, e);
                return Err(e);
            }
        };
        assert_eq!(bytes, serialized.len(), "message sent truncated");

        Ok(())
    }

    fn send_get_peers_reply(&self, addr: SocketAddr, transaction_id: &[u8], target: Id) {
        let nodes = self.get_nodes_for_reply(target);
        let values = self.get_values_for_reply(target);

        let values = if values.len() > 0 { Some(Bytes::new(values.as_slice())) } else { None };


        let token = gen_token(addr, target, SystemTime::now()).finalize().into_bytes();
        let mut token = Some(Bytes::new(token.as_slice()));

        if let Some(vals) =  self.announce_storage.get(&target) {
            if vals.len() > 6000 {
                token = None;
            }
        }

        let compact_addr = CompactSockAddr::from_sock_addr(addr);

        let msg = Message {
            transaction_id,
            message_type: MessageType::Response,
            version: Some(Bytes::new(VERSION)),
            request: None,
            response: Some(Response {
                id: &self.id.0,
                nodes: Some(Bytes::new(nodes.as_slice())),
                token,
                values,
                ..Default::default()
            }),
            query_type: message::QueryType::None,
            external_address: Some(&Bytes::new(compact_addr.as_slice()))
        };

        Self::send_message(&msg, addr, &self.socket, "");
    }

    fn send_announce_peer_reply(&mut self, addr: SocketAddr, transaction_id: &[u8], target: Id, port: u16) {

        let now = SystemTime::now();

        let entries = self.announce_storage.entry(target).or_insert(Vec::new());
        if let Some(existing) = entries.iter_mut().find(|e| e.contact.address.ip() == addr.ip()) {
            existing.last_seen = now;
            existing.contact.address.set_port(port);
        } else {
            entries.push(StoredPeer {
                contact: Contact {
                    id: target,
                    address: SocketAddr::new(addr.ip(), port),
                },
                last_seen: now,
            });
        }

        let mut args: message::Response = Default::default();
        args.id = &self.id.0;


        let compact_addr = CompactSockAddr::from_sock_addr(addr);

        let msg = Message {
            transaction_id,
            message_type: MessageType::Response,
            version: Some(Bytes::new(VERSION)),
            request: None,
            response: Some(args),
            query_type: message::QueryType::None,
            external_address: Some(&Bytes::new(compact_addr.as_slice()))
        };

        Self::send_message(&msg, addr, &self.socket, "");
    }

    fn send_sample_infohashes_reply(&self, addr: SocketAddr, transaction_id: &[u8], target: Id) {
        let nodes = self.get_nodes_for_reply(target);

        let num = self.announce_storage.len();
        // maybe use a seekable data structure with a random offset instead
        let mut samples: Vec<_> = self.announce_storage.keys().into_iter().collect();
        samples.shuffle(&mut thread_rng());
        samples.truncate(16);
        let samples = samples.into_iter().flat_map(|id| id.0).collect::<Vec<_>>();


        let mut args: message::Response = Default::default();
        args.id = &self.id.0;
        args.nodes = Some(Bytes::new(nodes.as_slice()));
        args.interval = Some(0);
        args.samples = Some(Bytes::new(samples.as_slice()));
        args.num = Some(num as u32);

        let compact_addr = CompactSockAddr::from_sock_addr(addr);

        let msg = Message {
            transaction_id,
            message_type: MessageType::Response,
            version: Some(Bytes::new(VERSION)),
            request: None,
            response: Some(args),
            query_type: message::QueryType::None,
            external_address: Some(&Bytes::new(compact_addr.as_slice()))
        };

        Self::send_message(&msg, addr, &self.socket, "");
    }

    fn bucket_covering_id(&self, id: Id) -> &Bucket {
        let range = self.routing_table.range((Included(Prefix::MIN), Included(Prefix::from_id(id))));

        range.last().expect("the routing table should cover the entire keyspace").1
    }

    fn bucket_covering_id_mut(&mut self, id: Id) -> &mut Bucket {
        let range = self.routing_table.range_mut((Included(Prefix::MIN), Included(Prefix::from_id(id))));

        range.last().expect("the routing table should cover the entire keyspace").1
    }

    fn register_query(&mut self, query: PendingQuery) {
        if let Some(expected_id) = query.expected_id {
            let bucket = self.bucket_covering_id_mut(expected_id);
            bucket.sent(query.sent_at, query.address, expected_id);
        }

        assert!(self.pending_queries.insert(query.transaction_id, query).is_none());
    }

    fn remove_query(&mut self, transaction_id: &TransactionId) -> PendingQuery {
        let removed = self.pending_queries.remove(transaction_id).expect("query matching transaction id");
        if let Some(lookup_id) = removed.lookup_id {
            let lookup = self.lookups.get_mut(&lookup_id).expect("there should be a lookup if the query has a lookup id");
            lookup.remove_query(&removed);
        }

        removed
    }

    fn response(&mut self, response: Message, from_address: SocketAddr) {
        let query = match self.pending_queries.get(response.transaction_id) {
            Some(query) => query,
            None => {
                debug!("could not find transaction ID for response {:?}", response.transaction_id);
                return;
            }
        };

        if query.address.ip() != from_address.ip() {
            // possibly spoofed, ignore
            debug!("ip mismatch. actual:{} expected:{}", query.address, from_address);
            return;
        }

        let transaction_id = query.transaction_id;

        let now = SystemTime::now();
        let elapsed = now.duration_since(query.sent_at).unwrap();
        self.response_histogram.saturating_record(elapsed.as_millis() as u64);

        'processing: {
            let response_args = match response.response {
                Some(response) => response,
                None => {
                    debug!("response didn't contain response args");
                    break 'processing;
                }
            };

            let id = response_args.id;

            if id.len() != 20 {
                debug!("expected 20 id bytes from remote");
                break 'processing;
            }

            let id = Id(id.try_into().expect("we just checked the length"));

            if id == self.id {
                // this is either our own external address or some other node mirroring our packets
                debug!("received own ID, discarding");
                // also insert into the oracle since it'll help us to filter out this remote address
                // during lookups.
                self.id_mismatch_oracle.insert(from_address, id, now);
                break 'processing;
            }

            if let Some(ref expected) = query.expected_id {
                if expected != &id {
                    debug!("{} expected ID did not match received ID; expected: {}, actual: {}", from_address, expected, id);
                    self.id_mismatch_oracle.insert(from_address, id, now);
                    break 'processing;
                }
            }

            if from_address != query.address {
                debug!("socket address mismatch");
                break 'processing;
            }

            let source_contact = Contact {id, address: from_address};

            if let Some(indicated_ip) = response.external_address {
                if let Some(bytes) = indicated_ip.get(0..4) {
                    // TODO: IPv6 support
                    let ary: [u8; 4] = TryFrom::try_from(bytes).expect("we just checked the length");
                    let ip = Ipv4Addr::from(ary);
                    self.external_address_indications.insert(from_address.ip(),  IpAddr::V4(ip));
                }
            }


            match query.query {
                QueryType::FindNode | QueryType::SampleInfohashes => {
                    let nodes: &[u8] = match response_args.nodes {
                        Some(nodes) => nodes,
                        None => {
                            debug!("missing nodes in lookup response");
                            break 'processing;
                        }
                    };
                    let mut contacts = match Contact::from_bytes(nodes) {
                        Ok(contacts) => contacts,
                        Err(e) => {
                            debug!("failed to parse 'nodes' {}", e);
                            break 'processing;
                        }
                    };

                    if let Some(lookup_id) = query.lookup_id {
                        let lookup = self.lookups.get_mut(&lookup_id).expect("queries with a lookup id should have a matching lookup");
                        lookup.responded(&query, source_contact.clone(), &response_args);
                        lookup.add_contacts(&mut contacts, Some(&source_contact), Some(query));
                    }
                },
                QueryType::Ping => {
                    // nothing to do here, the updates below are all we need
                },
                _ => unimplemented!()
            };

            self.unreachable_oracle.success(&query, now);

            self.insert_verified_contact(id, from_address, query.sent_at);
        };

        self.remove_query(&transaction_id);
    }


    fn insert_verified_contact(&mut self, id: Id, address: SocketAddr, sent_at: SystemTime) {
        let bucket = self.bucket_covering_id_mut(id);
        bucket.add_verified_contact(Contact { id, address }, sent_at);
    }

    fn request(&mut self, request: Message, from_address: SocketAddr) {
        let request_args = match request.request {
            None => {
                debug!("{:>21} -> {} {:?}", from_address, "incoming request lacking request args", request);
                return;
            }
            Some(args) => args
        };

        let id: Id = match request_args.id.try_into() {
            Ok(id) => id,
            Err(e) => {
                debug!("invalid ID in incoming request {}", e);
                return;
            }
        };

        if id == self.id {
            debug!("received own ID, discarding");
            return;
        }

        let bucket = self.bucket_covering_id_mut(id);
        bucket.add_unverified_contact(Contact {id, address: from_address });

        match request.query_type {
            message::QueryType::FindNode => {
                match request_args.target {
                    Some(target) => match target.as_ref().try_into() {
                        Ok(target) => self.send_find_node_reply(from_address, request.transaction_id, target),
                        Err(e) =>  debug!("could not process incoming find_node request {:?}", e)
                    }
                    _ => debug!("incoming find_node missing target")
                }
            }
            message::QueryType::Ping => {
                Self::send_ping_reply(self.id, from_address, request.transaction_id, &self.socket)
            }
            message::QueryType::GetPeers => {
                match request_args.info_hash {
                    Some(target) => match target.as_ref().try_into() {
                        Ok(target) => self.send_get_peers_reply(from_address ,request.transaction_id, target),
                        Err(e) => debug!("could not process incoming get_peers request {:?}", e)
                    }
                    _ => debug!("incoming get_peers missing info_hash")
                }
            }
            message::QueryType::AnnouncePeer => {
                let port = match request_args.port {
                    Some(port) => port,
                    None => {
                        debug!("incoming announce_peer missing port");
                        return;
                    }
                };

                let token = match request_args.token {
                    Some(token) => token,
                    None => {
                        debug!("incoming announce_peer missing token");
                        return;
                    }
                };

                match request_args.info_hash {
                    Some(target) => match target.as_ref().try_into() {
                        Ok(target) => {
                            if !check_token(token.as_ref(), from_address, target) {
                                debug!("incoming announce_peer invalid token");
                                return;
                            }

                            self.send_announce_peer_reply(from_address, request.transaction_id, target, port)
                        },
                        Err(e) => debug!("could not process incoming announce_peer request {:?}", e)
                    }
                    _ => debug!("incoming announce_peer missing info_hash")
                }
            }
            message::QueryType::SampleInfohashes => {
                match request_args.target {
                    Some(target) => match target.as_ref().try_into() {
                        Ok(target) => self.send_sample_infohashes_reply(from_address, request.transaction_id, target),
                        Err(e) => debug!("could not process incoming sample_infohashes request {:?}", e)
                    }
                    _ => debug!("incoming sample_infohashes missing info_hash")
                }
            }
            query @ _ => {
                debug!("{:>21} -> incoming request not implemented; using default handler, {:?}, {:?}", from_address, query,  request_args);
                if let Some(target) = request_args.info_hash.or(request_args.target) {
                    match target.as_ref().try_into() {
                        Ok(target) => self.send_find_node_reply(from_address, request.transaction_id, target),
                        Err(e) => debug!("could not decode target or infohash of unknown request type")
                    }
                } else {
                    // TODO: send error message
                }
            }
        }
    }

    fn error(&mut self, error: Message, from_address: SocketAddr) {
        debug!("{:>21} -> handling for incoming errors not implemented {:?}", from_address, error);
    }

}


#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use crate::crawl::Crawl;
    use crate::Dht;
    use crate::dht::Contact;
    use crate::dht::message::QueryType;

    use super::{Id, Prefix};

    #[test]
    fn test_prefix_split() {
        let (left, right) = Prefix::ALL.split().unwrap();
        assert_eq!(left, Prefix {bits: 1, base: Id([0u8; 20])});
        assert_eq!(right, Prefix {bits: 1, base: Id([0x80, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])});
        assert!(left.is_sibling(&right));
        assert!(right.is_sibling(&left));
    }

    #[test]
    fn test_prefix_parent() {
        assert_eq!(Prefix::ALL.parent(), None);

        let p = Prefix {bits: 10, base: Id([0x80, 0b1100_0000, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])};
        assert_eq!(p.parent(), Some(Prefix {bits: 9, base: Id([0x80, 0b1000_0000, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])}));

        let pid = Prefix::from_id(Id::random());
        let p = pid.parent().unwrap();
        let (a, b) = p.split().unwrap();
        assert_eq!([a, b].iter().filter(|&e| e == &pid).count(), 1);
    }

    #[test]
    fn test_prefix_cover() {
        assert!(Prefix::ALL.covers(&Id::random()), "random cover");

        let prefix = Prefix {base: Id([0b0100_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), bits: 3};
        let id = Id([0b0100_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(prefix.covers(&id));
        let id = Id([0b0101_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(prefix.covers(&id));
        let id = Id([0b0000_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!prefix.covers(&id));
        let id = Id([0b0110_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!prefix.covers(&id));
        let id = Id([0b1000_0000, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!prefix.covers(&id));
    }

    #[test]
    fn test_bep42_id() {
        let mut id;

        id = Id(hex::decode("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401").unwrap().try_into().unwrap());
        assert_eq!(id, id.to_restricted_id(Ipv4Addr::from_str("124.31.75.21").unwrap().into()));

        id = Id(hex::decode("5a3ce9c14e7a08645677bbd1cfe7d8f956d53256").unwrap().try_into().unwrap());
        assert_eq!(id, id.to_restricted_id(Ipv4Addr::from_str("21.75.31.124").unwrap().into()));

        id = Id(hex::decode("a5d43220bc8f112a3d426c84764f8c2a1150e616").unwrap().try_into().unwrap());
        assert_eq!(id, id.to_restricted_id(Ipv4Addr::from_str("65.23.51.170").unwrap().into()));

        id = Id(hex::decode("1b0321dd1bb1fe518101ceef99462b947a01ff41").unwrap().try_into().unwrap());
        assert_eq!(id, id.to_restricted_id(Ipv4Addr::from_str("84.124.73.14").unwrap().into()));

        id = Id(hex::decode("e56f6cbf5b7c4be0237986d5243b87aa6d51305a").unwrap().try_into().unwrap());
        assert_eq!(id, id.to_restricted_id(Ipv4Addr::from_str("43.213.53.83").unwrap().into()));
    }

    #[test]
    fn test_contact_decoding() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = [0; 26];
        bytes[0] = 42;
        bytes[20] = 127;
        bytes[24] = 1;

        let contact = Contact::from_bytes(&bytes)?.next().unwrap();
        assert_eq!(contact.id.0[0], 42);
        assert_eq!(Ok(contact.address.ip()), "127.0.0.0".parse());
        assert_eq!(contact.address.port(), 256);

        Ok(())
    }

    #[test]
    fn test_request_decode() {
        let raw = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaa6:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t4:00001:v4:UT001:y1:qe";
        let message = match serde_bencoded::from_bytes::<super::Message>(&raw[..]) {
            Err(e) => {
                eprintln!("{}", e);
                panic!("should decode")
            }
            Ok(msg) => msg
        };
        assert!(message.request.is_some());
        assert_eq!(message.query_type, QueryType::FindNode);

    }

    #[test]
    fn test_downcast() {
        let mut dht = Dht::new().unwrap();
        let crawl = Crawl::new();
        dht.lookups.insert(1, Box::new(crawl));
        assert!(dht.get_task::<Crawl>(1).is_some());
    }
}