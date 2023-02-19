use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};
use lazy_static::lazy_static;

use blake2::{Blake2sMac, digest::Mac, digest::consts::U6};
use blake2::digest::CtOutput;
use crate::Id;

type Blake2s6 = blake2::Blake2sMac<U6>;

const TOKEN_VALIDITY: u64 = 5 * 60;

lazy_static! {
    static ref TOKEN_KEY: [u8; 16] = rand::random();
}

pub fn gen_token(addr: SocketAddr, target: Id, time: SystemTime) -> Blake2s6 {
    let mut hasher = Blake2s6::new_with_salt_and_personal(TOKEN_KEY.as_slice(), &[], &[]).unwrap();

    match addr.ip() {
        IpAddr::V4(ip) => {
            hasher.update(ip.octets().as_slice());
        },
        IpAddr::V6(ip) => {
            hasher.update(ip.octets().as_slice());
        },
    }

    hasher.update(addr.port().to_be_bytes().as_slice());
    hasher.update(target.0.as_ref());

    let seconds = time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

    let timestamp = (seconds / TOKEN_VALIDITY).to_be_bytes();
    hasher.update(timestamp.as_slice());

    hasher
}

pub fn check_token(token: &[u8], addr: SocketAddr, target: Id) -> bool {
    let now = SystemTime::now();
    let t1  = gen_token(addr, target, now);
    if t1.verify_slice(token).is_ok() {
        return true;
    }
    let previous = now - Duration::from_secs(TOKEN_VALIDITY);
    let t2 = gen_token(addr, target, previous);

    t2.verify_slice(token).is_ok()
}