use std::collections::{HashMap, HashSet};
use mio::net::TcpStream;
use std::thread;
use mio::{Poll, Token};
use crate::{Dht, HashCollector, Id};

pub struct TorrentFetcher {
    connections: HashMap<Token, Peer>,
    torrents: HashMap<Id, Torrent>,
}

struct Torrent {
    infohash: Id,
    connections: HashSet<Token>
}

struct Peer {
    connection: TcpStream,
}

impl TorrentFetcher {
    pub fn new() -> TorrentFetcher {
        TorrentFetcher {
            connections: HashMap::new(),
            torrents: HashMap::new(),
        }
    }

    pub(crate) fn tick(&mut self, dht: &mut Dht, collector: &mut HashCollector, poll: &mut Poll) {
        // collector

    }

}