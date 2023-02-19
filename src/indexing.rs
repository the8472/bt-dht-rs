use std::collections::HashSet;
use std::time::SystemTime;
use rusqlite::{params, Connection, Result};
use crate::crawl::Crawl;
use crate::{Dht, Id};

pub struct HashCollector {
    connection: Connection,
}

impl HashCollector {
    pub fn new() -> Self {
        let mut connection = Connection::open("indexer.sqlite").unwrap();

        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous = off;").unwrap();
        connection.execute("
            CREATE TABLE IF NOT EXISTS hashes (
                infohash BLOB PRIMARY KEY  NOT NULL,
                state TEXT  NOT NULL,
                created INTEGER  NOT NULL,
                updated INTEGER  NOT NULL
            )
        ", []).unwrap();

        HashCollector { connection }
    }

    pub fn update(&mut self, crawl_query_id: u64, dht: &mut Dht) {
        if let Some(mut crawl) = dht.get_task::<Crawl>(crawl_query_id) {
            let mut batch = HashSet::new();
            batch.extend(crawl.drain_hashes());

            if batch.len() > 0 {
                let now = SystemTime::now();
                let now = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                let now_kiloseconds = now.as_secs() / 1000;

                let tx = self.connection.transaction().unwrap();

                let mut insert = tx.prepare("
                    INSERT INTO hashes (infohash, state, created, updated) VALUES(?, ?, ?, ?)
                        ON CONFLICT(infohash) DO UPDATE SET updated=excluded.updated
                ").unwrap();

                for hash in batch.drain() {
                    insert.execute(params![hash.0.as_slice(), "initial", now_kiloseconds, now_kiloseconds]).unwrap();
                }

                drop(insert);

                tx.commit().unwrap();
            }
        }
    }

    // /// Grab some torrents from the database, mark them as being-fetched
    // pub fn torrents_to_fetch(&mut self) -> impl Iterator<Item=Id> {
    //     unimplemented!()
    // }
}