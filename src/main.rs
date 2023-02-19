#![feature(array_windows)]
#![feature(drain_filter)]
#![feature(hash_drain_filter)]
#![feature(map_first_last)]
#![feature(array_chunks)]
#![feature(let_else)]
#![feature(iter_intersperse)]
#![feature(trait_upcasting)]
#![feature(label_break_value)]
#![feature(try_blocks)]
#![feature(map_try_insert)]
#![feature(ip)]

extern crate core;

use std::net::{UdpSocket, SocketAddr};
use std::error::Error;
use io_uring::{opcode, types, IoUring};
use std::{fs, io};
use serde_derive::{Deserialize, Serialize};
use socket2::{Socket, Domain, Type, SockRef, SockAddr};

mod dht;
mod indexing;
mod fetcher;
mod cli;

use dht::*;
use dht::message::*;
use std::time::Duration;
use std::io::ErrorKind;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use mio::{Events, Token};
use mio::unix::SourceFd;
use crate::cli::Cli;
use crate::fetcher::TorrentFetcher;
use crate::indexing::HashCollector;


fn main() -> Result<(), Box<dyn Error>> {

    std::env::set_var("RUST_BACKTRACE", "1");

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}] {}",
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Trace)
        .chain(fern::log_file("dht.log")?)
        .apply()?;

    let mut dht = Dht::new()?;
    let mut hash_collector = HashCollector::new();

    let crawl_id = Rc::new(AtomicU64::new(0));
    let crawl_id_setter = crawl_id.clone();

    let mut fetcher = TorrentFetcher::new();

    dht.bootstrap(Some(Box::new(move |lookup, dht: &mut Dht| {
        let id = dht.crawl();
        crawl_id_setter.store(id, Ordering::Relaxed);
    })))?;

    let mut events = Events::with_capacity(1024);
    let mut poll = mio::Poll::new()?;

    let stdin_fd = std::io::stdin().as_raw_fd();
    let mut source_fd = SourceFd(&stdin_fd);

    let cli = Cli::new();

    poll.registry().register(dht.socket(), Token(0), mio::Interest::READABLE)?;
    poll.registry().register(&mut source_fd, Token(1), mio::Interest::READABLE)?;


    loop {
        // if the interactions get more complicated we'll need an event/message bus or actor system

        // don't bother with checking poll results, it's just one socket
        dht.network_tick()?;
        // coordinate database with DHT
        hash_collector.update(crawl_id.load(Ordering::Relaxed), &mut dht);
        // coordinate torrent-fetcher with DHT and database
        fetcher.tick(&mut dht, &mut hash_collector, &mut poll);

        cli.tick(&events, &dht);

        // wait on IO or timeout
        match poll.poll(&mut events, Some(Duration::from_millis(200))) {
            Ok(()) => {},
            Err(e) if e.kind() == ErrorKind::Interrupted => {},
            e => e?
        };

        if let Err(e) = dht.tick(&mut poll) {
            eprintln!("error in tick(): {}", e);
        }
    }
}
