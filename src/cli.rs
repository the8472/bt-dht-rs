use std::fs::File;
use std::io::{ErrorKind, Read, stdin, StdinLock};
use std::mem::ManuallyDrop;
use std::os::unix::io::{AsRawFd, FromRawFd};
use log::{error, warn};
use mio::{Events, Token};
use nix::fcntl::{F_SETFL, F_SETLK, fcntl, OFlag};
use nix::libc::O_NONBLOCK;
use crate::Dht;

pub struct Cli {}

impl Cli {

    pub fn new() -> Self {
        Cli {}
    }

    pub fn tick(&self, events: &Events, dht: &Dht) {
        if events.iter().all(|e| e.token() != Token(1)) {
            return;
        }

        let mut stdin = stdin().lock();
        fcntl(stdin.as_raw_fd(), F_SETFL(OFlag::from_bits_truncate(O_NONBLOCK))).expect("setting nonblock failed");

        loop {

            let mut buf = [1u8; 1];

            let mut f = ManuallyDrop::new( unsafe {File::from_raw_fd(stdin.as_raw_fd())});

            match f.read(&mut buf) {
                Ok(0) => {
                    eprintln!("EOF from stdin");
                    break;
                },
                Ok(_) => {
                    match buf[0] as char {
                        'r' => dht.print_routing_table(),
                        'l' => dht.print_lookups(),
                        c => eprintln!("command ({}) not supported", c)
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("unexpected std error: {}", e);
                    break;
                }
            }
        }
    }
}