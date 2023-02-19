use std::net::SocketAddr;
use serde_derive::{Deserialize, Serialize};
use serde_bytes::Bytes;
use crate::dht::{VERSION, Id};

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
    #[serde(rename = "q")]
    Request,
    #[serde(rename = "r")]
    Response,
    #[serde(rename = "e")]
    Error,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    #[serde(skip)]
    None,
    FindNode,
    GetPeers,
    SampleInfohashes,
    Ping,
    AnnouncePeer,
    #[serde(other)]
    Unknown,
}

impl QueryType {
    fn none() -> QueryType {
        Self::None
    }

    fn is_none(&self) -> bool {
        *self == QueryType::None
    }
}


#[derive(Serialize, Deserialize, Debug, Default)]
// FIXME handle unknown requests with target field
// #[serde(tag = "q", content = "a")]
pub struct Request<'a> {
    #[serde(with = "serde_bytes")]
    pub id: &'a [u8],
    pub target: Option<&'a serde_bytes::Bytes>,
    pub info_hash: Option<&'a serde_bytes::Bytes>,
    pub port: Option<u16>,
    pub token: Option<&'a serde_bytes::Bytes>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Response<'a> {
    #[serde(with = "serde_bytes")]
    pub id: &'a [u8],
    pub nodes: Option<&'a serde_bytes::Bytes>,
    pub samples: Option<&'a serde_bytes::Bytes>,
    pub token: Option<&'a serde_bytes::Bytes>,
    pub values: Option<&'a serde_bytes::Bytes>,
    pub num: Option<u32>,
    pub interval: Option<u32>,
}

impl<'a> Response<'a> {
    pub fn samples(&self) -> impl Iterator<Item=Id> + '_ {
        self.samples.iter().flat_map(|&bytes| {
            bytes.array_chunks::<20>().map(|chunk| Id(*chunk))
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message<'a> {
    #[serde(rename = "t")]
    #[serde(with = "serde_bytes")]
    pub transaction_id: &'a [u8],
    #[serde(rename = "y")]
    pub message_type: MessageType,
    #[serde(rename = "v")]
    pub version: Option<&'a Bytes>,
    #[serde(rename = "a")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "r")]
    pub response: Option<Response<'a>>,
    #[serde(rename = "q")]
    #[serde(default = "QueryType::none")]
    #[serde(skip_serializing_if = "QueryType::is_none")]
    pub query_type: QueryType,
    #[serde(rename = "ip")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_address: Option<&'a Bytes>,
}

pub enum CompactSockAddr {
    V4([u8; 6]),
    V6([u8; 18]),
}

impl CompactSockAddr {
    pub fn from_sock_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => {
                let mut addr = [0u8; 6];
                addr[0..4].copy_from_slice(&v4.ip().octets());
                addr[4..6].copy_from_slice(&v4.port().to_be_bytes());
                Self::V4(addr)
            }
            SocketAddr::V6(v6) => {
                let mut addr = [0u8; 18];
                addr[0..16].copy_from_slice(&v6.ip().octets());
                addr[16..18].copy_from_slice(&v6.port().to_be_bytes());
                Self::V6(addr)
            }
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            CompactSockAddr::V4(ary) => ary.as_slice(),
            CompactSockAddr::V6(ary) => ary.as_slice()
        }
    }
}