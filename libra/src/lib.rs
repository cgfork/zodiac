#![feature(slice_as_chunks)]
pub mod client;

mod codec;

mod errors;
pub mod server;
pub use errors::Error;

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use codec::{DST_DOMAIN, DST_IPV4, DST_IPV6};
#[derive(Debug, Clone)]
pub struct Destination {
    aty: u8,
    host: Vec<u8>,
    port: u16,
}

impl Default for Destination {
    fn default() -> Self {
        Self {
            aty: DST_IPV4,
            host: vec![127, 0, 0, 1],
            port: 1080,
        }
    }
}

impl Destination {
    pub fn new(aty: u8, host: Vec<u8>, port: u16) -> Self {
        Self { aty, host, port }
    }

    pub fn into_tuple(self) -> (u8, Vec<u8>, u16) {
        (self.aty, self.host, self.port)
    }
}

impl From<(u8, Vec<u8>, u16)> for Destination {
    fn from(value: (u8, Vec<u8>, u16)) -> Self {
        Self::new(value.0, value.1, value.2)
    }
}

impl From<SocketAddrV4> for Destination {
    fn from(value: SocketAddrV4) -> Self {
        Self::new(DST_IPV4, value.ip().octets().to_vec(), value.port())
    }
}

impl From<SocketAddrV6> for Destination {
    fn from(value: SocketAddrV6) -> Self {
        Self::new(DST_IPV6, value.ip().octets().to_vec(), value.port())
    }
}

impl From<SocketAddr> for Destination {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(v4) => v4.into(),
            SocketAddr::V6(v6) => v6.into(),
        }
    }
}

impl From<(String, u16)> for Destination {
    fn from(value: (String, u16)) -> Self {
        Self::new(DST_DOMAIN, value.0.into_bytes(), value.1)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.aty {
            DST_IPV4 => SocketAddrV4::new(
                Ipv4Addr::new(self.host[0], self.host[1], self.host[2], self.host[3]),
                self.port,
            )
            .fmt(f),
            DST_IPV6 => SocketAddrV6::new(
                Ipv6Addr::from(self.host.as_chunks::<16>().0[0]),
                self.port,
                0,
                0,
            )
            .fmt(f),
            DST_DOMAIN => {
                let domain = String::from_utf8_lossy(&self.host);
                write!(f, "{}:{}", domain, self.port)
            }
            _ => unreachable!(),
        }
    }
}
