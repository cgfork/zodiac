#![feature(slice_as_chunks)]
#![feature(impl_trait_in_assoc_type)]
#![allow(dead_code)]
pub mod client;

mod codec;

mod errors;
pub mod server;
pub use errors::Error;
use tokio::net::TcpStream;

use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

pub trait Peer {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn remote_addr(&self) -> io::Result<SocketAddr>;

    fn peer_addr(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        Ok((self.local_addr()?, self.remote_addr()?))
    }
}

impl Peer for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

impl Peer for std::net::TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        std::net::TcpStream::local_addr(self)
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        std::net::TcpStream::peer_addr(self)
    }
}

#[cfg(feature = "tokio-native-tls")]
impl<T> Peer for tokio_native_tls::TlsStream<T>
where
    T: Peer,
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().get_ref().get_ref().local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().get_ref().get_ref().remote_addr()
    }
}

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

    pub fn is_socket_addr(&self) -> bool {
        self.aty == DST_IPV4 || self.aty == DST_IPV6
    }

    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self.aty {
            DST_IPV4 => {
                debug_assert!(self.host.len() >= 4, "invalid ipv4");
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(self.host[0], self.host[1], self.host[2], self.host[3]),
                    self.port,
                )))
            }
            DST_IPV6 => {
                debug_assert!(self.host.len() >= 16, "invalid ipv6");
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(self.host.as_chunks().0[0]),
                    self.port,
                    0,
                    0,
                )))
            }
            _ => None,
        }
    }

    pub fn host(&self) -> Option<&str> {
        if let Ok(v) = std::str::from_utf8(&self.host) {
            Some(v)
        } else {
            None
        }
    }

    pub fn port(&self) -> u16 {
        self.port
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
