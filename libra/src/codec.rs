use std::io;

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{self, Framed};

use crate::errors;

// Socks Allowable Methods
pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
pub const GSSAPI: u8 = 0x01;
pub const USERNAME_AND_PASSWORD: u8 = 0x02;
pub const IANA_ASSIGNED_MIN: u8 = 0x03; // Reserved start
pub const IANA_ASSIGNED_MAX: u8 = 0x7f; // Reserved stop
pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;

// COMMANDs
pub const CONNECT: u8 = 0x01;
pub const BIND: u8 = 0x02;
pub const UDP_ASSOCIATE: u8 = 0x03;

// ADDR TYPEs
pub const DST_IPV4: u8 = 0x01;
pub const DST_DOMAIN: u8 = 0x03;
pub const DST_IPV6: u8 = 0x04;

// RESPONSE CODEs
pub const SUCCEEDED: u8 = 0x00;
pub const GENERAL_SOCKS_SERVER_FAILURE: u8 = 0x01;
pub const CONNNECTION_NOT_ALLOWED_BY_RULESET: u8 = 0x02;
pub const NETWORK_UNREACHABLE: u8 = 0x03;
pub const HOST_UNREACHABLE: u8 = 0x04;
pub const CONNECTION_REFUSED: u8 = 0x05;
pub const TTL_EXPIRED: u8 = 0x06;
pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// Socks Version
pub const SOCKS_VERSION: u8 = 0x05;

// Auth Version
pub const AUTH_VERSION: u8 = 0x01;

// Auth Status
pub const AUTH_SUCCEED: u8 = 0x00;
pub const AUTH_FAILED: u8 = 0x01;

pub(crate) fn rep_str(rep: u8) -> &'static str {
    match rep {
        SUCCEEDED => "succeeded",
        GENERAL_SOCKS_SERVER_FAILURE => "general socks server failure",
        CONNNECTION_NOT_ALLOWED_BY_RULESET => "connection not allowed by ruleset",
        NETWORK_UNREACHABLE => "network unreachable",
        HOST_UNREACHABLE => "host unreachable",
        CONNECTION_REFUSED => "connection refused",
        TTL_EXPIRED => "ttl expired",
        COMMAND_NOT_SUPPORTED => "command not supported",
        ADDRESS_TYPE_NOT_SUPPORTED => "address type not supported",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The client connects to the server, and sends a version
    /// identifier/method selection message:
    ///
    /// +----+----------+----------+
    /// |VER | NMETHODS | METHODS  |
    /// +----+----------+----------+
    /// | 1  |    1     | 1 to 255 |
    /// +----+----------+----------+
    ///
    /// The VER field is set to X05 for this version of the protocol.
    /// The NMETHODS field contains the number of method identifier
    /// octets that appear in the METHODS field.
    Methods(Vec<u8>),

    /// The server selects from one of the METHODS given in the
    /// [`MethodRequest`], and sends a METHOD selection message:
    ///
    /// +----+--------+
    /// |VER | METHOD |
    /// +----+--------+
    /// | 1  |   1    
    /// +----+--------+
    ///
    /// If the selected METHOD is XFF, none of the methods listed by the
    /// client are acceptable, and the client MUST close the connection.
    ///
    /// The values currently defined for METHOD are:
    /// o  X00 NO AUTHENTICATION REQUIRED
    /// o  X01 GSSAPI
    /// o  X02 USERNAME/PASSWORD
    /// o  X03 to X7F IANA ASSIGNED
    /// o  X80 to XFE RESERVED FOR PRIVATE METHODS
    /// o  XFF NO ACCEPTABLE METHODS
    Selection(u8),

    /// The client sends the username and password if the server has selected
    /// the USERNAME/PASSWORD method.
    ///
    /// +----+----------+----------+
    /// |VER | USERNAME | PASSWORD |
    /// +----+----------+----------+
    /// | 1  |  1..255  |  1..255  |
    /// +----+----------+----------+
    ///
    /// The VER field is set to X01 for this version of the AUTHENTICATION.
    /// USERNAME or PASSWORD is a fixed string. The first octet of the field
    /// contains the number of octects of string that follow.
    UsernamePassword(String, String),

    /// The server authenticates the USERNAME and PASSWORD, and sends a
    /// status message:
    ///
    /// +----+--------+
    /// |VER | STATUS |
    /// +----+--------+
    /// | 1  |    1   |
    /// +----+--------+
    ///
    /// The VER field is set to X01 for this version of the AUTHENTICATION.
    Status(u8),

    /// Once the method-dependent subnegotiation has completed, the client
    /// sends the request details.
    ///
    /// +----+-----+-------+------+----------+----------+
    /// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    /// +----+-----+-------+------+----------+----------+
    /// | 1  |  1  |  X00  |  1   | Variable |    2     |
    /// +----+-----+-------+------+----------+----------+
    ///
    /// Where:
    /// o  VER    protocol version: X05
    /// o  CMD
    ///    o  CONNECT X01
    ///    o  BIND X02
    ///    o  UDP ASSOCIATE X03
    /// o  RSV    RESERVED
    /// o  ATYP   address type of following address
    ///    o  IP V4 address: X01
    ///    o  DOMAINNAME: X03
    ///    o  IP V6 address: X04
    /// o  DST.ADDR desired destination address
    /// o  DST.PORT desired destination port in network octet order
    Command(u8, u8, Vec<u8>, u16),

    /// The SOCKS request information is sent by the client as soon as it has
    /// established a connection to the SOCKS server, and completed the
    /// authentication negotiations.  The server evaluates the request, and
    /// returns a reply formed as follows:
    ///
    /// +----+-----+-------+------+----------+----------+
    /// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    /// +----+-----+-------+------+----------+----------+
    /// | 1  |  1  | X00 |  1   | Variable |    2     |
    /// +----+-----+-------+------+----------+----------+
    ///
    /// Where:
    /// o  VER    protocol version: X05
    /// o  REP    Reply field:
    ///    o  X00 succeeded
    ///    o  X01 general SOCKS server failure
    ///    o  X02 connection not allowed by ruleset
    ///    o  X03 Network unreachable
    ///    o  X04 Host unreachable
    ///    o  X05 Connection refused
    ///    o  X06 TTL expired
    ///    o  X07 Command not supported
    ///    o  X08 Address type not supported
    ///    o  X09 to XFF unassigned
    /// o  RSV    RESERVED
    /// o  ATYP   address type of following address
    ///    o  IP V4 address: X01
    ///    o  DOMAINNAME: X03
    ///    o  IP V6 address: X04
    /// o  BND.ADDR       server bound address
    /// o  BND.PORT       server bound port in network octet order
    ///
    /// Fields marked RESERVED (RSV) must be set to X00.
    Reply(u8, u8, Vec<u8>, u16),
}

#[derive(Debug, Clone, Copy)]
pub enum DecoderState {
    Methods,
    Selection,
    UsernamePassword,
    Status,
    Command,
    Reply,
}

pub struct Codec {
    state: DecoderState,
}

impl Codec {
    pub fn new(init: DecoderState) -> Self {
        Self { state: init }
    }

    pub(crate) fn set_next_state(&mut self, state: DecoderState) {
        self.state = state;
    }
}

impl codec::Decoder for Codec {
    type Item = Item;

    type Error = crate::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            DecoderState::Methods => {
                if src.len() < 2 || src[1] as usize > src.len() - 2 {
                    Ok(None)
                } else {
                    assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                    let len = src.get_u8() as usize;
                    let methods = src.split_to(len).to_vec();
                    Ok(Some(Item::Methods(methods)))
                }
            }
            DecoderState::Selection => {
                if src.len() < 2 {
                    Ok(None)
                } else {
                    assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                    Ok(Some(Item::Selection(src.get_u8())))
                }
            }
            DecoderState::UsernamePassword => {
                if src.len() < 2 || src[1] as usize > src.len() - 2 {
                    Ok(None)
                } else {
                    if src[2 + src[1] as usize] as usize + src[1] as usize + 2 > src.len() {
                        return Ok(None);
                    }

                    assert!(src.get_u8() == AUTH_VERSION, "Invalid AUTH version");
                    let len = src.get_u8() as usize;
                    let username = src.split_to(len).to_vec();
                    let len = src.get_u8() as usize;
                    let password = src.split_to(len).to_vec();
                    Ok(Some(Item::UsernamePassword(
                        String::from_utf8(username).expect("Invalid UTF-8"),
                        String::from_utf8(password).expect("Invalid UTF-8"),
                    )))
                }
            }
            DecoderState::Status => {
                if src.len() < 2 {
                    Ok(None)
                } else {
                    assert!(src.get_u8() == AUTH_VERSION, "Invalid AUTH version");
                    Ok(Some(Item::Status(src.get_u8())))
                }
            }
            DecoderState::Command => {
                if src.len() < 4 {
                    Ok(None)
                } else {
                    match src[3] {
                        DST_IPV4 => {
                            if src.len() < 10 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let cmd = src.get_u8();
                                src.advance(2);
                                let dst_addr = src.split_to(4).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Command(cmd, DST_IPV4, dst_addr, dst_port)))
                            }
                        }
                        DST_IPV6 => {
                            if src.len() < 22 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let cmd = src.get_u8();
                                src.advance(2);
                                let dst_addr = src.split_to(16).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Command(cmd, DST_IPV6, dst_addr, dst_port)))
                            }
                        }
                        DST_DOMAIN => {
                            if src.len() < 7 || src[5] as usize > src.len() - 7 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let cmd = src.get_u8();
                                src.advance(2);
                                let len = src.get_u8() as usize;
                                let dst_addr = src.split_to(len).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Command(cmd, DST_DOMAIN, dst_addr, dst_port)))
                            }
                        }
                        _ => Err(crate::Error::AddressTypeNotSupported),
                    }
                }
            }
            DecoderState::Reply => {
                if src.len() < 4 {
                    Ok(None)
                } else {
                    match src[3] {
                        DST_IPV4 => {
                            if src.len() < 10 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let rep = src.get_u8();
                                src.advance(2);
                                let dst_addr = src.split_to(4).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Reply(rep, DST_IPV4, dst_addr, dst_port)))
                            }
                        }
                        DST_IPV6 => {
                            if src.len() < 22 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let rep = src.get_u8();
                                src.advance(2);
                                let dst_addr = src.split_to(16).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Reply(rep, DST_IPV6, dst_addr, dst_port)))
                            }
                        }
                        DST_DOMAIN => {
                            if src.len() < 7 || src[5] as usize > src.len() - 7 {
                                Ok(None)
                            } else {
                                assert!(src.get_u8() == SOCKS_VERSION, "Invalid SOCKS version");
                                let rep = src.get_u8();
                                src.advance(2);
                                let len = src.get_u8() as usize;
                                let dst_addr = src.split_to(len).to_vec();
                                let dst_port = src.get_u16();
                                Ok(Some(Item::Reply(rep, DST_DOMAIN, dst_addr, dst_port)))
                            }
                        }
                        _ => Err(crate::Error::AddressTypeNotSupported),
                    }
                }
            }
        }
    }
}

impl codec::Encoder<Item> for Codec {
    type Error = crate::Error;

    fn encode(&mut self, item: Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Item::Methods(ms) => {
                dst.reserve(ms.len() + 2);
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(ms.len() as u8);
                dst.put_slice(&ms);
            }
            Item::Selection(m) => {
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(m);
            }
            Item::UsernamePassword(u, p) => {
                dst.reserve(3 + u.len() + p.len());
                dst.put_u8(AUTH_VERSION);
                dst.put_u8(u.len() as u8);
                dst.put_slice(u.as_bytes());
                dst.put_u8(p.len() as u8);
                dst.put_slice(p.as_bytes());
            }
            Item::Status(status) => {
                dst.reserve(2);
                dst.put_u8(AUTH_VERSION);
                dst.put_u8(status);
            }
            Item::Command(cmd, atyp, addr, port) => {
                dst.reserve(4);
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(cmd);
                dst.put_u8(0x00);
                dst.put_u8(atyp);
                match atyp {
                    DST_IPV4 => {
                        debug_assert!(addr.len() == 4);
                        dst.reserve(6);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    DST_IPV6 => {
                        debug_assert!(addr.len() == 16);
                        dst.reserve(18);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    DST_DOMAIN => {
                        dst.reserve(3 + addr.len());
                        dst.put_u8(addr.len() as u8);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    _ => return Err(crate::Error::AddressTypeNotSupported),
                }
            }
            Item::Reply(rep, atyp, addr, port) => {
                dst.reserve(4);
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(rep);
                dst.put_u8(0x00);
                dst.put_u8(atyp);
                match atyp {
                    DST_IPV4 => {
                        debug_assert!(addr.len() == 4);
                        dst.reserve(6);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    DST_IPV6 => {
                        debug_assert!(addr.len() == 16);
                        dst.reserve(18);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    DST_DOMAIN => {
                        dst.reserve(3 + addr.len());
                        dst.put_u8(addr.len() as u8);
                        dst.put_slice(&addr);
                        dst.put_u16(port);
                    }
                    _ => return Err(crate::Error::AddressTypeNotSupported),
                }
            }
        };
        Ok(())
    }
}

pub(crate) async fn send_wait<T>(
    frame: &mut Framed<T, Codec>,
    item: Item,
    state: DecoderState,
) -> Result<Item, crate::Error>
where
    T: AsyncWrite + AsyncRead + Unpin,
{
    frame.codec_mut().set_next_state(state);
    frame.send(item).await?;
    if let Some(r) = frame.next().await {
        let r = r?;
        if !matches(state, &r) {
            panic!("unexpected item: {:?}", r);
        }
        Ok(r)
    } else {
        Err(errors::Error::Io(io::ErrorKind::UnexpectedEof.into()))
    }
}

pub(crate) async fn recv<T>(
    frame: &mut Framed<T, Codec>,
    state: DecoderState,
) -> Result<Item, crate::Error>
where
    T: AsyncRead + Unpin,
{
    frame.codec_mut().set_next_state(state);
    if let Some(r) = frame.next().await {
        let r = r?;
        if !matches(state, &r) {
            panic!("unexpected item: {:?}", r);
        }
        Ok(r)
    } else {
        Err(errors::Error::Io(io::ErrorKind::UnexpectedEof.into()))
    }
}

fn matches(state: DecoderState, item: &Item) -> bool {
    matches!(
        (state, item),
        (DecoderState::Methods, Item::Methods(_))
            | (DecoderState::Selection, Item::Selection(_))
            | (DecoderState::UsernamePassword, Item::UsernamePassword(_, _))
            | (DecoderState::Status, Item::Status(_))
            | (DecoderState::Command, Item::Command(_, _, _, _))
            | (DecoderState::Reply, Item::Reply(_, _, _, _))
    )
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use super::{Codec, DecoderState, Item};

    #[test]
    fn test_codec() {
        let item = Item::Methods(vec![1, 2, 3]);
        let mut buf = BytesMut::new();
        let mut codec = Codec::new(DecoderState::Methods);
        codec.encode(item.clone(), &mut buf).unwrap();
        let item1 = codec.decode(&mut buf).unwrap();
        assert_eq!(Some(item), item1);
    }
}
