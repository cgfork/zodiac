use bytes::{BufMut, BytesMut};
use tokio_util::codec;

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

///  The destination address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DstAddr {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
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
    UserAndPass(String, String),

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
    Command(u8, DstAddr, u16),

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
    Reply(u8, DstAddr, u16),
}

enum CodecState {
    Methods,
    Selection,
    UserAndPass,
    Status,
    Command,
    Reply,
}

pub struct Codec {
    state: CodecState,
}

impl Codec {
    pub(crate) fn set_next_state(&mut self, state: CodecState) {
        self.state = state;
    }
}

impl codec::Decoder for Codec {
    type Item = Item;

    type Error = crate::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            CodecState::Methods => todo!(),
            CodecState::Selection => todo!(),
            CodecState::UserAndPass => todo!(),
            CodecState::Status => todo!(),
            CodecState::Command => todo!(),
            CodecState::Reply => todo!(),
        }
    }
}

impl codec::Encoder<Item> for Codec {
    type Error = crate::Error;

    fn encode(&mut self, item: Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Item::Methods(ms) => {
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(ms.len() as u8);
                dst.put_slice(&ms);
            }
            Item::Selection(m) => {
                dst.put_u8(SOCKS_VERSION);
                dst.put_u8(m);
            }
            Item::UserAndPass(u, p) => {
                dst.put_u8(AUTH_VERSION);
                dst.put_u8(u.len() as u8);
                dst.put_slice(u.as_bytes());
                dst.put_u8(p.len() as u8);
                dst.put_slice(p.as_bytes());
            }
            Item::Status(_) => todo!(),
            Item::Command(_, _, _) => todo!(),
            Item::Reply(_, _, _) => todo!(),
        };
        Ok(())
    }
}
