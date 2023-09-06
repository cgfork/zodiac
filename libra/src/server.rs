use std::net::SocketAddr;

use futures_util::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Decoder;

use crate::{
    codec::{
        recv, rep_str, Codec, DecoderState, Item, ADDRESS_TYPE_NOT_SUPPORTED, AUTH_FAILED,
        AUTH_SUCCEED, COMMAND_NOT_SUPPORTED, CONNECT, DST_DOMAIN, DST_IPV4, DST_IPV6,
        NO_ACCEPTABLE_METHODS, NO_AUTHENTICATION_REQUIRED, SUCCEEDED, USERNAME_AND_PASSWORD,
    },
    errors, Destination, Peer,
};

#[derive(Debug, Clone, Default)]
pub struct Builder {
    authorization: Option<(String, String)>,
    bind_addr: Option<SocketAddr>,
}

impl Builder {
    pub async fn handshake<T>(&self, io: T) -> Result<(T, String), errors::Error>
    where
        T: AsyncRead + AsyncWrite + Peer + Unpin,
    {
        let local_addr = io.local_addr()?;
        let mut frame = Codec::new(DecoderState::Methods).framed(io);
        if let Item::Methods(methods) = recv(&mut frame, DecoderState::Methods).await? {
            if let Some((user, pass)) = &self.authorization {
                if methods.contains(&USERNAME_AND_PASSWORD) {
                    frame.send(Item::Selection(USERNAME_AND_PASSWORD)).await?;
                    if let Item::UsernamePassword(u, p) =
                        recv(&mut frame, DecoderState::UsernamePassword).await?
                    {
                        if user == &u && pass == &p {
                            frame.send(Item::Status(AUTH_SUCCEED)).await?;
                        } else {
                            frame.send(Item::Status(AUTH_FAILED)).await?;
                            return Err(errors::Error::Unauthorized);
                        }
                    }
                } else {
                    frame.send(Item::Selection(NO_ACCEPTABLE_METHODS)).await?;
                    return Err(errors::Error::UnknownMethod);
                }
            } else {
                frame
                    .send(Item::Selection(NO_AUTHENTICATION_REQUIRED))
                    .await?;
            }
        }

        let mut destination = None;

        if let Item::Command(cmd, atyp, host, port) =
            recv(&mut frame, DecoderState::Command).await?
        {
            if cmd != CONNECT {
                frame
                    .send(Item::Reply(
                        COMMAND_NOT_SUPPORTED,
                        DST_IPV4,
                        vec![0, 0, 0, 0],
                        0,
                    ))
                    .await?;
                return Err(errors::Error::Rep(
                    COMMAND_NOT_SUPPORTED,
                    rep_str(COMMAND_NOT_SUPPORTED),
                ));
            }

            match atyp {
                DST_IPV4 | DST_IPV6 | DST_DOMAIN => {
                    destination = Some(Destination::new(atyp, host, port));
                }
                _ => {
                    frame
                        .send(Item::Reply(
                            ADDRESS_TYPE_NOT_SUPPORTED,
                            DST_IPV4,
                            vec![0, 0, 0, 0],
                            0,
                        ))
                        .await?;
                    return Err(errors::Error::AddressTypeNotSupported);
                }
            }
        }

        let bnd_addr = if let Some(addr) = self.bind_addr.clone() {
            addr
        } else {
            local_addr
        };

        let (atyp, addr, port) = match bnd_addr {
            SocketAddr::V4(v4) => (DST_IPV4, v4.ip().octets().to_vec(), v4.port()),
            SocketAddr::V6(v6) => (DST_IPV6, v6.ip().octets().to_vec(), v6.port()),
        };

        frame.send(Item::Reply(SUCCEEDED, atyp, addr, port)).await?;
        Ok((frame.into_inner(), destination.unwrap().to_string()))
    }

    pub fn set_authorization(mut self, username: String, password: String) -> Self {
        self.authorization = Some((username, password));
        self
    }

    pub fn set_bnd_addr(mut self, bind: SocketAddr) -> Self {
        self.bind_addr = Some(bind);
        self
    }
}
