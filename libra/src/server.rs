use futures_util::SinkExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::codec::Decoder;

use crate::{
    codec::{
        recv, rep_str, Codec, DecoderState, Item, ADDRESS_TYPE_NOT_SUPPORTED, AUTH_FAILED,
        AUTH_SUCCEED, COMMAND_NOT_SUPPORTED, CONNECT, DST_DOMAIN, DST_IPV4, DST_IPV6,
        HOST_UNREACHABLE, NO_ACCEPTABLE_METHODS, NO_AUTHENTICATION_REQUIRED, SUCCEEDED,
        USERNAME_AND_PASSWORD,
    },
    errors, Destination,
};

#[derive(Debug, Clone, Default)]
pub struct Builder {
    authorization: Option<(String, String)>,
}

impl Builder {
    pub async fn handshake<T>(&self, io: T) -> Result<(TcpStream, T), errors::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
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
        match self.connect(destination.unwrap()).await {
            Ok(stream) => {
                let remote_addr: Destination = stream.peer_addr()?.into();
                let (atyp, addr, port) = remote_addr.into_tuple();
                frame.send(Item::Reply(SUCCEEDED, atyp, addr, port)).await?;
                Ok((stream, frame.into_inner()))
            }
            Err(e) => {
                frame
                    .send(Item::Reply(HOST_UNREACHABLE, DST_IPV4, vec![0, 0, 0, 0], 0))
                    .await?;
                Err(e)
            }
        }
    }

    async fn connect(&self, destination: Destination) -> Result<TcpStream, errors::Error> {
        // TODO: DNS
        Ok(TcpStream::connect(destination.to_string()).await?)
    }
}
