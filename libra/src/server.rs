use std::{io, net::SocketAddr};

use futures_util::{Future, SinkExt};
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
    errors, Destination, Peer,
};

pub trait Connect {
    type Err;
    type Output;
    type Future<'a>: Future<Output = Result<Self::Output, Self::Err>> + Send
    where
        Self: 'a;

    fn connect(&self, destination: Destination) -> Self::Future<'_>;
}

pub struct TokioStream;

impl Connect for TokioStream {
    type Err = io::Error;

    type Output = TcpStream;

    type Future<'a> = impl Future<Output = Result<Self::Output, Self::Err>> + Send + 'a
    where
        Self: 'a;

    fn connect(&self, destination: Destination) -> Self::Future<'_> {
        Box::pin(async move { Ok(TcpStream::connect(destination.to_string()).await?) })
    }
}

#[derive(Debug, Clone)]
pub struct Builder<C> {
    authorization: Option<(String, String)>,
    connect: C,
}

impl<C, O, E> Builder<C>
where
    C: Connect<Output = O, Err = E>,
    O: AsyncRead + AsyncWrite + Unpin + Peer,
    E: Into<errors::Error>,
{
    pub async fn handshake<T>(&self, io: T) -> Result<(T, O), errors::Error>
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
                let remote_addr = stream.remote_addr()?;
                let (atyp, addr, port) = match remote_addr {
                    SocketAddr::V4(v4) => (DST_IPV4, v4.ip().octets().to_vec(), v4.port()),
                    SocketAddr::V6(v6) => (DST_IPV6, v6.ip().octets().to_vec(), v6.port()),
                };
                frame.send(Item::Reply(SUCCEEDED, atyp, addr, port)).await?;
                Ok((frame.into_inner(), stream))
            }
            Err(e) => {
                frame
                    .send(Item::Reply(HOST_UNREACHABLE, DST_IPV4, vec![0, 0, 0, 0], 0))
                    .await?;
                Err(e)
            }
        }
    }

    async fn connect(&self, destination: Destination) -> Result<O, errors::Error> {
        self.connect
            .connect(destination)
            .await
            .map_err(|e| e.into())
    }

    pub fn new(connect: C) -> Self {
        Self {
            authorization: None,
            connect,
        }
    }

    pub fn set_authorization(mut self, username: String, password: String) -> Self {
        self.authorization = Some((username, password));
        self
    }
}
