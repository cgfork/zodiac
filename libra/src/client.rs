use std::net::SocketAddr;

use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Decoder;

use crate::{
    codec::{
        rep_str, send_wait, Codec, DecoderState, Item, AUTH_SUCCEED, CONNECT,
        NO_AUTHENTICATION_REQUIRED, SUCCEEDED, USERNAME_AND_PASSWORD,
    },
    errors, Destination,
};

#[derive(Debug, Clone, Default)]
pub struct Builder {
    authorization: Option<(String, String)>,
    destination: Option<Destination>,
}

impl Builder {
    pub async fn handshake<T>(&self, io: T) -> Result<T, errors::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let methods = if self.is_auth_enabled() {
            vec![NO_AUTHENTICATION_REQUIRED, USERNAME_AND_PASSWORD]
        } else {
            vec![NO_AUTHENTICATION_REQUIRED]
        };

        let codec = Codec::new(DecoderState::Selection);

        let mut frame = codec.framed(io);
        // Write methods
        if let Item::Selection(selection) = send_wait(
            &mut frame,
            Item::Methods(methods.clone()),
            DecoderState::Selection,
        )
        .await?
        {
            if !methods.contains(&selection) {
                return Err(errors::Error::UnknownMethod);
            }

            if selection == USERNAME_AND_PASSWORD {
                if let Some((username, password)) = &self.authorization {
                    if let Item::Status(status) = send_wait(
                        &mut frame,
                        Item::UsernamePassword(username.clone(), password.clone()),
                        DecoderState::Status,
                    )
                    .await?
                    {
                        if status != AUTH_SUCCEED {
                            return Err(errors::Error::Unauthorized);
                        }
                    }
                } else {
                    return Err(errors::Error::Unauthorized);
                }
            }
        }

        // Write destination
        let (atyp, addr, port) = self.destination.clone().unwrap().into_tuple();
        if let Item::Reply(rep, atyp, host, port) = send_wait(
            &mut frame,
            Item::Command(CONNECT, atyp, addr, port),
            DecoderState::Reply,
        )
        .await?
        {
            debug!("reply with ({:?}, {:?}, {:?}, {:?})", rep, atyp, host, port);
            if rep != SUCCEEDED {
                return Err(errors::Error::Rep(rep, rep_str(rep)));
            }
        }

        Ok(frame.into_inner())
    }

    fn is_auth_enabled(&self) -> bool {
        self.authorization.is_some()
    }

    pub fn set_authorization(mut self, username: String, password: String) -> Self {
        self.authorization = Some((username, password));
        self
    }

    pub fn set_domain(mut self, domain: String, port: u16) -> Self {
        self.destination = Some((domain, port).into());
        self
    }

    pub fn set_addr(mut self, addr: SocketAddr) -> Self {
        self.destination = Some(addr.into());
        self
    }
}

