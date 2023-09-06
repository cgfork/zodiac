use base64::Engine;
use bytes::BytesMut;
use log::trace;
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};

use crate::{
    codec::{encode_response, parse_request},
    Error,
};

#[derive(Debug, Clone, Default)]
pub struct Builder {
    authorization: Option<String>,
}

impl Builder {
    pub async fn handshake<T>(&self, mut io: T) -> Result<(T, String), Error>
    where
        T: AsyncBufRead + AsyncWrite + Unpin,
    {
        trace!("parse request");
        let mut buf = BytesMut::new();
        if let Some((status, host)) = parse_request(&mut io, self.auth()).await? {
            trace!("encode response");
            encode_response(status, &mut buf);
            io.write_all_buf(&mut buf).await?;
            io.flush().await?;

            if !status.is_success() {
                return Err(Error::HttpStatus(
                    status.canonical_reason().unwrap_or("non canonical reason"),
                ));
            }

            if let Some(host) = host {
                Ok((io, host))
            } else {
                Err(Error::Http("non host"))
            }
        } else {
            Err(Error::Http("non http request"))
        }
    }

    fn auth(&self) -> Option<&str> {
        match &self.authorization {
            Some(s) => Some(s.as_str()),
            None => None,
        }
    }

    pub fn set_authorization(mut self, username: &str, password: &str) -> Self {
        let raw = format!("{}:{}", username, password);
        let mut encoded = String::from("Basic ");
        base64::engine::general_purpose::STANDARD.encode_string(raw.as_bytes(), &mut encoded);
        self.authorization = Some(encoded);
        self
    }
}
