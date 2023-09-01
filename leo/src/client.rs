use base64::Engine;
use bytes::{Buf, BytesMut};
use http::{header, HeaderMap};
use log::trace;
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt};

use crate::{
    codec::{encode_request, parse_response},
    Error,
};

#[derive(Debug, Clone, Default)]
pub struct Builder {
    authorization: Option<String>,
    destination: Option<(String, u16)>,
}

impl Builder {
    pub async fn handshake<T>(&self, mut io: T) -> Result<T, Error>
    where
        T: AsyncWrite + AsyncBufRead + Unpin,
    {
        let mut buf = BytesMut::new();
        let (host, port) = self
            .destination
            .as_ref()
            .ok_or_else(|| Error::Http("host and port required"))?;
        let mut headers = HeaderMap::new();
        if let Some(auth) = &self.authorization {
            headers.append(header::PROXY_AUTHORIZATION, auth.parse().unwrap());
        }
        trace!("encode request");
        encode_request(host.as_str(), *port, &headers, &mut buf);
        trace!("write {} bytes", buf.remaining(),);
        io.write_all_buf(&mut buf).await?;
        io.flush().await?;
        trace!("parse response");
        let resp = parse_response(&mut io).await?;
        if let Some(status) = resp {
            if status.is_success() {
                Ok(io)
            } else {
                Err(Error::HttpStatus(
                    status.canonical_reason().unwrap_or("non canonical reason"),
                ))
            }
        } else {
            Err(Error::HttpStatus("non status code"))
        }
    }

    pub fn set_authorization(mut self, username: &str, password: &str) -> Self {
        let raw_auth = format!("{}:{}", username, password);
        let mut encoded = String::from("Basic ");
        base64::engine::general_purpose::STANDARD.encode_string(raw_auth.as_bytes(), &mut encoded);
        self.authorization = Some(encoded);
        self
    }

    pub fn set_host_port(mut self, host: String, port: u16) -> Self {
        self.destination = Some((host, port));
        self
    }
}
