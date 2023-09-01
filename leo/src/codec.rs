use bytes::{BufMut, BytesMut};
use http::HeaderMap;
use httparse::{Request, Response};
use log::{debug, trace};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::errors::Error;

const LF: u8 = b'\n';

/// The maximum amount of headers parsed on the server.
const MAX_HEADERS: usize = 128;

/// The maximum length of the head section we'll try to parse.
const MAX_HEAD_LENGTH: usize = 8 * 1024;

/// The number returned from httparse when the request is HTTP 1.1
const HTTP_1_1_VERSION: u8 = 1;

pub(crate) async fn parse_request<R>(
    reader: &mut R,
    auth: Option<&str>,
) -> Result<Option<(http::StatusCode, Option<String>)>, Error>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf = Vec::new();
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut httparse_req = Request::new(&mut headers);

    loop {
        let bytes_read = reader.read_until(LF, &mut buf).await?;
        if bytes_read == 0 {
            return Ok(None);
        }

        trace!("read {} bytes, total {} bytes", bytes_read, buf.len());
        assert!(
            buf.len() < MAX_HEAD_LENGTH,
            "Head byte length should be less than 8kb"
        );

        let idx = buf.len() - 1;
        if idx >= 3 && &buf[idx - 3..] == b"\r\n\r\n" {
            break;
        }
    }

    trace!("check parse status");
    let status = httparse_req.parse(&buf)?;
    assert!(!status.is_partial(), "Malformed HTTP head");

    if Some("CONNECT") != httparse_req.method {
        trace!("method is not connect");
        return Ok(Some((http::StatusCode::METHOD_NOT_ALLOWED, None)));
    }

    if Some(HTTP_1_1_VERSION) != httparse_req.version {
        trace!("http version is not 1.1");
        return Ok(Some((http::StatusCode::HTTP_VERSION_NOT_SUPPORTED, None)));
    }

    let proxy_auth = httparse_req
        .headers
        .iter()
        .find(|x| x.name.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|x| std::str::from_utf8(x.value).ok());

    match (proxy_auth, auth) {
        (Some(a), Some(b)) => {
            if a != b {
                return Ok(Some((http::StatusCode::UNAUTHORIZED, None)));
            }
        }
        (None, Some(_)) => {
            return Ok(Some((
                http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                None,
            )));
        }
        (_, None) => {}
    }

    let host = httparse_req
        .headers
        .iter()
        .find(|x| x.name.eq_ignore_ascii_case("host"))
        .and_then(|x| std::str::from_utf8(x.value).ok())
        .map(|v| v.to_string());

    // TODO: Skip body

    Ok(Some((http::StatusCode::OK, host)))
}

pub(crate) async fn parse_response<R>(reader: &mut R) -> Result<Option<http::StatusCode>, Error>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf = Vec::new();
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut httparse_res = Response::new(&mut headers);

    loop {
        let bytes_read = reader.read_until(LF, &mut buf).await?;
        if bytes_read == 0 {
            return Ok(None);
        }

        debug!("read {} bytes, total {} bytes", bytes_read, buf.len());
        assert!(
            buf.len() < MAX_HEAD_LENGTH,
            "Head byte length should be less than 8kb"
        );

        let idx = buf.len() - 1;
        if idx >= 3 && &buf[idx - 3..] == b"\r\n\r\n" {
            break;
        }

        if idx >= 1 && buf[idx - 1..=idx] == [LF, LF] {
            break;
        }
    }

    debug!("check parse status");
    let status = httparse_res.parse(&buf)?;
    assert!(!status.is_partial(), "Malformed HTTP head");

    if Some(HTTP_1_1_VERSION) != httparse_res.version {
        debug!("http version is not 1.1");
        return Ok(None);
    }

    // TODO: Skip body

    let status_code = httparse_res
        .code
        .and_then(|v| http::StatusCode::from_u16(v).ok());
    Ok(status_code)
}

pub(crate) fn encode_request(host: &str, port: u16, headers: &HeaderMap, buf: &mut BytesMut) {
    let request_line = format!("CONNECT {}:{} HTTP/1.1\r\n", host, port);
    buf.reserve(request_line.len());
    buf.put_slice(request_line.as_bytes());
    let host = format!("Host: {}:{}\r\n", host, port);
    buf.reserve(host.len());
    buf.put_slice(host.as_bytes());
    for (k, v) in headers.iter() {
        let name = k.as_str();
        let value = v.as_bytes();
        buf.reserve(name.len() + value.len() + 4);
        buf.put_slice(name.as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value);
        buf.put_slice(b"\r\n");
    }
    buf.reserve(2);
    buf.put_slice(b"\r\n");
}

pub(crate) fn encode_response(status: http::StatusCode, buf: &mut BytesMut) {
    let status_line = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_str(),
        status.canonical_reason().unwrap()
    );
    buf.reserve(status_line.len());
    buf.put_slice(status_line.as_bytes());
    if status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        const STR: &str = "Proxy-Authenticate: Basic realm=Proxy Server\r\n";
        buf.reserve(STR.len());
        buf.put_slice(STR.as_bytes());
    }

    buf.reserve(2);
    buf.put_slice(b"\r\n");
}
