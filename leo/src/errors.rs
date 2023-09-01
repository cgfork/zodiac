use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("http parse error: {0}")]
    Httparse(#[from] httparse::Error),

    #[error("http status: {0}")]
    HttpStatus(&'static str),

    #[error("http error: {0}")]
    Http(&'static str),
}
