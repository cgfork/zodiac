#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid version")]
    InvalidVersion,

    #[error("unknown method")]
    UnknownMethod,

    #[error("no acceptable methods")]
    NoAcceptableMethods,

    #[error("address type not supported")]
    AddressTypeNotSupported,

    #[error("{1}({0})")]
    Rep(u8, &'static str),

    #[error("unknown error")]
    UnknownRep,

    #[error("unauthorized")]
    Unauthorized,

    #[error("io error:{0}")]
    Io(#[from] std::io::Error),

    #[error("unknown")]
    Unknown,
}
