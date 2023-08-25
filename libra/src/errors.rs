#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid version")]
    InvalidVersion,

    #[error("unknown method")]
    UnknownMethod,

    #[error("no acceptable methods")]
    NoAcceptableMethods,

    #[error("general socks server failure")]
    GeneralSocksServerFailure,

    #[error("connection not allowed by ruleset")]
    ConnectionNotAllowedByRuleset,

    #[error("ttl expired")]
    TtlExpired,

    #[error("command not supported")]
    CommandNotSupported,

    #[error("address type not supported")]
    AddressTypeNotSupported,

    #[error("unknown error")]
    UnknownRep,

    #[error("unauthorized")]
    Unauthorized,

    #[error("io error:{0}")]
    Io(#[from] std::io::Error),
}
