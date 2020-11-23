use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("end of buffer at {0}")]
    EndOfBuffer(usize),
    #[error("too many jumps at {0}")]
    TooManyJumps(usize),
    #[error("invalid result code `{0}`")]
    InvalidResultCode(u8),
    #[error("invalid query type `{0}`")]
    InvalidQueryType(u16),
    #[error("unimplemented query type `{0:?}`")]
    UnimplementedQueryType(crate::dns_packet::QueryType),
    #[error("label `{0}` exceeds the length limitation")]
    LabelLengthExceeded(String),
    #[error("too many recursion while looking up `{0}`")]
    TooManyRecursion(String),
    #[error("network error: {0}")]
    NetworkError(#[from] std::io::Error), // thus io::Error can implicitly `into` NetworkError
}
