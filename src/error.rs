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
    #[error("unknown query `{:?}`", self)]
    UnknownQuery {
        query_type_num: u16,
        name: String,
        data_len: u16,
        ttl: u32,
    },
    #[error("label `{0}` exceeds the length limitation")]
    LabelLengthExceeded(String),
    #[error("too many recursion while looking up `{0}`")]
    TooManyRecursion(String),
    #[error("network error: {0}")]
    NetworkError(#[from] std::io::Error), // thus io::Error can implicitly `into` NetworkError
}
