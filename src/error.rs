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
}
