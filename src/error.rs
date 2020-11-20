pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("end of buffer at {0}")]
    EndOfBuffer(usize),
    #[error("too many jumps at {0}")]
    TooManyJumps(usize),
}
