#[macro_export]
macro_rules! buf {
    ($path:literal) => {
        DnsPacketBuf::from_bytes(include_bytes!($path))
    };
}
