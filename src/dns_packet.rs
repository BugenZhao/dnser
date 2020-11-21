use crate::error::{Error, Result};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::dns_packet_buf::DnsPacketBuf;

#[derive(Copy, Clone, Eq, PartialEq, Debug, FromPrimitive, ToPrimitive)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl Default for DnsHeader {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl DnsHeader {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        let mut h = Self::default();
        h.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        h.recursion_desired = (a & (1 << 0)) > 0;
        h.truncated_message = (a & (1 << 1)) > 0;
        h.authoritative_answer = (a & (1 << 2)) > 0;
        h.opcode = (a >> 3) & 0x0F;
        h.response = (a & (1 << 7)) > 0;

        h.rescode = ResultCode::from_u8(b & 0x0F).ok_or(Error::InvalidResultCode(b & 0x0f))?;
        h.checking_disabled = (b & (1 << 4)) > 0;
        h.authed_data = (b & (1 << 5)) > 0;
        h.z = (b & (1 << 6)) > 0;
        h.recursion_available = (b & (1 << 7)) > 0;

        h.questions = buf.read_u16()?;
        h.answers = buf.read_u16()?;
        h.authoritative_entries = buf.read_u16()?;
        h.resource_entries = buf.read_u16()?;

        // Return the constant header size
        Ok(h)
    }
}

pub fn hello() {
    println!("{:?}", DnsHeader::default());
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buf;

    lazy_static! {
        static ref RESPONSE_BUF: DnsPacketBuf = buf!("../res/response.bin");
        static ref QUERY_BUF: DnsPacketBuf = buf!("../res/query.bin");
    }

    #[test]
    fn test_response_header() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let header = DnsHeader::read_from(&mut buf).unwrap();
        println!("{:?}", header);
        assert!(header.response);
    }

    #[test]
    fn test_query_header() {
        let mut buf: DnsPacketBuf = QUERY_BUF.clone();
        let header = DnsHeader::read_from(&mut buf).unwrap();
        println!("{:?}", header);
        assert_eq!(header.response, false);
    }
}
