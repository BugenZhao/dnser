use std::net::Ipv4Addr;

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

#[derive(Copy, Clone, Eq, PartialEq, Debug, FromPrimitive, ToPrimitive)]
pub enum QueryType {
    A = 1,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: QueryType,
}

impl DnsQuestion {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        let name = buf.read_name()?;
        let query_type_num = buf.read_u16()?;
        let query_type =
            QueryType::from_u16(query_type_num).ok_or(Error::InvalidQueryType(query_type_num))?;
        let _class = buf.read_u16()?;
        Ok(DnsQuestion { name, query_type })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DnsRecord {
    A {
        name: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        let name = buf.read_name()?;
        println!("{}", buf.pos);
        let query_type_num = buf.read_u16()?;
        let query_type =
            QueryType::from_u16(query_type_num).ok_or(Error::InvalidQueryType(query_type_num))?;
        let _ = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let _data_len = buf.read_u16()?;

        #[allow(unreachable_patterns)]
        match query_type {
            QueryType::A => {
                let addr = Ipv4Addr::new(
                    buf.read_u8()?,
                    buf.read_u8()?,
                    buf.read_u8()?,
                    buf.read_u8()?,
                );

                Ok(DnsRecord::A { name, addr, ttl })
            }
            _ => Err(Error::UnimplementedQueryType(query_type)),
        }
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
        assert_eq!(buf.pos, 12);
    }

    #[test]
    fn test_query_header() {
        let mut buf: DnsPacketBuf = QUERY_BUF.clone();
        let header = DnsHeader::read_from(&mut buf).unwrap();
        println!("{:?}", header);
        assert_eq!(header.response, false);
        assert_eq!(buf.pos, 12);
    }

    #[test]
    fn test_response_question() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let origin_pos = 12;
        buf.pos = origin_pos;

        let question = DnsQuestion::read_from(&mut buf).unwrap();
        println!("{:?}", question);
        assert_eq!(
            question,
            DnsQuestion {
                name: "416.bugen.dev".into(),
                query_type: QueryType::A,
            }
        );

        assert_eq!(buf.pos, origin_pos + 19);
    }

    #[test]
    fn test_response_answer() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let origin_pos = 0x1f;
        buf.pos = origin_pos;

        let record = DnsRecord::read_from(&mut buf).unwrap();
        println!("{:?}", record);
        assert_eq!(
            record,
            DnsRecord::A {
                name: "416.bugen.dev".into(),
                ttl: 300,
                addr: "59.78.37.159".parse().unwrap()
            }
        );

        assert_eq!(buf.pos, origin_pos + 16);
    }
}
