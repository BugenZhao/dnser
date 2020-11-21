use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

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
        Self {
            recursion_desired: true,
            authed_data: true,
            ..unsafe { std::mem::zeroed() }
        }
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

    pub fn write(&self, buf: &mut DnsPacketBuf) -> Result<()> {
        buf.write_u16(self.id)?;
        buf.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;
        buf.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;
        buf.write_u16(self.questions)?;
        buf.write_u16(self.answers)?;
        buf.write_u16(self.authoritative_entries)?;
        buf.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, FromPrimitive, ToPrimitive)]
pub enum QueryType {
    Unknown = 0,
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
        let query_type = QueryType::from_u16(query_type_num)
            .or(Some(QueryType::Unknown))
            .unwrap();
        let _class = buf.read_u16()?;
        Ok(DnsQuestion { name, query_type })
    }

    pub fn write(&self, buf: &mut DnsPacketBuf) -> Result<()> {
        buf.write_name_simple(&self.name)?;
        buf.write_u16(self.query_type.to_u16().unwrap())?;
        buf.write_u16(1)?; // class
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DnsRecord {
    Unknown {
        name: String,
        query_type: QueryType,
        data_len: u16,
        ttl: u32,
    },
    A {
        name: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        let name = buf.read_name()?;
        let query_type_num = buf.read_u16()?;
        let query_type = QueryType::from_u16(query_type_num)
            .or(Some(QueryType::Unknown))
            .unwrap();
        let _class = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

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
            QueryType::Unknown => {
                buf.step(data_len as usize);

                Ok(DnsRecord::Unknown {
                    name,
                    query_type,
                    data_len,
                    ttl,
                })
            }
            _ => Err(Error::UnimplementedQueryType(query_type)),
        }
    }

    pub fn write(&self, buf: &mut DnsPacketBuf) -> Result<()> {
        match *self {
            DnsRecord::A {
                ref name,
                ref addr,
                ttl,
            } => {
                buf.write_name_simple(name)?;
                buf.write_u16(QueryType::A.to_u16().unwrap())?;
                buf.write_u16(1)?; // class
                buf.write_u32(ttl)?;
                buf.write_u16(4)?; // data_len

                for &o in &addr.octets() {
                    buf.write_u8(o)?;
                }
            }
            DnsRecord::Unknown { .. } => {
                println!("ignore unknown record: {:?}", self);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        let header = DnsHeader::read_from(buf)?;
        let questions = (0..header.questions)
            .map(|_| DnsQuestion::read_from(buf))
            .collect::<Result<Vec<_>>>()?;
        let answers = (0..header.answers)
            .map(|_| DnsRecord::read_from(buf))
            .collect::<Result<Vec<_>>>()?;
        let authorities = (0..header.authoritative_entries)
            .map(|_| DnsRecord::read_from(buf))
            .collect::<Result<Vec<_>>>()?;
        let resources = (0..header.resource_entries)
            .map(|_| DnsRecord::read_from(buf))
            .collect::<Result<Vec<_>>>()?;

        Ok(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            resources,
        })
    }

    pub fn write(&self, buf: &mut DnsPacketBuf) -> Result<()> {
        self.header.write(buf)?;
        for q in &self.questions {
            q.write(buf)?;
        }
        for r in &self.answers {
            r.write(buf)?;
        }
        for r in &self.authorities {
            r.write(buf)?;
        }
        for r in &self.resources {
            r.write(buf)?;
        }

        Ok(())
    }
}

impl DnsPacket {
    pub fn example(domain: &str) -> Self {
        use rand::Rng;

        let header = DnsHeader {
            id: rand::thread_rng().gen_range(10000, u16::MAX),
            questions: 1,
            ..DnsHeader::default()
        };
        let questions = vec![DnsQuestion {
            name: domain.into(),
            query_type: QueryType::A,
        }];

        Self {
            header,
            questions,
            answers: vec![],
            authorities: vec![],
            resources: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buf;

    lazy_static! {
        static ref RESPONSE_BUF: DnsPacketBuf = buf!("../res/response.bin");
        static ref QUERY_BUF: DnsPacketBuf = buf!("../res/query.bin");
        static ref BUGGY_BUF: DnsPacketBuf = buf!("../res/buggy_jump.bin");
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

    #[test]
    fn test_response_packet() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet);
        assert_eq!(buf.pos, 0x2f);
    }

    #[test]
    fn test_query_packet() {
        let mut buf: DnsPacketBuf = QUERY_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet);
        assert_eq!(buf.pos, 0x1f);
    }

    #[test]
    fn test_buggy_packet() {
        let mut buf: DnsPacketBuf = BUGGY_BUF.clone();
        let packet_result = DnsPacket::read_from(&mut buf);
        assert!(match packet_result.unwrap_err() {
            Error::TooManyJumps(_) => true,
            _ => false,
        })
    }

    #[test]
    fn test_write_query_packet() {
        const DOMAIN: &str = "bugenzhao.com";

        let packet = DnsPacket::example(DOMAIN);
        let mut buf = DnsPacketBuf::new();
        packet.write(&mut buf).unwrap();

        buf.seek(0);
        let packet_parsed = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet_parsed);

        assert_eq!(packet_parsed.questions.first().unwrap().name, DOMAIN);
    }
}
