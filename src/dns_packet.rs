use clap::arg_enum;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::net::{Ipv4Addr, Ipv6Addr};

use log::*;

use crate::dns_packet_buf::DnsPacketBuf;
use crate::error::{Error, Result};

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

arg_enum! {
    #[derive(Copy, Clone, Eq, PartialEq, Debug, FromPrimitive, ToPrimitive)]
    pub enum QueryType {
        Unknown = 0,
        A = 1,
        NS = 2,
        CNAME = 5,
        MX = 15,
        AAAA = 28,
    }
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
    A {
        name: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        name: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        name: String,
        host: String,
        ttl: u32,
    },
    MX {
        name: String,
        preference: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        name: String,
        addr: Ipv6Addr,
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
            QueryType::NS => {
                let host = buf.read_name()?;

                Ok(DnsRecord::NS { name, host, ttl })
            }
            QueryType::CNAME => {
                let host = buf.read_name()?;

                Ok(DnsRecord::CNAME { name, host, ttl })
            }
            QueryType::MX => {
                let preference = buf.read_u16()?;
                let host = buf.read_name()?;

                Ok(DnsRecord::MX {
                    name,
                    preference,
                    host,
                    ttl,
                })
            }
            QueryType::AAAA => {
                let addr = Ipv6Addr::new(
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                    buf.read_u16()?,
                );

                Ok(DnsRecord::AAAA { name, addr, ttl })
            }
            _ => {
                buf.step(data_len as usize);

                Err(Error::UnknownQuery {
                    query_type_num,
                    name,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buf: &mut DnsPacketBuf) -> Result<()> {
        macro_rules! write_host_name {
            ($host:ident) => {
                let data_len_pos = buf.pos;
                buf.write_u16(0)?; // temp data_len
                buf.write_name_simple($host)?;

                let data_len = buf.pos - data_len_pos - 2;
                buf.set_u16(data_len_pos, data_len as u16)?;
            };
            ($host:ident, $preference:ident) => {
                let data_len_pos = buf.pos;
                buf.write_u16(0)?; // temp data_len
                buf.write_u16($preference)?;
                buf.write_name_simple($host)?;

                let data_len = buf.pos - data_len_pos - 2;
                buf.set_u16(data_len_pos, data_len as u16)?;
            };
        }

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
            DnsRecord::NS {
                ref name,
                ref host,
                ttl,
            } => {
                buf.write_name_simple(name)?;
                buf.write_u16(QueryType::NS.to_u16().unwrap())?;
                buf.write_u16(1)?; // class
                buf.write_u32(ttl)?;

                write_host_name!(host);
            }
            DnsRecord::CNAME {
                ref name,
                ref host,
                ttl,
            } => {
                buf.write_name_simple(name)?;
                buf.write_u16(QueryType::CNAME.to_u16().unwrap())?;
                buf.write_u16(1)?; // class
                buf.write_u32(ttl)?;

                write_host_name!(host);
            }
            DnsRecord::MX {
                ref name,
                preference,
                ref host,
                ttl,
            } => {
                buf.write_name_simple(name)?;
                buf.write_u16(QueryType::MX.to_u16().unwrap())?;
                buf.write_u16(1)?; // class
                buf.write_u32(ttl)?;

                write_host_name!(host, preference);
            }
            DnsRecord::AAAA {
                ref name,
                ref addr,
                ttl,
            } => {
                buf.write_name_simple(name)?;
                buf.write_u16(QueryType::AAAA.to_u16().unwrap())?;
                buf.write_u16(1)?; // class
                buf.write_u32(ttl)?;

                buf.write_u16(16)?; // data_len
                for &o in &addr.segments() {
                    buf.write_u16(o)?;
                }
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

impl Default for DnsPacket {
    fn default() -> Self {
        DnsPacket {
            header: DnsHeader::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }
}

impl DnsPacket {
    pub fn read_from(buf: &mut DnsPacketBuf) -> Result<Self> {
        macro_rules! fill {
            ($type:ident, $count:expr) => {{
                let mut results = Vec::new();
                for _ in 0..($count) {
                    let result = $type::read_from(buf);
                    match result {
                        Ok(r) => results.push(r),
                        Err(e @ Error::UnknownQuery { .. }) => {
                            // ignore this error
                            warn!("unknown query in parsing: {}", e);
                        }
                        Err(e) => {
                            // critical
                            return Err(e);
                        }
                    }
                }
                results
            }};
        };

        let header = DnsHeader::read_from(buf)?;
        let questions = fill!(DnsQuestion, header.questions);
        let answers = fill!(DnsRecord, header.answers);
        let authorities = fill!(DnsRecord, header.authoritative_entries);
        let resources = fill!(DnsRecord, header.resource_entries);

        Ok(DnsPacket {
            header: DnsHeader {
                questions: questions.len() as u16,
                answers: answers.len() as u16,
                authoritative_entries: authorities.len() as u16,
                resource_entries: resources.len() as u16,
                ..header
            },
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
    pub fn example(domain: &str, query_type: QueryType) -> Self {
        use rand::Rng;

        let header = DnsHeader {
            id: rand::thread_rng().gen_range(10000, u16::MAX),
            questions: 1,
            ..DnsHeader::default()
        };
        let questions = vec![DnsQuestion {
            name: domain.into(),
            query_type: query_type,
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
    fn read_response_header() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let header = DnsHeader::read_from(&mut buf).unwrap();
        println!("{:?}", header);
        assert!(header.response);
        assert_eq!(buf.pos, 12);
    }

    #[test]
    fn read_query_header() {
        let mut buf: DnsPacketBuf = QUERY_BUF.clone();
        let header = DnsHeader::read_from(&mut buf).unwrap();
        println!("{:?}", header);
        assert_eq!(header.response, false);
        assert_eq!(buf.pos, 12);
    }

    #[test]
    fn read_response_question() {
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
    fn read_response_answer() {
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
    fn read_response_packet() {
        let mut buf: DnsPacketBuf = RESPONSE_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet);
        assert_eq!(buf.pos, 0x2f);
    }

    #[test]
    fn read_query_packet() {
        let mut buf: DnsPacketBuf = QUERY_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet);
        assert_eq!(buf.pos, 0x1f);
    }

    #[test]
    fn read_buggy_packet() {
        let mut buf: DnsPacketBuf = BUGGY_BUF.clone();
        let packet_result = DnsPacket::read_from(&mut buf);
        assert!(match packet_result.unwrap_err() {
            Error::TooManyJumps(_) => true,
            _ => false,
        })
    }

    #[test]
    fn write_query_packet() {
        const DOMAIN: &str = "bugenzhao.com";

        let packet = DnsPacket::example(DOMAIN, QueryType::A);
        let mut buf = DnsPacketBuf::new();
        packet.write(&mut buf).unwrap();

        buf.seek(0);
        let packet_parsed = DnsPacket::read_from(&mut buf).unwrap();
        println!("{:#?}", packet_parsed);

        assert_eq!(packet_parsed.questions.first().unwrap().name, DOMAIN);
    }

    lazy_static! {
        static ref RESPONSE_NS_BUF: DnsPacketBuf = buf!("../res/response_ns.bin");
        static ref RESPONSE_MX_BUF: DnsPacketBuf = buf!("../res/response_mx.bin");
    }

    #[test]
    fn write_response_ns_packet() {
        let mut buf: DnsPacketBuf = RESPONSE_NS_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();

        let mut write_buf = DnsPacketBuf::new();
        packet.write(&mut write_buf).unwrap();
        write_buf.seek(0);

        let read_back_packet = DnsPacket::read_from(&mut write_buf).unwrap();
        println!("{:#?}", read_back_packet);

        assert!(match read_back_packet.answers.first() {
            Some(DnsRecord::NS { host, .. }) => host == "ns2.google.com",
            _ => false,
        });
    }

    #[test]
    fn write_response_mx_packet() {
        let mut buf: DnsPacketBuf = RESPONSE_MX_BUF.clone();
        let packet = DnsPacket::read_from(&mut buf).unwrap();

        let mut write_buf = DnsPacketBuf::new();
        packet.write(&mut write_buf).unwrap();
        write_buf.seek(0);

        let read_back_packet = DnsPacket::read_from(&mut write_buf).unwrap();
        println!("{:#?}", read_back_packet);

        assert!(match read_back_packet.answers.first() {
            Some(DnsRecord::MX {
                host, preference, ..
            }) => host == "mxbiz1.qq.com" && *preference == 5,
            _ => false,
        });
    }
}
