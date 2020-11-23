use crate::dns_packet::*;
use std::net::Ipv4Addr;

pub struct AuthorityNsRecord {
    pub ns_name: String,
    pub ns_host: String,
}

impl DnsPacket {
    pub fn get_authority_ns(&self, name: &str) -> Vec<AuthorityNsRecord> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS {
                    name: ns_name,
                    host: ns_host,
                    ..
                } if name.ends_with(ns_name) => Some(AuthorityNsRecord {
                    ns_name: ns_name.clone(),
                    ns_host: ns_host.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    pub fn resolve_in_resources(&self, name: &str) -> Option<&Ipv4Addr> {
        for resource in self.resources.iter() {
            match resource {
                DnsRecord::A {
                    name: r_name, addr, ..
                } if name == r_name => return Some(addr),
                _ => {}
            }
        }
        None
    }
}
