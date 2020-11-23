use crate::dns_packet::{DnsPacket, DnsRecord, QueryType, ResultCode};
use crate::dns_packet_buf::DnsPacketBuf;
use crate::error::{Error, Result};

use async_recursion::async_recursion;
use log::*;
use tokio::net::UdpSocket;

use std::net::Ipv4Addr;

pub async fn lookup(
    domain: &str,
    query_type: QueryType,
    server: (Ipv4Addr, u16),
) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.connect(server).await?; // into NetworkError

    let packet = DnsPacket::example(domain, query_type);
    let mut send_buf = DnsPacketBuf::new();
    packet.write(&mut send_buf)?;
    socket.send(&send_buf.buf[0..send_buf.pos]).await?;

    let mut recv_buf = DnsPacketBuf::new();
    let (_, response_server) = socket.recv_from(&mut recv_buf.buf).await?;
    let response_packet = DnsPacket::read_from(&mut recv_buf)?;

    info!(
        "Received answer for {} from {} => {:#?}",
        domain, response_server, response_packet
    );

    Ok(response_packet)
}

#[async_recursion]
pub async fn recursive_lookup(
    domain: &str,
    query_type: QueryType,
    root_server: (Ipv4Addr, u16),
    depth: u8,
) -> Result<DnsPacket> {
    if depth > 10 {
        return Err(Error::TooManyRecursion(domain.to_owned()));
    }

    let mut ns = root_server.to_owned();
    'outer: loop {
        let response = lookup(domain, query_type, ns).await?;
        match response.header.rescode {
            ResultCode::NXDOMAIN => {
                return Ok(response);
            }
            ResultCode::NOERROR if !response.answers.is_empty() => {
                return Ok(response);
            }
            _ => {
                let nss = response.get_authority_ns(domain);
                // no ns provided
                if nss.is_empty() {
                    return Ok(response);
                }
                // try resolving any ns
                for ns_record in nss.iter() {
                    if let Some(ns_addr) = response.resolve_in_resources(&ns_record.ns_host) {
                        ns = (*ns_addr, 53);
                        continue 'outer;
                    }
                }
                // all ns unresolved, lookup ns
                let recursive_response = recursive_lookup(
                    &nss.first().unwrap().ns_host,
                    QueryType::A,
                    root_server,
                    depth + 1,
                )
                .await?;
                // try using recursive ns addr
                if let Some(DnsRecord::A { addr, .. }) = recursive_response.answers.first() {
                    ns = (*addr, 53);
                    continue 'outer;
                }
            }
        }
    }
}
