use crate::dns_packet::{DnsPacket, QueryType};
use crate::dns_packet_buf::DnsPacketBuf;
use std::net::UdpSocket;

use crate::error::Result;

pub fn lookup(domain: &str, query_type: QueryType, server: &str) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect(server)?; // into NetworkError

    let packet = DnsPacket::example(domain, query_type);
    let mut send_buf = DnsPacketBuf::new();
    packet.write(&mut send_buf)?;
    socket.send(&send_buf.buf[0..send_buf.pos])?;

    let mut recv_buf = DnsPacketBuf::new();
    let (_, response_server) = socket.recv_from(&mut recv_buf.buf)?;
    let response_packet = DnsPacket::read_from(&mut recv_buf)?;

    println!(
        "Received answer for {} from {} => {:#?}",
        domain, response_server, response_packet
    );

    Ok(response_packet)
}
