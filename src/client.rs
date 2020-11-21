use crate::dns_packet::{DnsPacket, QueryType};
use crate::dns_packet_buf::DnsPacketBuf;
use std::net::UdpSocket;

use crate::error::Result;

pub fn lookup(domain: &str, query_type: QueryType, server: &str) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    socket.connect(server).unwrap();

    let packet = DnsPacket::example(domain, query_type);
    let mut send_buf = DnsPacketBuf::new();
    packet.write(&mut send_buf).unwrap();
    socket.send(&send_buf.buf[0..send_buf.pos]).unwrap();

    let mut recv_buf = DnsPacketBuf::new();
    let (_, response_server) = socket.recv_from(&mut recv_buf.buf).unwrap();
    let response_packet = DnsPacket::read_from(&mut recv_buf).unwrap();

    println!(
        "Received answer for {} from {} => {:#?}",
        domain, response_server, response_packet
    );

    Ok(response_packet)
}
