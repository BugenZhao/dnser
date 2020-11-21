use crate::client::lookup;
use crate::dns_packet::{DnsHeader, DnsPacket, QueryType, ResultCode};
use crate::dns_packet_buf::DnsPacketBuf;
use std::net::UdpSocket;

use crate::error::Result;

fn handle_query(socket: &UdpSocket, forward_server: &str) -> Result<()> {
    let mut query_buf = DnsPacketBuf::new();
    let (_, from_addr) = socket.recv_from(&mut query_buf.buf)?;
    let mut query_packet = DnsPacket::read_from(&mut query_buf)?;

    let mut response_packet = DnsPacket {
        header: DnsHeader {
            id: query_packet.header.id,
            recursion_available: true,
            response: true,
            ..DnsHeader::default()
        },
        ..DnsPacket::default()
    };

    // assuming exactly 1 question
    match query_packet.questions.pop() {
        Some(question) => match lookup(&question.name, question.query_type, forward_server) {
            Ok(packet) => {
                let r = &mut response_packet;

                r.questions.push(question);
                r.header.questions = 1;
                r.header.rescode = packet.header.rescode;

                r.answers = packet.answers;
                r.header.answers = r.answers.len() as u16;

                r.authorities = packet.authorities;
                r.header.authoritative_entries = r.authorities.len() as u16;

                r.resources = packet.resources;
                r.header.resource_entries = r.resources.len() as u16;
            }
            _ => response_packet.header.rescode = ResultCode::SERVFAIL,
        },
        None => response_packet.header.rescode = ResultCode::FORMERR,
    }

    let mut response_buf = DnsPacketBuf::new();
    response_packet.write(&mut response_buf)?;

    let len = response_buf.pos;
    socket.send_to(response_buf.peek_range(0, len)?, from_addr)?;
    println!(
        "Sent response to {}: [len={}] {:#?}",
        from_addr, len, response_packet
    );

    Ok(())
}

pub fn run(forward_server: &str, port: u16) -> Result<()> {
    let server_socket = UdpSocket::bind(("0.0.0.0", port))?;
    println!("Running on :{}", port);
    loop {
        match handle_query(&server_socket, forward_server) {
            Ok(_) => {}
            Err(e) => {
                println!("error {}", e);
            }
        };
    }
}
