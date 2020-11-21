use crate::client::lookup;
use crate::dns_packet::{DnsHeader, DnsPacket, ResultCode};
use crate::dns_packet_buf::DnsPacketBuf;
use tokio::net::UdpSocket;

use crate::error::Result;

async fn handle_query(socket: &mut UdpSocket, forward_server: &str) -> Result<()> {
    let mut query_buf = DnsPacketBuf::new();
    let (_, from_addr) = socket.recv_from(&mut query_buf.buf).await?;
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
        Some(question) => match lookup(&question.name, question.query_type, forward_server).await {
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

    let bytes = response_buf.peek_range(0, response_buf.pos)?;
    socket.send_to(bytes, from_addr).await?;
    println!("Sent response to {}: {:#?}", from_addr, response_packet);

    Ok(())
}

pub async fn run(forward_server: &str, port: u16) -> Result<()> {
    let mut server_socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    println!("Running on :{}", port);
    loop {
        match handle_query(&mut server_socket, forward_server).await {
            Ok(_) => {}
            Err(e) => {
                println!("error {}", e);
            }
        };
    }
}