use crate::client::{lookup, recursive_lookup};
use crate::dns_packet::{DnsHeader, DnsPacket, ResultCode};
use crate::dns_packet_buf::DnsPacketBuf;
use log::*;
use std::{net::Ipv4Addr, sync::Arc};
use tokio::net::UdpSocket;

use crate::error::Result;

async fn handle_query(
    socket: Arc<UdpSocket>,
    mut query_buf: DnsPacketBuf,
    from_addr: std::net::SocketAddr,
    remote_server: (Ipv4Addr, u16),
    proxy: bool,
) -> Result<()> {
    let mut query_packet = DnsPacket::read_from(&mut query_buf)?;

    let mut response_packet = DnsPacket::default();

    // assuming exactly 1 question
    match query_packet.questions.pop() {
        Some(question) => {
            let result = if proxy {
                lookup(&question.name, question.query_type, remote_server).await
            } else {
                recursive_lookup(&question.name, question.query_type, remote_server, 0).await
            };

            match result {
                Ok(packet) if proxy => {
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
                Ok(packet) if !proxy => {
                    response_packet = packet;
                }
                _ => response_packet.header.rescode = ResultCode::SERVFAIL,
            }
        }
        None => response_packet.header.rescode = ResultCode::FORMERR,
    }

    response_packet.header = DnsHeader {
        id: query_packet.header.id,
        recursion_available: true,
        response: true,
        ..response_packet.header
    };

    let mut response_buf = DnsPacketBuf::new();
    response_packet.write(&mut response_buf)?;

    let bytes = response_buf.peek_range(0, response_buf.pos)?;
    socket.send_to(bytes, from_addr).await?;
    info!("Sent response to {}: {:#?}", from_addr, response_packet);

    Ok(())
}

async fn prepare_query(
    socket: Arc<UdpSocket>,
    remote_server: (Ipv4Addr, u16),
    proxy: bool,
) -> Result<()> {
    let mut query_buf = DnsPacketBuf::new();
    let (_, from_addr) = socket.recv_from(&mut query_buf.buf).await?;

    tokio::spawn(async move {
        if let Err(e) = handle_query(socket, query_buf, from_addr, remote_server, proxy).await {
            error!("error {}", e);
        }
    });

    Ok(())
}

pub async fn run(remote_server: (Ipv4Addr, u16), listen_port: u16, proxy: bool) -> Result<()> {
    let server_socket = Arc::new(UdpSocket::bind(("0.0.0.0", listen_port)).await?);
    // let forward_server = Arc::new(forward_server);
    println!("Running on :{}", listen_port);
    loop {
        match prepare_query(server_socket.clone(), remote_server, proxy).await {
            Ok(_) => {}
            Err(e) => {
                error!("error {}", e);
            }
        };
    }
}
