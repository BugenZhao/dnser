#![allow(dead_code)]

#[cfg_attr(test, macro_use)]
extern crate lazy_static;
#[cfg_attr(dns_packet, macro_use)]
extern crate num_derive;

mod dns_packet;
mod dns_packet_buf;
mod error;
mod utils;

use dns_packet::DnsPacket;
use dns_packet_buf::DnsPacketBuf;
use std::net::UdpSocket;

fn main() {
    let ns_server = ("223.5.5.5", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    socket.connect(ns_server).unwrap();

    let packet = DnsPacket::example("bugen.dev");
    let mut send_buf = DnsPacketBuf::new();
    packet.write(&mut send_buf).unwrap();
    socket.send(&send_buf.buf[0..send_buf.pos]).unwrap();

    let mut recv_buf = DnsPacketBuf::new();
    let (_, _response_server) = socket.recv_from(&mut recv_buf.buf).unwrap();
    let response_packet = DnsPacket::read_from(&mut recv_buf).unwrap();

    println!("Received from {} => {:#?}", _response_server, response_packet);
}
