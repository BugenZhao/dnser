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
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dnser", about = "A DNS utility by Bugen.")]
struct Opt {
    #[structopt(short, long, default_value = "bugen.dev")]
    domain: String,
    #[structopt(short, long, default_value = "223.5.5.5:53")]
    server: String,
}

fn main() {
    let opt: Opt = Opt::from_args();
    let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    socket.connect(&opt.server).unwrap();

    let packet = DnsPacket::example(&opt.domain);
    let mut send_buf = DnsPacketBuf::new();
    packet.write(&mut send_buf).unwrap();
    socket.send(&send_buf.buf[0..send_buf.pos]).unwrap();

    let mut recv_buf = DnsPacketBuf::new();
    let (_, response_server) = socket.recv_from(&mut recv_buf.buf).unwrap();
    let response_packet = DnsPacket::read_from(&mut recv_buf).unwrap();

    println!(
        "Received answer for {} from {} => {:#?}",
        opt.domain, response_server, response_packet
    );
}
