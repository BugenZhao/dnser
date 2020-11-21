#![allow(dead_code)]

#[cfg_attr(test, macro_use)]
extern crate lazy_static;
#[cfg_attr(dns_packet, macro_use)]
extern crate num_derive;

extern crate tokio;

mod client;
mod dns_packet;
mod dns_packet_buf;
mod error;
mod server;
mod utils;

// use dns_packet::QueryType;
use dns_packet::QueryType;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dnser", about = "A DNS utility by Bugen.")]
enum Dnser {
    Client {
        #[structopt(short, long, default_value = "223.5.5.5:53")]
        server: String,
        #[structopt(short, long, possible_values = &QueryType::variants(), case_insensitive = true, default_value = "A")]
        r#type: QueryType,
        #[structopt(default_value = "bugen.dev")]
        domain: String,
    },
    Server {
        #[structopt(
            short,
            long,
            default_value = "223.5.5.5:53",
            help = "The DNS server to proxy"
        )]
        server: String,
        #[structopt(short, long, default_value = "55553")]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    match Dnser::from_args() {
        Dnser::Client {
            server,
            r#type,
            domain,
        } => {
            client::lookup(&domain, r#type, &server).await.unwrap();
        }
        Dnser::Server { server, port } => {
            server::run(server, port).await.unwrap();
        }
    }
}
