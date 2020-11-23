#![allow(dead_code)]

#[cfg_attr(test, macro_use)]
extern crate lazy_static;
#[cfg_attr(dns_packet, macro_use)]
extern crate num_derive;

extern crate async_recursion;
extern crate tokio;

mod client;
mod dns_packet;
mod dns_packet_buf;
mod error;
mod recursive;
mod server;
mod utils;

// use dns_packet::QueryType;
use dns_packet::QueryType;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dnser", about = "A DNS utility by Bugen.")]
enum Dnser {
    Lookup {
        #[structopt(short, long, default_value = "198.41.0.4")]
        server: String,
        #[structopt(short, long, possible_values = &QueryType::variants(), case_insensitive = true, default_value = "A")]
        r#type: QueryType,
        #[structopt()]
        domain: String,
    },
    Server {
        #[structopt(short, long, default_value = "198.41.0.4")]
        server: String,
        #[structopt(long)]
        proxy: bool,
        #[structopt(short, long, default_value = "55553")]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    match Dnser::from_args() {
        Dnser::Lookup {
            server,
            r#type,
            domain,
        } => {
            client::recursive_lookup(&domain, r#type, (server.parse().unwrap(), 53), 0)
                .await
                .unwrap();
        }
        Dnser::Server {
            server,
            port,
            proxy,
        } => {
            server::run((server.parse().unwrap(), 53), port, proxy)
                .await
                .unwrap();
        }
    }
}
