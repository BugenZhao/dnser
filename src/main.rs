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

use dns_packet::QueryType;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dnser", about = "A DNS utility by Bugen.")]
struct Opt {
    #[structopt(default_value = "bugen.dev")]
    domain: String,
    #[structopt(short, long, default_value = "223.5.5.5:53")]
    server: String,
    #[structopt(short, long, possible_values = &QueryType::variants(), case_insensitive = true, default_value = "A")]
    r#type: QueryType,
}

#[tokio::main]
async fn main() {
    let opt: Opt = Opt::from_args();
    server::run(&opt.server, 55553).await.unwrap();
}
