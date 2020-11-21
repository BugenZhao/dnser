#![allow(dead_code)]

#[cfg_attr(test, macro_use)]
extern crate lazy_static;
// #[cfg_attr(test, macro_use)]
// mod utils;

#[macro_use]
extern crate num_derive;

mod utils;
mod dns_packet;
mod dns_packet_buf;
mod error;

fn main() {
    println!("Hello, world!");
    dns_packet::hello();
}
