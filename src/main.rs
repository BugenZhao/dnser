#![allow(dead_code)]

#[cfg_attr(test, macro_use)]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;

mod dns_packet;
mod dns_packet_buf;
mod error;
mod utils;

fn main() {
    println!("Hello, world!");
}
