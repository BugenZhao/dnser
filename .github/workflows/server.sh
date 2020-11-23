#!/usr/bin/bash
cargo run -- server &
dig +time=5 @127.0.0.1 -p 55553 bugen.dev -t A && (killall dnser || true)
