extern crate resolve;

use std::env::args;

use resolve::resolve_addr;

fn main() {
    let args = args().collect::<Vec<_>>();

    if args.len() == 1 {
        println!("Usage: {} <ip address> [...]", args[0]);
        return;
    }

    for arg in &args[1..] {
        let ip = match arg.parse() {
            Ok(ip) => ip,
            Err(_) => {
                println!("\"{}\" is not a valid IP address", arg);
                continue;
            }
        };

        match resolve_addr(&ip) {
            Ok(name) => {
                println!("{} resolved to \"{}\"", ip, name);
            }
            Err(e) => println!("failed to resolve {}: {}", ip, e)
        }
    }
}
