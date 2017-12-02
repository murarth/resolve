//! Example demonstrating a resolver using custom DNS servers

extern crate resolve;

use std::env::args;

use resolve::{DnsConfig, DnsResolver};

fn main() {
    let config = DnsConfig::with_name_servers(vec![
        // Use Google's public DNS servers instead of the system default.
        "8.8.8.8:53".parse().unwrap(),
        "8.8.4.4:53".parse().unwrap(),
    ]);

    let resolver = match DnsResolver::new(config) {
        Ok(r) => r,
        Err(e) => {
            println!("failed to create DNS resolver: {}", e);
            return;
        }
    };

    let args = args().collect::<Vec<_>>();

    if args.len() == 1 {
        println!("Usage: {} <host name> [...]", args[0]);
        return;
    }

    for arg in &args[1..] {
        match resolver.resolve_host(&arg) {
            Ok(mut addrs) => {
                let addr = addrs.next().expect("empty ResolveHost");
                let n = addrs.count();

                if n == 0 {
                    println!("\"{}\" resolved to {}", arg, addr);
                } else {
                    println!("\"{}\" resolved to {} ({} more)", arg, addr, n);
                }
            }
            Err(e) => println!("failed to resolve \"{}\": {}", arg, e)
        }
    }
}
