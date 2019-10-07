extern crate resolve;

use std::env::args;

use resolve::record::Srv;
use resolve::{DnsConfig, DnsResolver};

fn main() {
    let args = args().collect::<Vec<_>>();

    if args.len() != 4 {
        println!("Usage: {} <service> <proto> <name>", args[0]);
        println!(" e.g.  {} _http _tcp example.com", args[0]);
        return;
    }

    let config = match DnsConfig::load_default() {
        Ok(config) => config,
        Err(e) => {
            println!("failed to load system configuration: {}", e);
            return;
        }
    };

    let resolver = match DnsResolver::new(config) {
        Ok(resolver) => resolver,
        Err(e) => {
            println!("failed to create DNS resolver: {}", e);
            return;
        }
    };

    let name = format!("{}.{}.{}", args[1], args[2], args[3]);

    match resolver.resolve_record::<Srv>(&name) {
        Ok(records) => {
            for srv in records {
                println!(
                    "SRV priority={} weight={} port={} target={}",
                    srv.priority, srv.weight, srv.port, srv.target
                );
            }
        }
        Err(e) => {
            println!("{}", e);
            return;
        }
    }
}
