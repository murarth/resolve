extern crate resolve;

use std::env::args;
use std::str;

use resolve::record::Txt;
use resolve::{DnsConfig, DnsResolver};

fn main() {
    let args = args().collect::<Vec<_>>();

    if args.len() != 2 {
        println!("Usage: {} <name>", args[0]);
        println!(" e.g.  {} example.com", args[0]);
        return;
    }

    let config = match DnsConfig::load_default() {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to load system configuration: {}", e);
            return;
        }
    };

    let resolver = match DnsResolver::new(config) {
        Ok(resolver) => resolver,
        Err(e) => {
            println!("Failed to create DNS resolver: {}", e);
            return;
        }
    };

    match resolver.resolve_record::<Txt>(&args[1]) {
        Ok(records) => {
            for txt in records {
                let data = match str::from_utf8(&txt.data) {
                    Ok(string) => string,
                    Err(e) => {
                        println!("Failed to decode UTF8 data: {}", e);
                        return;
                    }
                };
                println!("TXT data={}", data);
            }
        }
        Err(e) => {
            println!("{}", e);
            return;
        }
    }
}
