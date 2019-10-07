extern crate resolve;

use std::env::args;

use resolve::resolve_host;

fn main() {
    let args = args().collect::<Vec<_>>();

    if args.len() == 1 {
        println!("Usage: {} <host name> [...]", args[0]);
        return;
    }

    for arg in &args[1..] {
        match resolve_host(&arg) {
            Ok(mut addrs) => {
                let addr = addrs.next().expect("empty ResolveHost");
                let n = addrs.count();

                if n == 0 {
                    println!("\"{}\" resolved to {}", arg, addr);
                } else {
                    println!("\"{}\" resolved to {} ({} more)", arg, addr, n);
                }
            }
            Err(e) => println!("failed to resolve \"{}\": {}", arg, e),
        }
    }
}
