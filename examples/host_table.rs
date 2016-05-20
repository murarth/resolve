extern crate resolve;

use resolve::hosts::{host_file, load_hosts};

fn main() {
    let path = host_file();

    println!("Loading host table from {}", path.display());
    println!("");

    let table = match load_hosts(&path) {
        Ok(t) => t,
        Err(e) => {
            println!("Failed to load host table: {}", e);
            return;
        }
    };

    for host in &table.hosts {
        println!("  {:<20} points to {}", host.name, host.address);

        for alias in &host.aliases {
            println!("  {:<20} points to {}", alias, host.address);
        }
    }
}
