use clap::Parser;
use cdn_lookup::{CdnLookup, run_cdn_lookup};

#[derive(Parser)]
#[command(name = "cdn-lookup")]
#[command(about = "A tool to check if IP addresses belong to CDN providers")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// IP addresses to check, separated by spaces
    ip_addresses: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    if cli.ip_addresses.is_empty() {
        eprintln!("Error: At least one IP address must be provided");
        std::process::exit(1);
    }

    // Parse all IP addresses from arguments (including space and newline separated)
    let mut all_ips = Vec::new();
    for arg in cli.ip_addresses {
        // Split by whitespace and newlines
        for ip in arg.split_whitespace() {
            if !ip.is_empty() {
                all_ips.push(ip.to_string());
            }
        }
    }

    let mut cdn_lookup = CdnLookup::new()?;
    run_cdn_lookup(&mut cdn_lookup, &all_ips)?;

    Ok(())
}
