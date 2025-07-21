# CDN Lookup Tool

A Rust-based command-line tool to check if IP addresses belong to various CDN (Content Delivery Network) providers.

<details markdown>

<summary>Features</summary>

## Features

- Checks IP addresses against multiple CDN provider IP ranges
- Automatically downloads and caches provider IP lists
- Updates provider data monthly
- Supports both individual IP addresses and CIDR ranges
- Fast lookup using efficient IP range matching

## Installation

```bash
cargo build --release
```

## How it works

1. **Configuration**: Creates `~/.config/cdn-lookup/` directory if it doesn't exist
2. **Provider List**: Downloads `providers.conf` from the repository if not present locally
3. **Data Updates**: Checks for updates monthly using HTTP HEAD requests
4. **IP Range Processing**: Downloads and processes IP lists from providers, extracting CIDR ranges and individual IPs
5. **Lookup**: Efficiently matches input IP addresses against cached CIDR ranges
6. **Output**: Reports which CDN providers (if any) contain the queried IP addresses

## Provider Configuration

The `providers.conf` file contains CDN provider definitions in the format:
```
provider_name|url|last_response_timestamp|last_checked_timestamp
```

Example:
```
fastly|https://api.fastly.com/public-ip-list|0|0
cloudflare|https://raw.githubusercontent.com/lord-alfred/ipranges/refs/heads/main/cloudflare/ipv4.txt|0|0
```

## Supported CDN Providers

The tool supports checking against many CDN providers including:
- Fastly
- Cloudflare
- Amazon CloudFront
- Google
- Microsoft
- DigitalOcean
- Oracle
- And many more...

</details>

## Usage

Check multiple IP addresses:
```bash
$ cdn-lookup 8.8.8.8 1.1.1.1 104.16.123.96
```

Check IP addresses from a list (space or newline separated):
```bash
echo "8.8.8.8 1.1.1.1" | xargs cdn-lookup
```

## Output Examples

```bash
$ cdn-lookup 8.8.8.8 104.16.123.96 192.168.1.1
8.8.8.8: Found in google
104.16.123.96: Found in cloudflare
192.168.1.1: -
```
