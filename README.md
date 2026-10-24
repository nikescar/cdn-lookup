# CDN Lookup Tool

A Rust-based CLI tool that identifies which CDN, cloud provider, or network service an IP address belongs to. Automatically downloads and caches IP ranges from 118+ providers, with monthly updates. Fast lookup using efficient CIDR range matching.

## Features

- **118+ Providers**: CDNs, cloud providers, bots, VPNs, threat intelligence feeds
- **Automatic Updates**: Checks provider data monthly, downloads only when changed
- **Git-Based Sources**: Shallow clones for bandwidth efficiency, handles force-pushed histories
- **HTTP Sources**: Uses Last-Modified headers to minimize unnecessary downloads
- **Local Cache**: Stores data in `~/.config/cdn-lookup/` for fast lookups
- **CIDR Matching**: Efficient IP range matching with support for both individual IPs and CIDR blocks

## Installation

```bash
cargo build --release
```

## Usage

Check multiple IP addresses:
```bash
$ cdn-lookup 8.8.8.8 1.1.1.1 104.16.123.96
```

Force immediate provider data refresh (ignores monthly check):
```bash
$ cdn-lookup --refresh 8.8.8.8
```

Check IP addresses from a list (space or newline separated):
```bash
echo "8.8.8.8 1.1.1.1" | xargs cdn-lookup
```

## Output Examples

```bash
$ cdn-lookup 8.8.8.8 104.16.123.96 192.168.1.1
8.8.8.8: Found in googleservices
104.16.123.96: Found in cloudflare
192.168.1.1: -
```

## Supported Providers (118+)

| Category | Providers |
|----------|-----------|
| **CDN (8)** | Akamai, Bunny.net, CacheFly, CDN77, Cloudflare, Fastly, Gcore, QUIC.cloud |
| **Cloud & Hosting (26)** | Alibaba Cloud, Amazon Web Services (AWS), Microsoft Azure, Backblaze, Contabo, DigitalOcean, Fly.io, Gabia, Hetzner, Hostway, Huawei Cloud, IBM Cloud, Leaseweb, Linode, M247, NHN Cloud, Oracle Cloud, OVHcloud, Play2go, Rackspace, Render, Scaleway, Tencent Cloud, UpCloud, Vultr, Wasabi, Yandex Cloud |
| **Crawlers & Bots (13)** | Amazonbot, Anthropic Crawler, Applebot, Common Crawl (CCBot), ClaudeBot, Common Crawl, DuckAssistBot, DuckDuckBot, Googlebot, Google Special Crawlers, Google User-Triggered Fetchers, GPTBot (OpenAI), PerplexityBot |
| **Security (4)** | Imperva, Stormwall, Sucuri, Zscaler |
| **SaaS & Services (16)** | Atlassian, CircleCI, Datadog, Discord, GitHub, GitLab, Google Cloud Services, Intercom, Internet Archive, Meta (Facebook), Microsoft 365, Okta, Salesforce, Stripe, TeamCity, Telegram, Twitter, Zoom, Zoho |
| **Monitoring (15)** | Better Stack, Checkly, Grafana Synthetic Monitoring, HetrixTools, New Relic Synthetics, NodePing, Oh Dear, Pingdom, Sentry Uptime, Site24x7, StatusCake, updown.io, UptimeRobot, Uptrends |
| **Security Scanners (7)** | Detectify, Intruder, Invicti, Qualys, Rapid7 InsightAppSec, Tenable Cloud Scanners, Cortex Xpanse |
| **VPN & Anonymisers (8)** | AirVPN, Apple Private Relay, IVPN, Mullvad, ProtonVPN, Surfshark, Tor Exit Nodes, X4BNet VPN |
| **Threat Intelligence (13)** | Spamhaus ASN-DROP, Binary Defense, Blocklist.de, CINS Army List, Team Cymru Bogons, DShield Recommended Block List, Emerging Threats Compromised IPs, abuse.ch Feodo Tracker, GreenSnow, IPsum, Spamhaus DROP, StopForumSpam, abuse.ch ThreatFox |
| **Other Services (8)** | AhrefsBot, Bingbot, GoCache, Google Cloud Platform |

## How It Works

1. **First Run**: Downloads provider data from git repositories and HTTP sources
2. **Data Processing**: Extracts IP ranges from JSON and plain text formats
3. **Caching**: Stores processed CIDR ranges in `~/.config/cdn-lookup/*.cidr`
4. **Monthly Updates**: Checks provider sources monthly (configurable via timestamps)
5. **Fast Lookup**: Loads all CIDR ranges into memory for instant matching

### Data Sources

- **Git-based**: Clones from GitHub repositories using shallow clones (depth=1)
  - Handles force-pushed histories gracefully
  - Examples: jonhadfield/cloud-ips, rezmoss/cloud-provider-ip-addresses
- **HTTP-based**: Direct downloads with Last-Modified header caching
  - Only downloads when remote data changes

### Configuration

Data stored in `~/.config/cdn-lookup/`:
- `providers.conf` - Provider list with URLs and update timestamps
- `*.cidr` - Cached CIDR ranges per provider
- `repos/` - Cloned git repositories

## Troubleshooting

**No matches found for known IPs**:
```bash
# Force refresh all provider data
cdn-lookup --refresh 1.1.1.1
```

**Git repository errors**:
```bash
# Remove cached repos to force clean clone
rm -rf ~/.config/cdn-lookup/repos
cdn-lookup --refresh <ip>
```

**Clear all cached data**:
```bash
rm -rf ~/.config/cdn-lookup
# Next run will download everything fresh
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
