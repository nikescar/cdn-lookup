# CDN Lookup Tool

A Rust-based CLI tool that identifies which CDN, cloud provider, or network service an IP address belongs to. Automatically downloads and caches IP ranges from 118+ providers, with monthly updates. Fast lookup using efficient CIDR range matching.

## Features

- 🚀 Fast IP lookup against 118+ provider databases
- 📦 Automatic provider data download and caching
- 🔄 Monthly automatic updates via HTTP HEAD checks
- 🎯 Support for both JSON and plaintext provider formats
- 💾 Cached locally at `~/.config/cdn-lookup/`

## Installation

```bash
cargo build --release
```

## Usage

Check multiple IP addresses:
```bash
$ cdn-lookup 8.8.8.8 1.1.1.1 104.16.123.96
```

Force immediate provider data refresh:
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

<details>
<summary><b>CDN (8)</b></summary>

- Akamai
- Bunny.net
- CacheFly
- CDN77
- Cloudflare
- Fastly
- Gcore
- QUIC.cloud

</details>

<details>
<summary><b>Cloud & Hosting (26)</b></summary>

- Alibaba Cloud
- Amazon Web Services (AWS)
- Microsoft Azure
- Backblaze
- Contabo
- DigitalOcean
- Fly.io
- Gabia
- Hetzner
- Hostway
- Huawei Cloud
- IBM Cloud
- Leaseweb
- Linode
- M247
- NHN Cloud
- Oracle Cloud
- OVHcloud
- Play2go
- Rackspace
- Render
- Scaleway
- Tencent Cloud
- UpCloud
- Vultr
- Wasabi
- Yandex Cloud

</details>

<details>
<summary><b>Crawlers & Bots (13)</b></summary>

- Amazonbot
- Anthropic Crawler
- Applebot
- Common Crawl (CCBot)
- ClaudeBot
- Common Crawl
- DuckAssistBot
- DuckDuckBot
- Googlebot
- Google Special Crawlers
- Google User-Triggered Fetchers
- GPTBot (OpenAI)
- PerplexityBot

</details>

<details>
<summary><b>Security (4)</b></summary>

- Imperva
- Stormwall
- Sucuri
- Zscaler

</details>

<details>
<summary><b>SaaS & Services (16)</b></summary>

- Atlassian
- CircleCI
- Datadog
- Discord
- GitHub
- GitLab
- Google Cloud Services
- Intercom
- Internet Archive
- Meta (Facebook)
- Microsoft 365
- Okta
- Salesforce
- Stripe
- TeamCity
- Telegram
- Twitter
- Zoom
- Zoho

</details>

<details>
<summary><b>Monitoring (15)</b></summary>

- Better Stack
- Checkly
- Grafana Synthetic Monitoring
- HetrixTools
- New Relic Synthetics
- NodePing
- Oh Dear
- Pingdom
- Sentry Uptime
- Site24x7
- StatusCake
- updown.io
- UptimeRobot
- Uptrends

</details>

<details>
<summary><b>Security Scanners (7)</b></summary>

- Detectify
- Intruder
- Invicti
- Qualys
- Rapid7 InsightAppSec
- Tenable Cloud Scanners
- Cortex Xpanse

</details>

<details>
<summary><b>VPN & Anonymisers (8)</b></summary>

- AirVPN
- Apple Private Relay
- IVPN
- Mullvad
- ProtonVPN
- Surfshark
- Tor Exit Nodes
- X4BNet VPN

</details>

<details>
<summary><b>Threat Intelligence (13)</b></summary>

- Spamhaus ASN-DROP
- Binary Defense
- Blocklist.de
- CINS Army List
- Team Cymru Bogons
- DShield Recommended Block List
- Emerging Threats Compromised IPs
- abuse.ch Feodo Tracker
- GreenSnow
- IPsum
- Spamhaus DROP
- StopForumSpam
- abuse.ch ThreatFox

</details>

<details>
<summary><b>Other Services (8)</b></summary>

- AhrefsBot
- Bingbot
- GoCache
- Google Cloud Platform

</details>

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
