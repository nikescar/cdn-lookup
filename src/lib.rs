use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::DateTime;
use ipnet::IpNet;
use regex::Regex;

const PROVIDERS_URL: &str = "https://raw.githubusercontent.com/nikescar/cdn-lookup/refs/heads/main/providers.conf";
const ONE_MONTH_SECONDS: u64 = 30 * 24 * 60 * 60; // 30 days in seconds

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub url: String,
    pub last_response_timestamp: u64,
    pub last_checked_timestamp: u64,
}

impl Provider {
    pub fn from_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 4 {
            anyhow::bail!("Invalid provider line format: {}", line);
        }

        Ok(Provider {
            name: parts[0].to_string(),
            url: parts[1].to_string(),
            last_response_timestamp: parts[2].parse()?,
            last_checked_timestamp: parts[3].parse()?,
        })
    }

    pub fn to_line(&self) -> String {
        format!("{}|{}|{}|{}", self.name, self.url, self.last_response_timestamp, self.last_checked_timestamp)
    }
}

pub struct CdnLookup {
    config_dir: PathBuf,
    providers: Vec<Provider>,
    ip_ranges: HashMap<String, Vec<IpNet>>,
}

impl CdnLookup {
    pub fn new() -> Result<Self> {
        let config_dir = Self::get_config_dir()?;
        let providers = Self::load_providers(&config_dir)?;

        Ok(Self {
            config_dir,
            providers,
            ip_ranges: HashMap::new(),
        })
    }

    fn get_config_dir() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        let config_dir = PathBuf::from(home).join(".config").join("cdn-lookup");
        
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .context("Failed to create config directory")?;
        }

        Ok(config_dir)
    }

    fn load_providers(config_dir: &PathBuf) -> Result<Vec<Provider>> {
        let providers_file = config_dir.join("providers.conf");
        
        // Download providers.conf if it doesn't exist
        if !providers_file.exists() {
            println!("Downloading providers.conf...");
            let response = minreq::get(PROVIDERS_URL).send()?;
            let content = response.as_str()?;
            
            let mut file = fs::File::create(&providers_file)?;
            file.write_all(content.as_bytes())?;
        }

        // Read and parse providers.conf
        let content = fs::read_to_string(&providers_file)?;
        let mut providers = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                providers.push(Provider::from_line(line)?);
            }
        }

        Ok(providers)
    }

    pub fn update_providers(&mut self) -> Result<()> {
        let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut updated = false;
        let mut downloads = Vec::new();

        // First pass: collect data to download
        for provider in &mut self.providers {
            let should_check_remote = current_timestamp - provider.last_checked_timestamp > ONE_MONTH_SECONDS;
            
            if should_check_remote {
                println!("Checking {} for updates...", provider.name);
                
                // HEAD request to check Last-Modified
                match minreq::head(&provider.url).send() {
                    Ok(response) => {
                        let remote_timestamp = if let Some(last_modified) = response.headers.get("last-modified") {
                            if let Ok(datetime) = DateTime::parse_from_rfc2822(last_modified) {
                                datetime.timestamp() as u64
                            } else {
                                current_timestamp
                            }
                        } else {
                            current_timestamp
                        };

                        if remote_timestamp > provider.last_response_timestamp {
                            println!("Downloading updated data for {}...", provider.name);
                            if let Ok(response) = minreq::get(&provider.url).send() {
                                if let Ok(content) = response.as_str() {
                                    downloads.push((provider.name.clone(), content.to_string()));
                                    provider.last_response_timestamp = remote_timestamp;
                                    updated = true;
                                }
                            }
                        }
                        provider.last_checked_timestamp = current_timestamp;
                    }
                    Err(e) => {
                        eprintln!("Failed to check {}: {}", provider.name, e);
                        provider.last_checked_timestamp = current_timestamp;
                    }
                }
            } else {
                // Update last checked timestamp without downloading
                provider.last_checked_timestamp = current_timestamp;
            }
        }

        // Second pass: process downloaded data
        for (provider_name, content) in downloads {
            self.process_provider_data(&provider_name, &content)?;
        }

        if updated {
            self.save_providers()?;
        }

        Ok(())
    }

    fn process_provider_data(&self, provider_name: &str, content: &str) -> Result<()> {
        let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")?;
        let cidr_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b")?;
        
        let mut cidrs = Vec::new();

        // Extract CIDR ranges
        for cap in cidr_regex.find_iter(content) {
            if let Ok(cidr) = cap.as_str().parse::<IpNet>() {
                cidrs.push(cidr);
            }
        }

        // Extract individual IPs and convert to /32 CIDR
        for cap in ip_regex.find_iter(content) {
            let ip_str = cap.as_str();
            if !cidr_regex.is_match(&format!("{}/", ip_str)) { // Skip if already part of CIDR
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if let Ok(cidr) = format!("{}/32", ip).parse::<IpNet>() {
                        cidrs.push(cidr);
                    }
                }
            }
        }

        // Save to file
        let cidr_file = self.config_dir.join(format!("{}.cidr", provider_name));
        let mut file = fs::File::create(&cidr_file)?;
        for cidr in &cidrs {
            writeln!(file, "{}", cidr)?;
        }

        println!("Processed {} CIDR ranges for {}", cidrs.len(), provider_name);
        Ok(())
    }

    fn save_providers(&self) -> Result<()> {
        let providers_file = self.config_dir.join("providers.conf");
        let mut file = fs::File::create(&providers_file)?;
        
        for provider in &self.providers {
            writeln!(file, "{}", provider.to_line())?;
        }

        Ok(())
    }

    pub fn load_all_cidr_ranges(&mut self) -> Result<()> {
        self.ip_ranges.clear();

        for entry in fs::read_dir(&self.config_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "cidr" {
                    if let Some(filename) = path.file_stem() {
                        if let Some(provider_name) = filename.to_str() {
                            let content = fs::read_to_string(&path)?;
                            let mut ranges = Vec::new();
                            
                            for line in content.lines() {
                                let line = line.trim();
                                if !line.is_empty() {
                                    if let Ok(cidr) = line.parse::<IpNet>() {
                                        ranges.push(cidr);
                                    }
                                }
                            }
                            
                            self.ip_ranges.insert(provider_name.to_string(), ranges);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_ip(&self, ip_str: &str) -> Vec<String> {
        let ip = match IpAddr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => return Vec::new(),
        };

        let mut matches = Vec::new();

        for (provider_name, ranges) in &self.ip_ranges {
            for range in ranges {
                if range.contains(&ip) {
                    matches.push(provider_name.clone());
                    break; // Found in this provider, no need to check other ranges
                }
            }
        }

        matches
    }
}

pub fn run_cdn_lookup(cdn_lookup: &mut CdnLookup, ip_addresses: &[String]) -> Result<()> {
    // Update providers data
    cdn_lookup.update_providers()?;
    
    // Download data for providers that don't have CIDR files
    for provider in &cdn_lookup.providers.clone() {
        let cidr_file = cdn_lookup.config_dir.join(format!("{}.cidr", provider.name));
        if !cidr_file.exists() {
            println!("Downloading initial data for {}...", provider.name);
            match minreq::get(&provider.url).send() {
                Ok(response) => {
                    if let Ok(content) = response.as_str() {
                        if let Err(e) = cdn_lookup.process_provider_data(&provider.name, content) {
                            eprintln!("Failed to process data for {}: {}", provider.name, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to download data for {}: {}", provider.name, e);
                }
            }
        }
    }
    
    // Load all CIDR ranges
    cdn_lookup.load_all_cidr_ranges()?;

    // Check each IP address
    for ip in ip_addresses {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }

        let matches = cdn_lookup.check_ip(ip);
        
        if matches.is_empty() {
            println!("{}: -", ip);
        } else {
            println!("{}: Found in {}", ip, matches.join(", "));
        }
    }

    Ok(())
}
