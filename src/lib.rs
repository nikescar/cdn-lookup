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

fn convert_github_to_git(http_url: &str) -> Option<String> {
    // https://raw.githubusercontent.com/owner/repo/refs/heads/branch/path/to/file.txt
    // → git://github.com/owner/repo/branch/path/to/file.txt

    if let Some(rest) = http_url.strip_prefix("https://raw.githubusercontent.com/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 5 && parts[2] == "refs" && parts[3] == "heads" {
            let owner = parts[0];
            let repo = parts[1];
            let branch = parts[4];
            let file_path = parts[5..].join("/");

            return Some(format!(
                "git://github.com/{}/{}/{}/{}",
                owner, repo, branch, file_path
            ));
        }
    }

    // Also handle github.com/owner/repo/raw/refs/heads/branch/path format
    if let Some(rest) = http_url.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 7 && parts[2] == "raw" && parts[3] == "refs" && parts[4] == "heads" {
            let owner = parts[0];
            let repo = parts[1];
            let branch = parts[5];
            let file_path = parts[6..].join("/");

            return Some(format!(
                "git://github.com/{}/{}/{}/{}",
                owner, repo, branch, file_path
            ));
        }
    }

    None
}

fn convert_git_to_http(git_url: &str) -> String {
    // git://github.com/owner/repo/branch/path/to/file.txt
    // → https://raw.githubusercontent.com/owner/repo/refs/heads/branch/path/to/file.txt

    if let Some(rest) = git_url.strip_prefix("git://github.com/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 4 {
            let owner = parts[0];
            let repo = parts[1];
            let branch = parts[2];
            let file_path = parts[3..].join("/");

            return format!(
                "https://raw.githubusercontent.com/{}/{}/refs/heads/{}/{}",
                owner, repo, branch, file_path
            );
        }
    }
    git_url.to_string()
}

struct GitRepoManager {
    repos_dir: PathBuf,
}

impl GitRepoManager {
    fn new(config_dir: &PathBuf) -> Result<Self> {
        let repos_dir = config_dir.join("repos");
        if !repos_dir.exists() {
            fs::create_dir_all(&repos_dir)?;
        }
        Ok(Self { repos_dir })
    }

    fn parse_git_url(&self, url: &str) -> Option<(String, String, String)> {
        // Parse git://github.com/owner/repo/branch/file/path
        if !url.starts_with("git://github.com/") {
            return None;
        }

        let parts: Vec<&str> = url.strip_prefix("git://github.com/")?.split('/').collect();
        if parts.len() < 4 {
            return None;
        }

        let owner = parts[0];
        let repo = parts[1];
        let branch = parts[2];
        let file_path = parts[3..].join("/");

        let repo_url = format!("https://github.com/{}/{}", owner, repo);
        Some((repo_url, branch.to_string(), file_path))
    }

    fn ensure_repo(&self, repo_url: &str, branch: &str) -> Result<PathBuf> {
        let repo_name = repo_url.split('/').last()
            .ok_or_else(|| anyhow::anyhow!("Invalid repo URL"))?;
        let repo_path = self.repos_dir.join(repo_name);

        if repo_path.exists() {
            // Update existing repo: fetch + reset for shallow clones
            let fetch = std::process::Command::new("git")
                .args(["-C"])
                .arg(&repo_path)
                .args(["fetch", "--depth", "1", "origin", branch])
                .output()
                .context("Failed to execute git fetch")?;

            if !fetch.status.success() {
                let stderr = String::from_utf8_lossy(&fetch.stderr);
                anyhow::bail!("git fetch failed: {}", stderr);
            }

            let reset = std::process::Command::new("git")
                .args(["-C"])
                .arg(&repo_path)
                .args(["reset", "--hard", &format!("origin/{}", branch)])
                .output()
                .context("Failed to execute git reset")?;

            if !reset.status.success() {
                let stderr = String::from_utf8_lossy(&reset.stderr);
                anyhow::bail!("git reset failed: {}", stderr);
            }
        } else {
            // Clone new repo
            let clone = std::process::Command::new("git")
                .args(["clone", "--depth", "1", "--branch", branch, repo_url])
                .arg(&repo_path)
                .output()
                .context("Failed to execute git clone")?;

            if !clone.status.success() {
                let stderr = String::from_utf8_lossy(&clone.stderr);
                anyhow::bail!("git clone failed: {}", stderr);
            }
        }

        Ok(repo_path)
    }

    fn read_file(&self, git_url: &str) -> Result<String> {
        let (repo_url, branch, file_path) = self.parse_git_url(git_url)
            .ok_or_else(|| anyhow::anyhow!("Invalid git URL: {}", git_url))?;

        let repo_path = self.ensure_repo(&repo_url, &branch)
            .with_context(|| format!("Failed to clone/update repo: {}", repo_url))?;
        let file_full_path = repo_path.join(&file_path);

        if !file_full_path.exists() {
            anyhow::bail!("File not found in repo: {} (expected at {:?})", file_path, file_full_path);
        }

        fs::read_to_string(&file_full_path)
            .with_context(|| format!("Failed to read file: {:?}", file_full_path))
    }
}

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

    fn fetch_upstream_providers() -> Result<Vec<Provider>> {
        let response = minreq::get(PROVIDERS_URL).send()?;
        let content = response.as_str()?;

        let mut providers = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                providers.push(Provider::from_line(line)?);
            }
        }
        Ok(providers)
    }

    fn merge_providers(local: Vec<Provider>, upstream: Vec<Provider>) -> Vec<Provider> {
        let mut merged = HashMap::new();

        // Start with all local providers (includes user additions)
        for provider in local {
            merged.insert(provider.name.clone(), provider);
        }

        // Add new providers from upstream (don't overwrite existing)
        for provider in upstream {
            merged.entry(provider.name.clone())
                .or_insert(provider);
        }

        // Convert back to Vec and sort by name for consistent ordering
        let mut result: Vec<Provider> = merged.into_values().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    fn save_providers_to_file(path: &PathBuf, providers: &[Provider]) -> Result<()> {
        let mut file = fs::File::create(path)?;
        for provider in providers {
            writeln!(file, "{}", provider.to_line())?;
        }
        Ok(())
    }
}

pub struct CdnLookup {
    config_dir: PathBuf,
    providers: Vec<Provider>,
    ip_ranges: HashMap<String, Vec<IpNet>>,
    refresh: bool,
    no_git: bool,
    git_manager: GitRepoManager,
}

impl CdnLookup {
    pub fn new(refresh: bool, no_git: bool) -> Result<Self> {
        let config_dir = Self::get_config_dir()?;
        let providers = Self::load_providers(&config_dir)?;
        let git_manager = GitRepoManager::new(&config_dir)?;

        Ok(Self {
            config_dir,
            providers,
            ip_ranges: HashMap::new(),
            refresh,
            no_git,
            git_manager,
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
        let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let local_providers = if providers_file.exists() {
            // Load existing local providers
            let content = fs::read_to_string(&providers_file)?;
            let mut providers = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    providers.push(Provider::from_line(line)?);
                }
            }

            // Check if we should update (monthly check)
            let oldest_check = providers.iter()
                .map(|p| p.last_checked_timestamp)
                .min()
                .unwrap_or(0);

            if current_timestamp - oldest_check > ONE_MONTH_SECONDS {
                eprintln!("Checking for new providers from upstream...");
                match Provider::fetch_upstream_providers() {
                    Ok(upstream) => {
                        let merged = Provider::merge_providers(providers, upstream);
                        // Save merged result
                        Provider::save_providers_to_file(&providers_file, &merged)?;
                        eprintln!("Providers updated from upstream");
                        merged
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to fetch upstream providers: {}", e);
                        eprintln!("Continuing with local providers");
                        providers // Use local on fetch failure
                    }
                }
            } else {
                providers
            }
        } else {
            // First run: download and save
            eprintln!("Downloading providers.conf...");
            let upstream = Provider::fetch_upstream_providers()?;
            Provider::save_providers_to_file(&providers_file, &upstream)?;
            upstream
        };

        Ok(local_providers)
    }

    pub fn update_providers(&mut self) -> Result<()> {
        let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut updated = false;
        let mut downloads = Vec::new();

        for provider in &mut self.providers {
            let should_check_remote = self.refresh ||
                current_timestamp - provider.last_checked_timestamp > ONE_MONTH_SECONDS;

            if should_check_remote {
                eprintln!("Checking {} for updates...", provider.name);

                // Auto-convert GitHub HTTPS URLs to git:// for deduplication (unless --no-git)
                let git_url = if !self.no_git {
                    convert_github_to_git(&provider.url)
                } else {
                    None
                };
                let use_git = !self.no_git && (git_url.is_some() || provider.url.starts_with("git://"));
                let effective_url = git_url.as_ref().unwrap_or(&provider.url);

                let content = if use_git {
                    // Git-based provider (auto-detected or explicit git://)
                    match self.git_manager.read_file(effective_url) {
                        Ok(c) => {
                            eprintln!("✓ {} (via git)", provider.name);
                            provider.last_response_timestamp = current_timestamp;
                            provider.last_checked_timestamp = current_timestamp;
                            updated = true;
                            Some(c)
                        }
                        Err(e) => {
                            eprintln!("⚠ {} git failed, trying HTTP: {}", provider.name, e);
                            // Convert git:// URL to HTTP and try fallback
                            let http_url = convert_git_to_http(&provider.url);
                            match minreq::get(&http_url).send() {
                                Ok(response) => {
                                    if let Ok(c) = response.as_str() {
                                        eprintln!("✓ {} (via HTTP fallback)", provider.name);
                                        provider.last_response_timestamp = current_timestamp;
                                        provider.last_checked_timestamp = current_timestamp;
                                        updated = true;
                                        Some(c.to_string())
                                    } else {
                                        eprintln!("✗ Skipping {}: HTTP response decode failed", provider.name);
                                        provider.last_checked_timestamp = current_timestamp;
                                        None
                                    }
                                }
                                Err(e) => {
                                    eprintln!("✗ Skipping {}: {}", provider.name, e);
                                    provider.last_checked_timestamp = current_timestamp;
                                    None
                                }
                            }
                        }
                    }
                } else {
                    // HTTP-based provider (existing logic)
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
                                match minreq::get(&provider.url).send() {
                                    Ok(resp) => {
                                        if let Ok(c) = resp.as_str() {
                                            eprintln!("✓ {} (via HTTP)", provider.name);
                                            provider.last_response_timestamp = remote_timestamp;
                                            provider.last_checked_timestamp = current_timestamp;
                                            updated = true;
                                            Some(c.to_string())
                                        } else {
                                            provider.last_checked_timestamp = current_timestamp;
                                            None
                                        }
                                    }
                                    Err(_) => {
                                        provider.last_checked_timestamp = current_timestamp;
                                        None
                                    }
                                }
                            } else {
                                provider.last_checked_timestamp = current_timestamp;
                                None
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Skipping {}: {}", provider.name, e);
                            provider.last_checked_timestamp = current_timestamp;
                            None
                        }
                    }
                };

                if let Some(c) = content {
                    downloads.push((provider.name.clone(), c));
                }
            }
        }

        // Process downloaded data
        for (provider_name, content) in downloads {
            self.process_provider_data(&provider_name, &content)?;
        }

        if updated {
            self.save_providers()?;
        }

        Ok(())
    }

    fn process_provider_data(&self, provider_name: &str, content: &str) -> Result<()> {
        let mut cidrs = Vec::new();

        // Try JSON parsing first
        let trimmed = content.trim();
        if (trimmed.starts_with('{') || trimmed.starts_with('[')) &&
           (serde_json::from_str::<serde_json::Value>(content).is_ok()) {
            // JSON format
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                self.extract_cidrs_from_json(&json, &mut cidrs);
            }
        }

        // Fallback to regex if JSON returned 0 results or wasn't JSON
        if cidrs.is_empty() {
            let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")?;
            let cidr_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b")?;

            // Extract CIDR ranges
            for cap in cidr_regex.find_iter(content) {
                if let Ok(cidr) = cap.as_str().parse::<IpNet>() {
                    cidrs.push(cidr);
                }
            }

            // Extract individual IPs and convert to /32 CIDR
            for cap in ip_regex.find_iter(content) {
                let ip_str = cap.as_str();
                if !cidr_regex.is_match(&format!("{}/", ip_str)) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if let Ok(cidr) = format!("{}/32", ip).parse::<IpNet>() {
                            cidrs.push(cidr);
                        }
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

        eprintln!("Processed {} CIDR ranges for {}", cidrs.len(), provider_name);
        Ok(())
    }

    fn extract_cidrs_from_json(&self, json: &serde_json::Value, cidrs: &mut Vec<IpNet>) {
        match json {
            serde_json::Value::Array(arr) => {
                for item in arr {
                    // Check if array contains direct CIDR strings
                    if let serde_json::Value::String(s) = item {
                        if let Ok(cidr) = s.parse::<IpNet>() {
                            cidrs.push(cidr);
                        }
                    } else {
                        // Recurse for non-string values (objects, nested arrays)
                        self.extract_cidrs_from_json(item, cidrs);
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                // Check for ipv4Prefix field
                if let Some(serde_json::Value::String(prefix)) = obj.get("ipv4Prefix") {
                    if let Ok(cidr) = prefix.parse::<IpNet>() {
                        cidrs.push(cidr);
                    }
                }
                // Check for ip_prefix field (alternative naming)
                if let Some(serde_json::Value::String(prefix)) = obj.get("ip_prefix") {
                    if let Ok(cidr) = prefix.parse::<IpNet>() {
                        cidrs.push(cidr);
                    }
                }
                // Check for prefix field
                if let Some(serde_json::Value::String(prefix)) = obj.get("prefix") {
                    if let Ok(cidr) = prefix.parse::<IpNet>() {
                        cidrs.push(cidr);
                    }
                }
                // Recursively check nested objects
                for value in obj.values() {
                    self.extract_cidrs_from_json(value, cidrs);
                }
            }
            _ => {}
        }
    }

    fn save_providers(&self) -> Result<()> {
        let providers_file = self.config_dir.join("providers.conf");
        Provider::save_providers_to_file(&providers_file, &self.providers)
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
            eprintln!("Downloading initial data for {}...", provider.name);
            match minreq::get(&provider.url).send() {
                Ok(response) => {
                    if let Ok(content) = response.as_str() {
                        if let Err(e) = cdn_lookup.process_provider_data(&provider.name, content) {
                            eprintln!("Warning: Failed to process data for {}: {}", provider.name, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Skipping {}: {}", provider.name, e);
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
