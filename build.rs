use std::process::Command;

fn main() {
    // Get git version using describe
    let output = Command::new("git")
        .args(&["describe", "--tags", "--always", "--dirty"])
        .output();

    let git_version = match output {
        Ok(output) => {
            String::from_utf8(output.stdout)
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
                .trim()
                .to_string()
        }
        Err(_) => {
            // Fallback to Cargo.toml version if git is not available
            env!("CARGO_PKG_VERSION").to_string()
        }
    };

    println!("cargo:rustc-env=GIT_VERSION={}", git_version);

    // Rebuild when git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}
