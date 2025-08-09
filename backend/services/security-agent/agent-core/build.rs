// iSECTECH Security Agent - Build Script
// Generate build-time information for agent identification
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn main() {
    // Generate build information
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_info.txt");
    let mut f = File::create(&dest_path).unwrap();
    
    // Get build timestamp
    let build_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    
    // Get git information
    let git_commit = get_git_commit();
    let git_branch = get_git_branch();
    
    // Get build profile
    let build_profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    
    // Get target information
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    
    // Write build information
    writeln!(f, "Build Date: {}", build_date).unwrap();
    writeln!(f, "Git Commit: {}", git_commit).unwrap();
    writeln!(f, "Git Branch: {}", git_branch).unwrap();
    writeln!(f, "Build Profile: {}", build_profile).unwrap();
    writeln!(f, "Target: {}", target).unwrap();
    writeln!(f, "Rust Version: {}", rustc_version()).unwrap();
    
    // Set environment variables for compilation
    println!("cargo:rustc-env=BUILD_DATE={}", build_date);
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);
    println!("cargo:rustc-env=BUILD_PROFILE={}", build_profile);
    println!("cargo:rustc-env=TARGET_ARCH={}", target);
    
    // Trigger rebuild if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    
    // Generate protocol buffers if proto files exist
    let proto_dir = "proto";
    if Path::new(proto_dir).exists() {
        println!("cargo:rerun-if-changed={}", proto_dir);
        // TODO: Add protobuf generation when proto files are added
    }
}

fn get_git_commit() -> String {
    Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_git_branch() -> String {
    Command::new("git")
        .args(&["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}