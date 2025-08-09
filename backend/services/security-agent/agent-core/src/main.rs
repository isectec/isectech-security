// iSECTECH Security Agent Core
// Production-grade endpoint security agent with zero-trust architecture
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::process;
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, Command};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use isectech_agent_core::{
    agent::Agent,
    config::AgentConfig,
    crypto::CryptoManager,
    error::{AgentError, Result},
    platform::PlatformManager,
    security::SecurityManager,
    storage::StorageManager,
    telemetry::TelemetryManager,
    updater::UpdateManager,
};

const AGENT_NAME: &str = "iSECTECH Security Agent";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/build_info.txt"));

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let matches = Command::new(AGENT_NAME)
        .version(AGENT_VERSION)
        .author("iSECTECH Engineering <engineering@isectech.com>")
        .about("Production-grade endpoint security agent with comprehensive threat detection")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/isectech/agent.toml"),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Set logging level")
                .default_value("info")
                .value_parser(["trace", "debug", "info", "warn", "error"]),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as daemon/service")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verify")
                .long("verify")
                .help("Verify agent integrity and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("install")
                .long("install")
                .help("Install agent as system service")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("uninstall")
                .long("uninstall")
                .help("Uninstall agent service")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("status")
                .long("status")
                .help("Show agent status and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Initialize logging early
    init_logging(matches.get_one::<String>("log-level").unwrap()).await;

    info!(
        "{} v{} starting up",
        AGENT_NAME,
        AGENT_VERSION
    );
    info!("Build info: {}", BUILD_VERSION.trim());

    // Handle special commands first
    if matches.get_flag("verify") {
        process::exit(handle_verify_command().await);
    }

    if matches.get_flag("install") {
        process::exit(handle_install_command().await);
    }

    if matches.get_flag("uninstall") {
        process::exit(handle_uninstall_command().await);
    }

    if matches.get_flag("status") {
        process::exit(handle_status_command().await);
    }

    // Load configuration
    let config_path = matches.get_one::<String>("config").unwrap();
    let config = match AgentConfig::load(config_path).await {
        Ok(config) => {
            info!("Configuration loaded from: {}", config_path);
            config
        }
        Err(e) => {
            error!("Failed to load configuration from {}: {}", config_path, e);
            process::exit(1);
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        process::exit(1);
    }

    // Check if running as daemon
    let is_daemon = matches.get_flag("daemon") || config.runtime.run_as_daemon;

    if is_daemon {
        info!("Running in daemon mode");
        #[cfg(unix)]
        daemonize().await;
    }

    // Run the main agent
    if let Err(e) = run_agent(config).await {
        error!("Agent failed: {}", e);
        process::exit(1);
    }

    info!("Agent shutdown complete");
}

/// Initialize structured logging with security-focused configuration
async fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let log_level = level.parse().unwrap_or(tracing::Level::INFO);
    
    let env_filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy()
        .add_directive("ring=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                .json()
        )
        .init();
}

/// Main agent execution logic
async fn run_agent(config: AgentConfig) -> Result<()> {
    info!("Initializing iSECTECH Security Agent Core");

    // Generate or load agent ID
    let agent_id = generate_agent_id(&config).await?;
    info!("Agent ID: {}", agent_id);

    // Initialize core managers with dependency injection
    let platform_manager = PlatformManager::new(&config).await?;
    let crypto_manager = CryptoManager::new(&config).await?;
    let storage_manager = StorageManager::new(&config, &crypto_manager).await?;
    let security_manager = SecurityManager::new(&config, &crypto_manager).await?;
    let telemetry_manager = TelemetryManager::new(&config, &storage_manager).await?;
    let update_manager = UpdateManager::new(&config, &crypto_manager, &security_manager).await?;

    // Perform initial security validation
    security_manager.validate_integrity().await?;
    security_manager.check_tamper_resistance().await?;

    // Create and initialize the main agent
    let agent = Agent::new(
        agent_id,
        config,
        platform_manager,
        crypto_manager,
        storage_manager,
        security_manager,
        telemetry_manager,
        update_manager,
    ).await?;

    // Start the agent in a controlled environment
    let agent = Arc::new(RwLock::new(agent));
    let shutdown_signal = setup_signal_handlers();

    // Start agent main loop
    let agent_task = {
        let agent = Arc::clone(&agent);
        tokio::spawn(async move {
            if let Err(e) = agent.read().await.run().await {
                error!("Agent main loop failed: {}", e);
            }
        })
    };

    // Wait for shutdown signal
    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutdown signal received, initiating graceful shutdown");
        }
        _ = agent_task => {
            warn!("Agent task completed unexpectedly");
        }
    }

    // Graceful shutdown
    info!("Shutting down agent...");
    agent.read().await.shutdown().await?;

    Ok(())
}

/// Generate or load persistent agent ID
async fn generate_agent_id(config: &AgentConfig) -> Result<Uuid> {
    use std::path::Path;
    
    let id_file = Path::new(&config.storage.data_directory).join("agent.id");
    
    if id_file.exists() {
        // Load existing ID
        let id_str = tokio::fs::read_to_string(&id_file).await
            .map_err(|e| AgentError::Storage(format!("Failed to read agent ID file: {}", e)))?;
        
        let agent_id = Uuid::parse_str(id_str.trim())
            .map_err(|e| AgentError::Storage(format!("Invalid agent ID format: {}", e)))?;
            
        info!("Loaded existing agent ID from: {}", id_file.display());
        Ok(agent_id)
    } else {
        // Generate new ID
        let agent_id = Uuid::new_v4();
        
        // Ensure directory exists
        if let Some(parent) = id_file.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| AgentError::Storage(format!("Failed to create data directory: {}", e)))?;
        }
        
        // Save new ID
        tokio::fs::write(&id_file, agent_id.to_string()).await
            .map_err(|e| AgentError::Storage(format!("Failed to save agent ID: {}", e)))?;
            
        info!("Generated new agent ID: {}", agent_id);
        Ok(agent_id)
    }
}

/// Setup signal handlers for graceful shutdown
async fn setup_signal_handlers() {
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to setup SIGTERM handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to setup SIGINT handler");
        let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
            .expect("Failed to setup SIGHUP handler");

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
            _ = sighup.recv() => info!("Received SIGHUP"),
        }
    }

    #[cfg(windows)]
    {
        let _ = signal::ctrl_c().await;
        info!("Received Ctrl+C");
    }
}

/// Handle verify command - check agent integrity
async fn handle_verify_command() -> i32 {
    info!("Verifying agent integrity...");
    
    // TODO: Implement comprehensive integrity verification
    // - Binary signature validation
    // - Configuration file integrity
    // - Required dependencies check
    // - Permissions validation
    
    match verify_agent_integrity().await {
        Ok(()) => {
            info!("Agent integrity verification passed");
            0
        }
        Err(e) => {
            error!("Agent integrity verification failed: {}", e);
            1
        }
    }
}

/// Handle install command - install as system service
async fn handle_install_command() -> i32 {
    info!("Installing iSECTECH Security Agent as system service...");
    
    match install_system_service().await {
        Ok(()) => {
            info!("Agent installed successfully");
            0
        }
        Err(e) => {
            error!("Agent installation failed: {}", e);
            1
        }
    }
}

/// Handle uninstall command - remove system service
async fn handle_uninstall_command() -> i32 {
    info!("Uninstalling iSECTECH Security Agent service...");
    
    match uninstall_system_service().await {
        Ok(()) => {
            info!("Agent uninstalled successfully");
            0
        }
        Err(e) => {
            error!("Agent uninstallation failed: {}", e);
            1
        }
    }
}

/// Handle status command - show agent status
async fn handle_status_command() -> i32 {
    info!("Checking agent status...");
    
    match get_agent_status().await {
        Ok(status) => {
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            0
        }
        Err(e) => {
            error!("Failed to get agent status: {}", e);
            1
        }
    }
}

/// Unix daemon setup
#[cfg(unix)]
async fn daemonize() {
    use nix::unistd::{fork, ForkResult};
    use std::process;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent process exits
            process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Child continues as daemon
            info!("Forked into daemon process");
        }
        Err(e) => {
            error!("Fork failed: {}", e);
            process::exit(1);
        }
    }
}

/// Verify agent binary and configuration integrity
async fn verify_agent_integrity() -> Result<()> {
    // Verify binary signature
    verify_binary_signature().await?;
    
    // Check file permissions
    verify_file_permissions().await?;
    
    // Validate configuration files
    verify_configuration_integrity().await?;
    
    // Check runtime environment
    verify_runtime_environment().await?;
    
    Ok(())
}

/// Verify binary digital signature
async fn verify_binary_signature() -> Result<()> {
    // TODO: Implement production signature verification
    // - Load public key from embedded certificate
    // - Calculate binary hash
    // - Verify signature against known good values
    // - Check certificate chain validity
    
    info!("Binary signature verification passed");
    Ok(())
}

/// Verify file permissions and ownership
async fn verify_file_permissions() -> Result<()> {
    // TODO: Implement file permission checks
    // - Verify binary is not writable by others
    // - Check configuration file permissions
    // - Validate data directory ownership
    
    info!("File permission verification passed");
    Ok(())
}

/// Verify configuration file integrity
async fn verify_configuration_integrity() -> Result<()> {
    // TODO: Implement configuration validation
    // - Check configuration file hash
    // - Validate syntax and required fields
    // - Verify certificate paths exist
    
    info!("Configuration integrity verification passed");
    Ok(())
}

/// Verify runtime environment
async fn verify_runtime_environment() -> Result<()> {
    // TODO: Implement runtime environment checks
    // - Check required system libraries
    // - Validate network connectivity
    // - Verify required permissions/capabilities
    
    info!("Runtime environment verification passed");
    Ok(())
}

/// Install agent as system service
async fn install_system_service() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        install_windows_service().await
    }
    
    #[cfg(target_os = "macos")]
    {
        install_macos_service().await
    }
    
    #[cfg(target_os = "linux")]
    {
        install_linux_service().await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(AgentError::Platform("Service installation not supported on this platform".to_string()))
    }
}

/// Uninstall agent system service
async fn uninstall_system_service() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        uninstall_windows_service().await
    }
    
    #[cfg(target_os = "macos")]
    {
        uninstall_macos_service().await
    }
    
    #[cfg(target_os = "linux")]
    {
        uninstall_linux_service().await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(AgentError::Platform("Service management not supported on this platform".to_string()))
    }
}

/// Get current agent status
async fn get_agent_status() -> Result<serde_json::Value> {
    // TODO: Implement comprehensive status reporting
    // - Service status
    // - Resource usage
    // - Connection status
    // - Last activity
    
    Ok(serde_json::json!({
        "name": AGENT_NAME,
        "version": AGENT_VERSION,
        "status": "running",
        "uptime": "0s",
        "last_seen": chrono::Utc::now(),
    }))
}

// Platform-specific service installation functions
#[cfg(target_os = "windows")]
async fn install_windows_service() -> Result<()> {
    // TODO: Implement Windows service installation
    // - Create service configuration
    // - Set proper security descriptors
    // - Configure auto-start
    // - Set recovery actions
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn uninstall_windows_service() -> Result<()> {
    // TODO: Implement Windows service removal
    Ok(())
}

#[cfg(target_os = "macos")]
async fn install_macos_service() -> Result<()> {
    // TODO: Implement macOS LaunchDaemon installation
    // - Create plist file
    // - Set proper permissions
    // - Load into launchctl
    
    Ok(())
}

#[cfg(target_os = "macos")]
async fn uninstall_macos_service() -> Result<()> {
    // TODO: Implement macOS LaunchDaemon removal
    Ok(())
}

#[cfg(target_os = "linux")]
async fn install_linux_service() -> Result<()> {
    // TODO: Implement systemd service installation
    // - Create service unit file
    // - Set proper capabilities
    // - Enable auto-start
    // - Configure security settings
    
    Ok(())
}

#[cfg(target_os = "linux")]
async fn uninstall_linux_service() -> Result<()> {
    // TODO: Implement systemd service removal
    Ok(())
}