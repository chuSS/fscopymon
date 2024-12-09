mod config;
mod watcher;
mod daemon;
mod file_operations;

use std::io;
use clap::{Arg, ArgAction, Command as ClapCommand};
use env_logger::{self, Target};
use log::{info, error};
use std::path::Path;
use std::fs;
use ctrlc;

fn setup_logger(log_level: &str, log_file: &str) -> io::Result<()> {
    use env_logger::{Builder, WriteStyle};
    use log::LevelFilter;
    use std::fs;

    let level = match log_level.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    let mut builder = Builder::new();
    builder
        .filter(None, level)
        .write_style(WriteStyle::Always);

    if !log_file.is_empty() {
        let log_file_handle = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        builder.target(Target::Pipe(Box::new(log_file_handle)));
    }

    builder.init();

    Ok(())
}

fn main() -> io::Result<()> {
    let matches = ClapCommand::new("fscopymon")
        .version("1.0")
        .author("Your Name")
        .about("File system copy monitor")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Config file path")
                .default_value("config.json"),
        )
        .arg(
            Arg::new("pid-file")
                .short('p')
                .long("pid-file")
                .value_name("FILE")
                .help("PID file path")
                .default_value("fscopymon.pid"),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (error/warn/info/debug/trace)")
                .default_value("info"),
        )
        .arg(
            Arg::new("log-file")
                .short('f')
                .long("log-file")
                .value_name("FILE")
                .help("Log file path"),
        )
        .arg(
            Arg::new("start")
                .long("start")
                .help("Start the daemon")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stop")
                .long("stop")
                .help("Stop the daemon")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .help("Run as daemon (internal use)")
                .action(ArgAction::SetTrue)
                .hide(true),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let pid_file = matches.get_one::<String>("pid-file").unwrap();
    let log_level = matches.get_one::<String>("log-level").unwrap();
    let empty_string = String::new();
    let log_file = matches.get_one::<String>("log-file").unwrap_or(&empty_string);

    setup_logger(log_level, log_file)?;

    if matches.get_flag("daemon") {
        // Running as daemon process
        info!("Starting daemon process with PID {}", std::process::id());
        
        // Set up Ctrl+C handler
        info!("Setting up Ctrl+C handler...");
        let pid_file_clone = pid_file.to_string();
        ctrlc::set_handler(move || {
            info!("Received shutdown signal");
            if Path::new(&pid_file_clone).exists() {
                if let Err(e) = fs::remove_file(&pid_file_clone) {
                    error!("Failed to remove PID file: {}", e);
                }
            }
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");
        info!("Ctrl+C handler set up successfully");
        
        // Write PID file
        info!("Writing PID file...");
        if let Err(e) = daemon::write_pid_file(pid_file) {
            error!("Failed to write PID file: {}", e);
            return Err(e);
        }
        info!("PID file written: {}", pid_file);

        // Load config and start watching
        info!("Loading configuration...");
        let config = config::read_config(config_path)?;
        info!("Config loaded from: {}", config_path);
        info!("Starting file system watcher...");
        watcher::start_watching(config)?;
        info!("Watcher stopped");
    } else if matches.get_flag("start") {
        info!("Starting daemon...");
        daemon::start_daemon(config_path, pid_file, log_level)?;
    } else if matches.get_flag("stop") {
        info!("Stopping daemon...");
        daemon::stop_daemon(pid_file)?;
        info!("Daemon stopped");
    } else {
        let is_running = daemon::is_process_running(pid_file);
        info!("Daemon status: {}", if is_running { "running" } else { "stopped" });
        if !is_running && Path::new(pid_file).exists() {
            // Clean up stale PID file
            fs::remove_file(pid_file)?;
        }
    }

    Ok(())
}
