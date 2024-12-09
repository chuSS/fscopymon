use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use log::{info, error};

pub const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(5);

pub fn is_process_running(pid_file: &str) -> bool {
    if let Ok(pid_str) = fs::read_to_string(pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            #[cfg(windows)]
            {
                Command::new("tasklist")
                    .args(["/NH", "/FO", "CSV", "/FI", &format!("PID eq {}", pid)])
                    .output()
                    .map(|output| {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        !output_str.trim().is_empty() && output_str.contains(&format!(",{},", pid))
                    })
                    .unwrap_or(false)
            }

            #[cfg(unix)]
            {
                use nix::sys::signal;
                use nix::unistd::Pid;
                signal::kill(Pid::from_raw(pid as i32), None).is_ok()
            }
        } else {
            false
        }
    } else {
        false
    }
}

pub fn write_pid_file(pid_file: &str) -> io::Result<()> {
    fs::write(pid_file, std::process::id().to_string())
}

pub fn start_daemon(config_path: &str, pid_file: &str, log_level: &str) -> io::Result<()> {
    if is_process_running(pid_file) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Daemon is already running",
        ));
    }

    info!("Starting daemon process...");
    
    let current_exe = std::env::current_exe()?;
    info!("Current executable: {:?}", current_exe);
    
    // Create log file path next to the pid file
    let log_file = format!("{}.log", pid_file.trim_end_matches(".pid"));
    info!("Daemon log file: {}", log_file);
    
    #[cfg(windows)]
    let child = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        
        let result = Command::new(&current_exe)
            .args([
                "--daemon",
                "--config", config_path,
                "--pid-file", pid_file,
                "--log-level", log_level,
                "--log-file", &log_file
            ])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn();

        match result {
            Ok(child) => child,
            Err(ref e) if e.raw_os_error() == Some(740) => {
                // Error 740: The requested operation requires elevation
                error!("Process requires elevation, trying to run with 'runas'");
                Command::new("runas")
                    .args([
                        "/user:Administrator",
                        &format!("\"{}\"", current_exe.display()),
                        "--daemon",
                        "--config", config_path,
                        "--pid-file", pid_file,
                        "--log-level", log_level,
                        "--log-file", &log_file
                    ])
                    .spawn()?
            }
            Err(e) => return Err(e),
        }
    };

    #[cfg(unix)]
    let child = {
        Command::new(&current_exe)
            .args([
                "--daemon",
                "--config", config_path,
                "--pid-file", pid_file,
                "--log-level", log_level,
                "--log-file", &log_file
            ])
            .spawn()?
    };
            
    info!("Spawned daemon process with PID: {}", child.id());

    // Wait for daemon to start and create PID file
    info!("Waiting for daemon to start...");
    let start = Instant::now();
    let timeout = Duration::from_secs(10); // Increase timeout to 10 seconds
    
    while start.elapsed() < timeout {
        if is_process_running(pid_file) {
            info!("Daemon started successfully");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    error!("Daemon failed to start within timeout period");
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Failed to start daemon process - timeout waiting for PID file",
    ))
}

pub fn stop_daemon(pid_file: &str) -> io::Result<()> {
    if !is_process_running(pid_file) {
        // If process is not running but PID file exists, clean it up
        if Path::new(pid_file).exists() {
            fs::remove_file(pid_file)?;
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Daemon is not running",
        ));
    }

    let pid_str = fs::read_to_string(pid_file)?;
    let pid = pid_str.trim().parse::<u32>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PID in pid file: {}", e),
        )
    })?;

    #[cfg(windows)]
    {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output()?;
    }

    #[cfg(unix)]
    {
        use nix::sys::signal;
        use nix::unistd::Pid;
        signal::kill(Pid::from_raw(pid as i32), signal::Signal::SIGTERM).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to send SIGTERM: {}", e),
            )
        })?;
    }

    // Wait for process to actually stop
    let start = Instant::now();
    while start.elapsed() < DAEMON_START_TIMEOUT {
        if !is_process_running(pid_file) {
            // Process stopped, clean up PID file
            if Path::new(pid_file).exists() {
                fs::remove_file(pid_file)?;
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Timed out waiting for daemon to stop",
    ))
}
