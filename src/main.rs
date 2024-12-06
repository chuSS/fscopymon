use clap::{Parser, ValueEnum};
use log::{error, info, warn, debug};
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};
use std::thread;
use std::io;
use ctrlc;
use env_logger;

#[cfg(unix)]
use nix::{
    sys::signal::{self, Signal},
    unistd::{self, Pid},
};

const DEFAULT_CONFIG_PATH: &str = "./fscopymon.json";
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[clap(author, version, about = "File Synchronization Monitor")]
struct Cli {
    #[clap(value_enum, default_value = "auto")]
    #[clap(help = "Command to execute")]
    command: CommandType,

    #[clap(short, long, help = "Path to config file")]
    conf: Option<String>,

    #[clap(long, hide = true)]
    daemon: bool,

    #[clap(short, long, default_value = "info", help = "Log level (error, warn, info, debug)")]
    log_level: String,

    #[clap(long, help = "Custom path for PID file")]
    pid_file: Option<String>,

    #[clap(long, help = "Custom path for log file")]
    log_file: Option<String>,
}

#[derive(ValueEnum, Clone)]
#[clap(rename_all = "lowercase")]
enum CommandType {
    #[clap(help = "Show daemon status and current configuration")]
    Auto,
    #[clap(help = "Start the monitoring daemon")]
    Start,
    #[clap(help = "Stop the monitoring daemon")]
    Stop,
    #[clap(hide = true)]
    ReadConf,
}

#[derive(Deserialize)]
struct Config {
    folders: Vec<FolderConfig>,
}

#[derive(Deserialize)]
struct FolderConfig {
    source: String,
    destination: String,
}

fn setup_logger(log_file: &str) -> Result<(), io::Error> {
    use std::io::Write;
    use std::fs::OpenOptions;
    
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] {} - {}",
                buf.timestamp(),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    
    Ok(())
}

fn load_config(path: &str) -> Result<Config, io::Error> {
    let config_data = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&config_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(config)
}

fn copy_file(src: &Path, dest: &Path) -> Result<(), io::Error> {
    const MAX_RETRIES: u32 = 3;
    let mut retries = 0;
    
    while retries < MAX_RETRIES {
        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                error!("Ошибка создания директории {}: {}", parent.display(), e);
                return Err(e);
            }
        }
        
        match fs::copy(src, dest) {
            Ok(_) => {
                info!("Скопирован файл: {} -> {}", src.display(), dest.display());
                return Ok(());
            }
            Err(e) => {
                warn!("Попытка {} копирования файла {} не удалась: {}", retries + 1, src.display(), e);
                retries += 1;
                if retries < MAX_RETRIES {
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }
    
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Не удалось скопировать файл после {} попыток", MAX_RETRIES)
    ))
}

fn should_copy_file(src: &Path, dest: &Path) -> bool {
    if !dest.exists() {
        info!("Новый файл будет скопирован: {}", dest.display());
        return true;
    }
    
    // Если файл существует, сравниваем размер и время модификации
    match (fs::metadata(src), fs::metadata(dest)) {
        (Ok(src_meta), Ok(dest_meta)) => {
            let should_copy = src_meta.len() != dest_meta.len() || 
                            src_meta.modified().ok() != dest_meta.modified().ok();
            if should_copy {
                info!("Файл изменен и будет обновлен: {}", dest.display());
            } else {
                debug!("Файл не требует обновления: {}", dest.display());
            }
            should_copy
        }
        _ => {
            warn!("Не удалось получить метаданные файла, будет выполнено копирование: {}", dest.display());
            true
        }
    }
}

fn sync_directories(source: &Path, destination: &Path) -> io::Result<()> {
    if !source.exists() {
        warn!("Исходная директория не существует: {}", source.display());
        return Ok(());
    }

    if !destination.exists() {
        info!("Создание целевой директории: {}", destination.display());
        fs::create_dir_all(destination)?;
    }

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = destination.join(entry.file_name());

        if src_path.is_dir() {
            sync_directories(&src_path, &dest_path)?;
        } else if should_copy_file(&src_path, &dest_path) {
            if let Err(e) = copy_file(&src_path, &dest_path) {
                error!("Ошибка копирования {}: {}", src_path.display(), e);
            } else {
                info!("Скопирован файл: {} -> {}", src_path.display(), dest_path.display());
            }
        }
    }
    Ok(())
}

fn is_process_running(pid_file: &str) -> bool {
    if let Ok(pid_str) = fs::read_to_string(pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            #[cfg(windows)]
            {
                use std::process::Command;
                let output = Command::new("tasklist")
                    .output()
                    .expect("Failed to execute tasklist");
                let output_str = String::from_utf8_lossy(&output.stdout);
                return output_str.contains(&format!("{}", pid));
            }
            #[cfg(unix)]
            {
                return std::path::Path::new(&format!("/proc/{}", pid)).exists();
            }
        }
    }
    false
}

fn wait_for_pid_file(pid_file: &str, exists: bool) -> io::Result<()> {
    let start = Instant::now();
    let timeout = if exists { DAEMON_START_TIMEOUT } else { DAEMON_STOP_TIMEOUT };
    while start.elapsed() < timeout {
        if exists == Path::new(pid_file).exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        if exists {
            "Таймаут ожидания создания PID файла"
        } else {
            "Таймаут ожидания удаления PID файла"
        }
    ))
}

fn start_watching(config: Config) -> notify::Result<()> {
    info!("Запуск мониторинга...");
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        info!("Получен сигнал завершения...");
        r.store(false, Ordering::SeqCst);
    }).expect("Ошибка установки обработчика Ctrl-C");

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        NotifyConfig::default(),
    )?;

    // Инициализируем начальную синхронизацию
    info!("Выполняем начальную синхронизацию...");
    for folder in &config.folders {
        let source = Path::new(&folder.source);
        let destination = Path::new(&folder.destination);
        if let Err(e) = sync_directories(source, destination) {
            error!("Ошибка начальной синхронизации: {}", e);
        }
        watcher.watch(source, RecursiveMode::Recursive)?;
        info!("Мониторинг папки: {}", folder.source);
    }

    info!("Мониторинг начат...");

    while running.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                if let EventKind::Create(_) | EventKind::Modify(_) = event.kind {
                    for path in event.paths {
                        for folder in &config.folders {
                            let source = Path::new(&folder.source);
                            if path.starts_with(source) {
                                let relative_path = path.strip_prefix(source)
                                    .expect("Ошибка получения относительного пути");
                                let dest_path = PathBuf::from(&folder.destination).join(relative_path);
                                
                                if path.is_dir() {
                                    if !dest_path.exists() {
                                        info!("Создание новой директории: {}", dest_path.display());
                                        if let Err(e) = fs::create_dir_all(&dest_path) {
                                            error!("Ошибка создания директории {}: {}", dest_path.display(), e);
                                        }
                                    }
                                } else if should_copy_file(&path, &dest_path) {
                                    if let Err(e) = copy_file(&path, &dest_path) {
                                        error!("Ошибка копирования файла {}: {}", path.display(), e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(e) => {
                error!("Ошибка получения события: {}", e);
                break;
            }
        }
    }
    
    info!("Завершение мониторинга...");
    Ok(())
}

fn run_daemon(config_path: &str, pid_file: &str, log_file: &str) -> io::Result<()> {
    // Записываем PID файл
    let pid = std::process::id().to_string();
    fs::write(pid_file, &pid)?;

    // Настраиваем логирование
    setup_logger(log_file)?;

    info!("Демон запущен с PID: {}", pid);

    // Загружаем конфигурацию и запускаем мониторинг
    match load_config(config_path) {
        Ok(config) => {
            if let Err(e) = start_watching(config) {
                error!("Ошибка при мониторинге: {:?}", e);
                fs::remove_file(pid_file).ok();
                return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
            }
        }
        Err(e) => {
            error!("Ошибка загрузки конфигурации: {}", e);
            fs::remove_file(pid_file).ok();
            return Err(e);
        }
    }

    Ok(())
}

fn start_daemon(config_path: &str, pid_file: &str, log_file: &str) -> io::Result<()> {
    if is_process_running(pid_file) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Демон уже запущен"
        ));
    }

    // Запускаем процесс демона
    let current_exe = std::env::current_exe()?;
    let mut command = Command::new(current_exe);
    command
        .arg("--daemon")
        .arg("--conf")
        .arg(config_path)
        .arg("--pid-file")
        .arg(pid_file)
        .arg("--log-file")
        .arg(log_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(target_family = "unix")]
    {
        use std::os::unix::process::CommandExt;
        command.before_exec(|| {
            nix::unistd::daemon(true, true)?;
            Ok(())
        });
    }

    let child = command.spawn()?;

    // Записываем PID
    fs::write(pid_file, child.id().to_string())?;

    // Ждем создания PID файла
    wait_for_pid_file(pid_file, true)?;

    Ok(())
}

fn stop_daemon(pid_file: &str) -> io::Result<()> {
    if !is_process_running(pid_file) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Демон не запущен"
        ));
    }

    let pid = fs::read_to_string(pid_file)?
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    terminate_process(pid)?;

    // Явно удаляем PID файл после остановки процесса
    if let Err(e) = fs::remove_file(pid_file) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Не удалось удалить PID файл: {}", e)
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::PROCESS_TERMINATE;
    
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle == std::ptr::null_mut() {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(740) { // ERROR_ELEVATION_REQUIRED
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Требуются права администратора для остановки процесса. Пожалуйста, запустите команду от имени администратора."
                ));
            }
            return Err(err);
        }
        if TerminateProcess(handle, 0) == 0 {
            let err = io::Error::last_os_error();
            CloseHandle(handle);
            return Err(err);
        }
        CloseHandle(handle);
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> io::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn main() {
    let cli = Cli::parse();
    
    let config_path = cli.conf.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string());
    let pid_file = cli.pid_file.unwrap_or_else(|| "./fscopymon.pid".to_string());
    let log_file = cli.log_file.unwrap_or_else(|| "./fscopymon.log".to_string());

    // Настраиваем уровень логирования
    std::env::set_var("RUST_LOG", &cli.log_level);

    // Если запущены в режиме демона
    if cli.daemon {
        if let Err(e) = run_daemon(&config_path, &pid_file, &log_file) {
            eprintln!("Ошибка запуска демона: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Режим launcher
    match cli.command {
        CommandType::Auto => {
            // Проверяем статус демона
            if is_process_running(&pid_file) {
                println!("Демон запущен");
                if let Ok(pid) = fs::read_to_string(&pid_file) {
                    println!("PID: {}", pid.trim());
                }
                println!("\nТекущая конфигурация:");
                match load_config(&config_path) {
                    Ok(config) => {
                        for folder in config.folders {
                            println!("Source: {}", folder.source);
                            println!("Destination: {}", folder.destination);
                            println!("---");
                        }
                    }
                    Err(e) => {
                        eprintln!("Ошибка чтения конфигурации: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("Демон не запущен");
                println!("\nИспользуйте команду 'start' для запуска демона");
            }
        }
        CommandType::Start => {
            match start_daemon(&config_path, &pid_file, &log_file) {
                Ok(()) => println!("Демон успешно запущен"),
                Err(e) => {
                    eprintln!("Ошибка запуска демона: {}", e);
                    std::process::exit(1);
                }
            }
        }
        CommandType::Stop => {
            match stop_daemon(&pid_file) {
                Ok(()) => println!("Демон успешно остановлен"),
                Err(e) => {
                    eprintln!("Ошибка остановки демона: {}", e);
                    std::process::exit(1);
                }
            }
        }
        CommandType::ReadConf => {
            eprintln!("Команда не предназначена для прямого использования");
            std::process::exit(1);
        }
    }
}
