use notify::{Watcher, RecursiveMode, Result as NotifyResult, EventKind};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;

#[derive(Deserialize)]
struct Config {
    folders: Vec<FolderConfig>,
}

#[derive(Deserialize)]
struct FolderConfig {
    source: String,
    destination: String,
}

fn load_config(path: &str) -> Result<Config, std::io::Error> {
    let config_data = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&config_data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(config)
}

fn copy_file(src: &Path, dest: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?; // Создаём директории, если они отсутствуют
    }
    fs::copy(src, dest)?;
    println!("Скопирован файл: {} -> {}", src.display(), dest.display());
    Ok(())
}

fn start_watching(config: Config) -> NotifyResult<()> {
    let (tx, rx) = channel();

    // Создаем наблюдатель
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Err(e) = tx.send(res) {
            eprintln!("Ошибка отправки события: {:?}", e);
        }
    })?;

    // Настраиваем наблюдение для всех указанных папок
    for folder in &config.folders {
        watcher.watch(Path::new(&folder.source), RecursiveMode::NonRecursive)?;
        println!("Мониторинг папки: {}", folder.source);
    }

    println!("Мониторинг начат...");

    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(event)) => {
                // Получение списка путей (в event.paths это Vec<PathBuf>, не Option<Vec<PathBuf>>)
                for path in event.paths {
                    if let EventKind::Create(_) = event.kind {
                        for folder in &config.folders {
                            if path.starts_with(&folder.source) {
                                let relative_path = path.strip_prefix(&folder.source).unwrap();
                                let dest_path = PathBuf::from(&folder.destination).join(relative_path);
                                if let Err(e) = copy_file(&path, &dest_path) {
                                    eprintln!("Ошибка копирования файла {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => eprintln!("Ошибка наблюдения: {:?}", e),
            Err(_) => continue, // Тайм-аут, ждем новых событий
        }
    }
}

fn main() {
    let config_path = "config.json";

    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Ошибка загрузки конфигурации: {}", e);
            return;
        }
    };

    if let Err(e) = start_watching(config) {
        eprintln!("Ошибка при мониторинге: {:?}", e);
    }
}
