use std::path::Path;
use std::sync::mpsc::channel;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config as NotifyConfig};
use log::{debug, error, info};
use crate::config::Config;
use crate::file_operations;

pub fn start_watching(config: Config) -> std::io::Result<()> {
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        tx,
        NotifyConfig::default(),
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    for folder in &config.folders {
        let source_path = Path::new(&folder.source);
        if !source_path.exists() {
            error!("Source path does not exist: {:?}", source_path);
            continue;
        }

        match watcher.watch(source_path, RecursiveMode::Recursive) {
            Ok(_) => info!("Started watching {:?}", source_path),
            Err(e) => error!("Failed to watch {:?}: {}", source_path, e),
        }

        // Initial sync
        let dest_path = Path::new(&folder.destination);
        if let Err(e) = file_operations::sync_directory(source_path, dest_path) {
            error!("Initial sync failed for {:?}: {}", source_path, e);
        }
    }

    info!("Monitoring started...");

    // Keep watcher alive and process events
    let _keep_watcher = watcher;
    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                debug!("Change detected: {:?}", event);
                for folder in &config.folders {
                    let source = Path::new(&folder.source);
                    let dest = Path::new(&folder.destination);
                    if let Err(e) = file_operations::sync_directory(source, dest) {
                        error!("Sync failed after change: {}", e);
                    }
                }
            }
            Ok(Err(e)) => error!("Watch error: {}", e),
            Err(e) => {
                error!("Channel error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
