use std::fs;
use std::io;
use std::path::Path;
use log::{debug, error};

pub fn sync_directory(source: &Path, destination: &Path) -> io::Result<()> {
    if !source.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Source directory does not exist: {:?}", source),
        ));
    }

    if !destination.exists() {
        fs::create_dir_all(destination)?;
    }

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let dest_path = destination.join(path.file_name().unwrap());

        if path.is_file() {
            match fs::copy(&path, &dest_path) {
                Ok(_) => debug!("Copied {:?} to {:?}", path, dest_path),
                Err(e) => error!("Failed to copy {:?} to {:?}: {}", path, dest_path, e),
            }
        } else if path.is_dir() {
            match sync_directory(&path, &dest_path) {
                Ok(_) => debug!("Synced directory {:?} to {:?}", path, dest_path),
                Err(e) => error!("Failed to sync directory {:?} to {:?}: {}", path, dest_path, e),
            }
        }
    }

    Ok(())
}
