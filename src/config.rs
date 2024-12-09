use serde::Deserialize;
use std::fs;
use std::io;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub folders: Vec<FolderConfig>,
}

#[derive(Debug, Deserialize)]
pub struct FolderConfig {
    pub source: String,
    pub destination: String,
}

pub fn read_config(path: &str) -> Result<Config, io::Error> {
    let config_data = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&config_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(config)
}
