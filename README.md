# FSCopyMon (File System Copy Monitor)

A robust, cross-platform file system monitoring and synchronization utility written in Rust. FSCopyMon watches specified source directories and automatically synchronizes their contents to designated destination directories in real-time.

## Features

- Real-time file system monitoring and synchronization
- Cross-platform support (Windows and Unix)
- Daemon mode operation
- Configurable logging levels
- JSON-based configuration
- Graceful shutdown handling

## Installation

Ensure you have Rust installed on your system, then:

```bash
cargo build --release
```

The compiled binary will be available in `target/release/fscopymon`.

## Usage

```bash
fscopymon [OPTIONS]

Options:
  -c, --config <FILE>      Config file path [default: config.json]
  -p, --pid-file <FILE>    PID file path [default: fscopymon.pid]
  -l, --log-level <LEVEL>  Log level (error/warn/info/debug/trace) [default: info]
  -f, --log-file <FILE>    Log file path
      --start             Start the daemon
      --stop              Stop the daemon
  -h, --help              Print help
  -V, --version           Print version
```

## Configuration

Create a `config.json` file with the following structure:

```json
{
  "folders": [
    {
      "source": "/path/to/source/directory",
      "destination": "/path/to/destination/directory"
    }
  ]
}
```

Multiple source-destination pairs can be specified in the configuration.

## Key Components

- **Main Module**: Entry point and CLI argument handling
- **Config Module**: JSON configuration file parsing
- **Daemon Module**: Daemon process management
- **File Operations**: Directory synchronization logic
- **Watcher**: File system event monitoring

## Dependencies

- clap: Command-line argument parsing
- notify: File system event monitoring
- serde: JSON serialization/deserialization
- log & env_logger: Logging functionality
- ctrlc: Signal handling
- Platform-specific dependencies for Windows and Unix systems

## License

[Insert your chosen license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
