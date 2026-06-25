use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use clap::{Parser, Subcommand};

use crate::{
    config_store::{
        default_config_template, format_value, get_value, load_json, parse_cli_value,
        resolve_config_path, set_value, user_config_path, user_state_dir, validate_config_file,
        write_json, SYSTEM_CONFIG_PATH, SYSTEM_STATE_DIR,
    },
    BoxError,
};

#[derive(Debug, Parser)]
#[command(
    name = "altura-prot",
    bin_name = "altura-prot",
    version,
    about = "AlturaProt L7 DDoS protection reverse proxy",
    after_help = "Alias: AlturaProt\n\nExamples:\n  altura-prot init --listen 0.0.0.0:8080 --upstream http://127.0.0.1:9000\n  altura-prot config set http.limits.per_ip_rps 500\n  altura-prot run\n  altura-prot status"
)]
pub struct Cli {
    /// Config file used by `run` (also accepts legacy `altura-prot --config ...`)
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the proxy server
    Run,
    /// Create config directories and a default config file
    Init {
        /// Install paths for /etc and /var/lib instead of user-local paths
        #[arg(long)]
        system: bool,
        /// HTTP listen address
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,
        /// HTTP upstream origin
        #[arg(long, default_value = "http://127.0.0.1:9000")]
        upstream: String,
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },
    /// Validate a config file
    Validate {
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Inspect or change configuration values
    #[command(subcommand)]
    Config(ConfigCommands),
    /// Show service or process status
    Status,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Print the active config file path
    Path {
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Print the full config as JSON
    Show {
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Read one config value by dot path
    Get {
        key: String,
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Set one config value by dot path
    Set {
        key: String,
        value: String,
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
}

pub fn execute(cli: Cli) -> Result<(), BoxError> {
    match cli.command {
        None | Some(Commands::Run) => Err("run is async; call execute_async".into()),
        Some(Commands::Init {
            system,
            listen,
            upstream,
            force,
        }) => init_config(system, &listen, &upstream, force),
        Some(Commands::Validate { config }) => {
            validate_command(resolve_cli_config(cli.config.as_deref(), config.as_deref()))
        }
        Some(Commands::Config(command)) => config_command(command, cli.config.as_deref()),
        Some(Commands::Status) => status_command(cli.config.as_deref()),
    }
}

fn resolve_cli_config(global: Option<&Path>, local: Option<&Path>) -> PathBuf {
    resolve_config_path(local.or(global))
}

pub async fn execute_async(cli: Cli) -> Result<(), BoxError> {
    match cli.command {
        None | Some(Commands::Run) => {
            let path = resolve_config_path(cli.config.as_deref());
            eprintln!("using config {}", path.display());
            crate::daemon::run(&path).await
        }
        other => {
            let cli = Cli {
                config: cli.config,
                command: other,
            };
            execute(cli)
        }
    }
}

fn init_config(system: bool, listen: &str, upstream: &str, force: bool) -> Result<(), BoxError> {
    let (config_path, state_dir) = if system {
        (
            PathBuf::from(SYSTEM_CONFIG_PATH),
            PathBuf::from(SYSTEM_STATE_DIR),
        )
    } else {
        (user_config_path(), user_state_dir())
    };

    if config_path.exists() && !force {
        return Err(format!(
            "config already exists at {}; use --force to overwrite",
            config_path.display()
        )
        .into());
    }

    fs::create_dir_all(state_dir.join("runtime"))?;
    let template = default_config_template(listen, upstream, &state_dir);
    write_json(&config_path, &template)?;
    validate_config_file(&config_path)?;

    println!("created config {}", config_path.display());
    println!("state directory {}", state_dir.display());
    println!("next steps:");
    println!("  altura-prot config set http.admin_token <secret>");
    if system {
        println!("  sudo systemctl enable --now altura-prot");
    } else {
        println!("  altura-prot run");
    }
    Ok(())
}

fn validate_command(path: PathBuf) -> Result<(), BoxError> {
    validate_config_file(&path)?;
    println!("config valid: {}", path.display());
    Ok(())
}

fn config_command(command: ConfigCommands, global_config: Option<&Path>) -> Result<(), BoxError> {
    match command {
        ConfigCommands::Path { config } => {
            let path = resolve_cli_config(global_config, config.as_deref());
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommands::Show { config } => {
            let path = resolve_cli_config(global_config, config.as_deref());
            let value = load_json(&path)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        ConfigCommands::Get { key, config } => {
            let path = resolve_cli_config(global_config, config.as_deref());
            let value = load_json(&path)?;
            println!("{}", format_value(get_value(&value, &key)?));
            Ok(())
        }
        ConfigCommands::Set { key, value, config } => {
            let path = resolve_cli_config(global_config, config.as_deref());
            let mut document = load_json(&path)?;
            set_value(&mut document, &key, parse_cli_value(&value))?;
            let tmp_path = path.with_extension("tmp");
            write_json(&tmp_path, &document)?;
            if let Err(err) = validate_config_file(&tmp_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
            fs::rename(&tmp_path, &path)?;
            println!("updated {} in {}", key, path.display());
            Ok(())
        }
    }
}

fn status_command(config: Option<&Path>) -> Result<(), BoxError> {
    if try_systemd_status()? {
        return Ok(());
    }

    let config_path = resolve_config_path(config);
    if config_path.is_file() {
        println!("config: {}", config_path.display());
    } else {
        println!("config: not found (run `altura-prot init` first)");
    }

    if let Some(pid) = find_running_pid() {
        println!("process: running (pid {pid})");
    } else {
        println!("process: not running");
    }
    Ok(())
}

fn try_systemd_status() -> Result<bool, BoxError> {
    if !Path::new("/run/systemd/system").exists() {
        return Ok(false);
    }
    let output = Command::new("systemctl")
        .args(["is-active", "altura-prot"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !output.success() {
        return Ok(false);
    }
    let status = Command::new("systemctl")
        .args(["status", "altura-prot", "--no-pager"])
        .status()?;
    if !status.success() {
        return Err("systemctl status altura-prot failed".into());
    }
    Ok(true)
}

fn find_running_pid() -> Option<u32> {
    let output = Command::new("pgrep")
        .args(["-x", "altura-prot"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().next()?.trim().parse().ok()
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn unique_temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("altura-prot-cli-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_template(dir: &Path) -> PathBuf {
        let cfg_path = dir.join("config.json");
        let template = default_config_template("127.0.0.1:8080", "http://127.0.0.1:9000", dir);
        write_json(&cfg_path, &template).unwrap();
        cfg_path
    }

    #[test]
    fn cli_has_expected_commands() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_set_then_get_round_trips() {
        let dir = unique_temp_dir("set");
        let cfg_path = write_template(&dir);

        config_command(
            ConfigCommands::Set {
                key: "http.limits.per_ip_rps".to_string(),
                value: "500".to_string(),
                config: Some(cfg_path.clone()),
            },
            None,
        )
        .unwrap();

        let document = load_json(&cfg_path).unwrap();
        assert_eq!(
            get_value(&document, "http.limits.per_ip_rps").unwrap(),
            &Value::from(500)
        );
        assert!(!cfg_path.with_extension("tmp").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_set_rejects_invalid_value_and_preserves_original() {
        let dir = unique_temp_dir("reject");
        let cfg_path = write_template(&dir);
        let original = load_json(&cfg_path).unwrap();

        // Negative rates fail config validation, so the write must be rolled back.
        let result = config_command(
            ConfigCommands::Set {
                key: "http.limits.per_ip_rps".to_string(),
                value: "-1".to_string(),
                config: Some(cfg_path.clone()),
            },
            None,
        );
        assert!(result.is_err());

        assert_eq!(load_json(&cfg_path).unwrap(), original);
        assert!(
            !cfg_path.with_extension("tmp").exists(),
            "stale tmp file left after rejected set"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validate_command_accepts_default_template() {
        let dir = unique_temp_dir("validate");
        let cfg_path = write_template(&dir);
        validate_command(cfg_path).unwrap();
        fs::remove_dir_all(&dir).ok();
    }
}
