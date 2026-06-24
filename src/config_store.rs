use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::{config::AppConfig, BoxError};

pub const SYSTEM_CONFIG_PATH: &str = "/etc/altura-prot/config.json";
pub const SYSTEM_STATE_DIR: &str = "/var/lib/altura-prot";
pub const USER_CONFIG_ENV: &str = "ALTURA_PROT_CONFIG";

pub fn default_config_path() -> PathBuf {
    if let Ok(path) = env::var(USER_CONFIG_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    let system = PathBuf::from(SYSTEM_CONFIG_PATH);
    if system.is_file() {
        return system;
    }
    let user = user_config_path();
    if user.is_file() {
        return user;
    }
    PathBuf::from("configs/example.json")
}

pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path)
}

pub fn user_config_path() -> PathBuf {
    if let Ok(path) = env::var(USER_CONFIG_ENV) {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("altura-prot")
            .join("config.json");
    }
    PathBuf::from("configs/example.json")
}

pub fn user_state_dir() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("altura-prot");
    }
    PathBuf::from("runtime")
}

pub fn load_json(path: &Path) -> Result<Value, BoxError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn write_json(path: &Path, value: &Value) -> Result<(), BoxError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rendered = serde_json::to_string_pretty(value)? + "\n";
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, rendered)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn validate_config_file(path: &Path) -> Result<AppConfig, BoxError> {
    AppConfig::from_path(path)
}

pub fn get_value<'a>(value: &'a Value, key_path: &str) -> Result<&'a Value, BoxError> {
    let mut current = value;
    if key_path.is_empty() {
        return Err("config key path must not be empty".into());
    }
    for segment in key_path.split('.') {
        if segment.is_empty() {
            return Err(format!("invalid config key path: {key_path}").into());
        }
        current = current
            .get(segment)
            .ok_or_else(|| format!("config key not found: {key_path}"))?;
    }
    Ok(current)
}

pub fn set_value(value: &mut Value, key_path: &str, new_value: Value) -> Result<(), BoxError> {
    let segments: Vec<&str> = key_path.split('.').collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(format!("invalid config key path: {key_path}").into());
    }
    let mut current = value;
    for segment in &segments[..segments.len() - 1] {
        let next = current
            .get_mut(*segment)
            .ok_or_else(|| format!("config key not found: {key_path}"))?;
        if !next.is_object() {
            return Err(format!("config key {key_path} is not an object path").into());
        }
        current = next;
    }
    let leaf = segments[segments.len() - 1];
    let Some(object) = current.as_object_mut() else {
        return Err(format!("config key {key_path} is not an object path").into());
    };
    object.insert(leaf.to_string(), new_value);
    Ok(())
}

pub fn parse_cli_value(raw: &str) -> Value {
    if let Ok(value) = serde_json::from_str(raw) {
        return value;
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Value::from(value);
    }
    if let Ok(value) = raw.parse::<f64>() {
        return Value::from(value);
    }
    match raw {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(raw.to_string()),
    }
}

pub fn format_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

const INSTALL_DEFAULT_CONFIG: &str = include_str!("../configs/install.default.json");

pub fn default_config_template(listen: &str, upstream: &str, state_dir: &Path) -> Value {
    let runtime_dir = state_dir.join("runtime");
    let mut value: Value = serde_json::from_str(INSTALL_DEFAULT_CONFIG)
        .expect("embedded install.default.json must be valid JSON");
    set_value(&mut value, "http.listen", Value::String(listen.to_string()))
        .expect("install template must contain http.listen");
    set_value(
        &mut value,
        "http.upstream",
        Value::String(upstream.to_string()),
    )
    .expect("install template must contain http.upstream");
    set_value(
        &mut value,
        "filters.runtime_file",
        Value::String(
            runtime_dir
                .join("filters.json")
                .to_string_lossy()
                .into_owned(),
        ),
    )
    .expect("install template must contain filters.runtime_file");
    set_value(
        &mut value,
        "adaptive.event_log",
        Value::String(
            runtime_dir
                .join("attack_events.jsonl")
                .to_string_lossy()
                .into_owned(),
        ),
    )
    .expect("install template must contain adaptive.event_log");
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_and_set_nested_values() {
        let mut value = serde_json::json!({
            "http": {
                "listen": "127.0.0.1:8080",
                "limits": { "per_ip_rps": 250 }
            }
        });
        assert_eq!(
            get_value(&value, "http.limits.per_ip_rps").unwrap(),
            &Value::from(250)
        );
        set_value(&mut value, "http.limits.per_ip_rps", Value::from(500)).unwrap();
        assert_eq!(
            get_value(&value, "http.limits.per_ip_rps").unwrap(),
            &Value::from(500)
        );
    }

    #[test]
    fn parse_cli_value_handles_common_types() {
        assert_eq!(parse_cli_value("500"), Value::from(500));
        assert_eq!(parse_cli_value("true"), Value::Bool(true));
        assert_eq!(
            parse_cli_value(r#"["127.0.0.1"]"#),
            Value::Array(vec![Value::String("127.0.0.1".to_string())])
        );
        assert_eq!(
            parse_cli_value("http://127.0.0.1:9000"),
            Value::String("http://127.0.0.1:9000".to_string())
        );
    }

    #[test]
    fn get_value_rejects_empty_and_missing_paths() {
        let value = serde_json::json!({ "http": { "listen": "127.0.0.1:8080" } });
        assert!(get_value(&value, "").is_err());
        assert!(get_value(&value, "http..listen").is_err());
        assert!(get_value(&value, "http.upstream").is_err());
    }

    #[test]
    fn set_value_rejects_non_object_path() {
        let mut value = serde_json::json!({ "http": { "listen": "127.0.0.1:8080" } });
        // `listen` is a scalar, so descending through it is an error.
        assert!(set_value(&mut value, "http.listen.port", Value::from(1)).is_err());
        assert!(set_value(&mut value, "", Value::from(1)).is_err());
    }

    #[test]
    fn default_config_template_is_valid_and_wired_to_state_dir() {
        let dir =
            std::env::temp_dir().join(format!("altura-prot-store-template-{}", std::process::id()));
        let runtime_dir = dir.join("runtime");
        let template = default_config_template("0.0.0.0:8080", "http://127.0.0.1:9000", &dir);

        assert_eq!(
            get_value(&template, "http.listen").unwrap(),
            &Value::from("0.0.0.0:8080")
        );
        assert_eq!(
            get_value(&template, "http.upstream").unwrap(),
            &Value::from("http://127.0.0.1:9000")
        );
        assert_eq!(
            get_value(&template, "filters.runtime_file").unwrap(),
            &Value::from(runtime_dir.join("filters.json").to_string_lossy().as_ref())
        );
        assert_eq!(
            get_value(&template, "adaptive.event_log").unwrap(),
            &Value::from(
                runtime_dir
                    .join("attack_events.jsonl")
                    .to_string_lossy()
                    .as_ref()
            )
        );

        let cfg_path = dir.join("config.json");
        write_json(&cfg_path, &template).unwrap();
        validate_config_file(&cfg_path).expect("rendered template must validate");
        assert_eq!(load_json(&cfg_path).unwrap(), template);
        fs::remove_dir_all(&dir).ok();
    }
}
