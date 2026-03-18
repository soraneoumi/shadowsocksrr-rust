use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub obfs: ObfsConfig,
    pub protocol: ProtocolConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default)]
    pub redirect: Vec<String>,
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default = "default_read_buf")]
    pub read_buffer_size: usize,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default = "default_udp_enabled")]
    pub udp_enabled: bool,
    #[serde(default)]
    pub udp_listen: Option<String>,
    #[serde(default = "default_udp_timeout_secs")]
    pub udp_timeout_secs: u64,
    #[serde(default = "default_udp_max_associations")]
    pub udp_max_associations: usize,
    #[serde(default = "default_replay_max_entries")]
    pub replay_max_entries: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObfsConfig {
    #[serde(default = "default_obfs_method")]
    pub method: String,
    #[serde(default)]
    pub obfs_param: String,
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolConfig {
    pub method: String,
    #[serde(alias = "key")]
    pub password: String,
    #[serde(default)]
    pub protocol_param: String,
    #[serde(default = "default_tcp_mss")]
    pub tcp_mss: u16,
    #[serde(default = "default_overhead")]
    pub overhead: u16,
    #[serde(default)]
    pub users: HashMap<String, String>,
}

fn default_read_buf() -> usize {
    64 * 1024
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn default_cipher() -> String {
    "none".to_string()
}

fn default_obfs_method() -> String {
    "tls1.2_ticket_auth".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_tcp_mss() -> u16 {
    0
}

fn default_overhead() -> u16 {
    4
}

fn default_udp_enabled() -> bool {
    true
}

fn default_udp_timeout_secs() -> u64 {
    180
}

fn default_udp_max_associations() -> usize {
    65536
}

fn default_max_tcp_connections() -> usize {
    65536
}

fn default_replay_max_entries() -> usize {
    1048576
}

fn is_supported_protocol_method(method: &str) -> bool {
    matches!(
        method,
        "auth_chain_d"
            | "auth_chain_e"
            | "auth_chain_f"
            | "auth_akarin_rand"
            | "auth_akarin_spec_a"
    )
}

impl Default for ObfsConfig {
    fn default() -> Self {
        Self {
            method: default_obfs_method(),
            obfs_param: String::new(),
            host: String::new(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        let config: Self = toml::from_str(&text).with_context(|| "failed to parse TOML config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol.password.trim().is_empty() {
            anyhow::bail!("protocol.password must not be empty");
        }
        if !is_supported_protocol_method(self.protocol.method.trim()) {
            anyhow::bail!(
                "unsupported legacy protocol.method `{}`",
                self.protocol.method
            );
        }
        Ok(())
    }

    pub fn user_map_bytes(&self) -> HashMap<u32, Vec<u8>> {
        self.protocol
            .users
            .iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|id| (id, v.as_bytes().to_vec())))
            .collect()
    }

    pub fn udp_listen_addr(&self) -> String {
        self.server
            .udp_listen
            .clone()
            .unwrap_or_else(|| self.server.listen.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::AppConfig;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!("ssrr-{name}-{nonce}.toml"))
    }

    #[test]
    fn parses_protocol_password() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"
            "#,
        )
        .expect("parse config");

        config.validate().expect("validate config");
        assert_eq!(config.protocol.password, "demo-pass");
    }

    #[test]
    fn accepts_legacy_protocol_key_alias() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_akarin_spec_a"
                key = "legacy-pass"
            "#,
        )
        .expect("parse config");

        config.validate().expect("validate config");
        assert_eq!(config.protocol.password, "legacy-pass");
    }

    #[test]
    fn rejects_empty_protocol_password() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "   "
            "#,
        )
        .expect("parse config");

        let err = config.validate().expect_err("empty password should fail");
        assert!(
            err.to_string().contains("protocol.password"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_legacy_shared_password_without_obfs_password() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [obfs]
                method = "tls1.2_ticket_auth"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"
            "#,
        )
        .expect("parse config");

        config
            .validate()
            .expect("shared password should be accepted");
    }

    #[test]
    fn server_limits_have_safe_defaults() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"
            "#,
        )
        .expect("parse config");

        assert_eq!(config.server.max_tcp_connections, 65536);
        assert_eq!(config.server.replay_max_entries, 1048576);
    }

    #[test]
    fn app_config_loads_minimal_valid_file() {
        let path = temp_config_path("load-minimal");
        fs::write(
            &path,
            r#"
                [server]
                listen = "127.0.0.1:443"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"
            "#,
        )
        .expect("write temp config");

        let loaded = AppConfig::load(&path).expect("config should load");
        let _ = fs::remove_file(&path);

        assert_eq!(loaded.server.listen, "127.0.0.1:443");
        assert_eq!(loaded.protocol.password, "demo-pass");
        assert_eq!(loaded.obfs.method, "tls1.2_ticket_auth");
        assert_eq!(loaded.logging.level, "info");
    }

    #[test]
    fn user_map_bytes_preserves_all_configured_users() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"

                [protocol.users]
                "1001" = "alpha"
                "1002" = "beta"
                "invalid" = "ignored"
            "#,
        )
        .expect("parse config");

        let users = config.user_map_bytes();
        assert_eq!(users.len(), 2);
        assert_eq!(users.get(&1001), Some(&b"alpha".to_vec()));
        assert_eq!(users.get(&1002), Some(&b"beta".to_vec()));
    }

    #[test]
    fn udp_listen_addr_defaults_to_tcp_listen() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"
                udp_enabled = true

                [protocol]
                method = "auth_akarin_spec_a"
                password = "demo-pass"
            "#,
        )
        .expect("parse config");

        assert_eq!(config.udp_listen_addr(), "0.0.0.0:443");
    }

    #[test]
    fn rejects_unsupported_protocol_methods() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                listen = "0.0.0.0:443"

                [protocol]
                method = "auth_removed_protocol"
                password = "demo-pass"
            "#,
        )
        .expect("parse config");

        let err = config
            .validate()
            .expect_err("unsupported methods should be rejected");
        assert!(
            err.to_string().contains("unsupported legacy protocol.method"),
            "unexpected error: {err}"
        );
    }
}
