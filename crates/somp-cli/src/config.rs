//! Config: ~/.config/somp/config.yaml + session state file. Fail-closed defaults.

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::aiec::Client;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub aiec: AIecCfg,
    #[serde(default)]
    pub session: SessionCfg,
    #[serde(default)]
    pub guard: GuardCfg,
    #[serde(default)]
    pub srt: SrtCfg,
    #[serde(default)]
    pub security: SecurityCfg,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AIecCfg {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub api_key_env: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionCfg {
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default = "default_cpu")]
    pub cpus: u32,
    #[serde(default = "default_mem")]
    pub mem_mb: u32,
    #[serde(default = "default_disk")]
    pub disk_mb: u32,
    /// Renew-before-expiry window; AIec bounds sandbox lifetime (MAX 86400s).
    #[serde(default = "default_ttl")]
    pub ttl_s: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuardCfg {
    #[serde(default = "default_template")]
    pub template: String,
    /// Model endpoint for the model-only template (REQUIRED server-side:
    /// GuardPolicy::template(ModelOnly, None, _) is an error). No default:
    /// inventing an endpoint would aim the sandbox at a wrong provider.
    /// Set guard.model_host + guard.model_port in config.yaml.
    pub model_host: Option<String>,
    pub model_port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SrtCfg {
    #[serde(default = "default_srt_settings")]
    pub settings_path: PathBuf,
}
/// Governed security level: what the subagent sandbox enforces.
/// Env SOMP_LEVEL overrides config file (strict > standard > off).
/// Fail-closed: unknown values refuse to parse; `off` refuses governed work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    /// Full stack: Firecracker microVM + Guard model-only + srt inner sandbox.
    #[default]
    Strict,
    /// Docker worker + Guard + srt (dev only: no microVM boundary).
    Standard,
    /// No sandboxing: local process only. dispatch/session refuse to run.
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityCfg {
    #[serde(default)]
    pub level: SecurityLevel,
}
impl Default for SecurityCfg {
    fn default() -> Self {
        Self { level: SecurityLevel::Strict }
    }
}

impl SecurityLevel {
    /// Effective level: SOMP_LEVEL env wins over config file. Unknown values
    /// are a hard error (fail-closed: never guess a security posture).
    pub fn effective(configured: SecurityLevel) -> Result<SecurityLevel> {
        match std::env::var("SOMP_LEVEL").as_deref() {
            Ok("") | Err(_) => Ok(configured),
            Ok("strict") => Ok(SecurityLevel::Strict),
            Ok("standard") => Ok(SecurityLevel::Standard),
            Ok("off") => Ok(SecurityLevel::Off),
            Ok(other) => anyhow::bail!("SOMP_LEVEL must be strict|standard|off, got {other:?}"),
        }
    }

    pub fn badge(self) -> &'static str {
        match self {
            SecurityLevel::Strict => "STRICT",
            SecurityLevel::Standard => "STANDARD",
            SecurityLevel::Off => "OFF",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            SecurityLevel::Strict => "Firecracker microVM + Guard model-only + srt",
            SecurityLevel::Standard => "Docker worker + Guard + srt (dev only, no microVM)",
            SecurityLevel::Off => "no sandboxing — governed work refused",
        }
    }
}

fn default_base_url() -> String {
    "http://127.0.0.1:8080".into()
}
fn default_image() -> String {
    "somp-guest".into()
}
fn default_cpu() -> u32 {
    2
}
fn default_mem() -> u32 {
    1024
}
fn default_disk() -> u32 {
    4096
}
fn default_ttl() -> u64 {
    82800
}
fn default_template() -> String {
    "model-only".into()
}
fn default_srt_settings() -> PathBuf {
    PathBuf::from("guest/srt-settings.json")
}

impl Default for AIecCfg {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            key_file: None,
            api_key_env: "AIEC_API_KEY".into(),
        }
    }
}
impl Default for SessionCfg {
    fn default() -> Self {
        Self {
            image: default_image(),
            cpus: default_cpu(),
            mem_mb: default_mem(),
            disk_mb: default_disk(),
            ttl_s: default_ttl(),
        }
    }
}
impl Default for GuardCfg {
    fn default() -> Self {
        Self {
            template: default_template(),
            model_host: None,
            model_port: None,
        }
    }
}
impl Default for SrtCfg {
    fn default() -> Self {
        Self {
            settings_path: default_srt_settings(),
        }
    }
}

#[derive(Debug, Args)]
pub struct SessionArgs {
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long)]
    pub cpus: Option<u32>,
    #[arg(long)]
    pub mem: Option<u32>,
}

pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".config"));
    base.join("somp").join("config.yaml")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/root"))
}

pub fn state_path() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".local").join("state"));
    base.join("somp").join("session.json")
}

pub fn load() -> Result<Config> {
    let p = config_path();
    if !p.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("parse {}", p.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn session_state_load() -> Result<Option<SessionState>> {
    let p = state_path();
    if !p.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&p)?;
    Ok(Some(serde_json::from_str(&text)?))
}

pub fn session_state_store(id: uuid::Uuid) -> Result<()> {
    let p = state_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let st = SessionState {
        id,
        created_at: chrono::Utc::now(),
    };
    std::fs::write(&p, serde_json::to_string_pretty(&st)?)?;
    Ok(())
}

pub fn session_state_clear() -> Result<()> {
    let p = state_path();
    if p.exists() {
        std::fs::remove_file(&p)?;
    }
    Ok(())
}

impl Config {
    pub fn aiec_client(&self) -> Result<Client> {
        let key = if let Some(f) = &self.aiec.key_file {
            std::fs::read_to_string(f)
                .with_context(|| format!("read AIec key file {}", f.display()))?
                .trim()
                .to_owned()
        } else if self.aiec.api_key_env.is_empty() {
            anyhow::bail!("no AIec key: set aiec.key_file or aiec.api_key_env in {}", config_path().display())
        } else {
            std::env::var(&self.aiec.api_key_env).with_context(|| {
                format!(
                    "env {} unset and no key_file configured (see {})",
                    self.aiec.api_key_env,
                    config_path().display()
                )
            })?
        };
        if key.is_empty() {
            anyhow::bail!("empty AIec API key; refusing to run unauthenticated");
        }
        Client::new(self.aiec.base_url.clone(), key)
    }

    /// Guard clause shared by both builders. Verified against AIec source:
    /// - network wire format is {enabled:bool, allowed_hosts?} (aiec-core
    ///   network.rs Serialize impl); guarded sandboxes carry NO guest NIC —
    ///   the model path is brokered via the worker gateway (aiec-cli main.rs
    ///   sets NetworkPolicy::Disabled alongside resources.guard).
    /// - environment.guard is a GuardConfig: {policy_template (kebab-case),
    ///   model_endpoint?} (aiec-guard policy.rs). ModelOnly REQUIRES an
    ///   endpoint (template(ModelOnly, None, _) is Err) — missing config is
    ///   a build-time bail, never a silent no-network downgrade.
    fn guard_json(&self) -> Result<serde_json::Value> {
        let template = self.guard.template.clone();
        let mut guard = serde_json::json!({ "policy_template": template });
        if template == "model-only" || template == "model-plus-allowlist" {
            let (Some(host), Some(port)) = (self.guard.model_host.clone(), self.guard.model_port) else {
                anyhow::bail!(
                    "guard template {template:?} needs guard.model_host + guard.model_port \
                     in config.yaml (server refuses ModelOnly without an endpoint)"
                );
            };
            guard["model_endpoint"] = serde_json::json!({ "host": host, "port": port });
        }
        Ok(guard)
    }

    pub fn session_create_request(&self, args: &SessionArgs) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "image": args.image.clone().unwrap_or_else(|| self.session.image.clone()),
            "cpu": args.cpus.unwrap_or(self.session.cpus),
            "memory_mb": args.mem.unwrap_or(self.session.mem_mb),
            "disk_mb": self.session.disk_mb,
            "timeout_seconds": self.session.ttl_s,
            "network": { "enabled": false },
            "environment": { "guard": self.guard_json()? },
        }))
    }

    /// Disposable subagent sandbox: model-endpoint-only Guard, tight TTL.
    /// (No task label: upstream CreateSandboxRequest has no name/label slot;
    /// the sandbox id returned at create is the correlation handle.)
    pub fn subagent_create_request(
        &self,
        cpus: u32,
        mem_mb: u32,
        timeout_s: u64,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "image": self.session.image.clone(),
            "cpu": cpus,
            "memory_mb": mem_mb,
            "disk_mb": self.session.disk_mb,
            "timeout_seconds": timeout_s,
            "network": { "enabled": false },
            "environment": { "guard": self.guard_json()? },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governed_cfg() -> Config {
        let mut c = Config::default();
        c.guard.model_host = Some("api.example-model.com".into());
        c.guard.model_port = Some(443);
        c
    }

    #[test]
    fn defaults_are_governed() {
        let c = governed_cfg();
        assert_eq!(c.guard.template, "model-only");
        let req = c.session_create_request(&SessionArgs {
            image: None,
            cpus: None,
            mem: None,
        }).unwrap();
        assert_eq!(req["network"], serde_json::json!({"enabled": false}));
        assert_eq!(req["environment"]["guard"]["policy_template"], serde_json::json!("model-only"));
        assert_eq!(req["environment"]["guard"]["model_endpoint"]["host"], serde_json::json!("api.example-model.com"));
    }

    #[test]
    fn missing_endpoint_is_build_error_not_downgrade() {
        let c = Config::default();
        assert!(c.session_create_request(&SessionArgs { image: None, cpus: None, mem: None }).is_err());
    }

    #[test]
    fn subagent_request_is_governed_short_lived() {
        let c = governed_cfg();
        let req = c.subagent_create_request(1, 512, 600).unwrap();
        assert_eq!(req["network"], serde_json::json!({"enabled": false}));
        assert_eq!(req["timeout_seconds"], serde_json::json!(600));
    }

    #[test]
    fn level_defaults_strict_and_badges() {
        assert_eq!(Config::default().security.level, SecurityLevel::Strict);
        assert_eq!(SecurityLevel::Strict.badge(), "STRICT");
        assert_eq!(SecurityLevel::Standard.badge(), "STANDARD");
        assert_eq!(SecurityLevel::Off.badge(), "OFF");
    }

    #[test]
    fn level_unknown_env_refuses() {
        let prev = std::env::var("SOMP_LEVEL").ok();
        std::env::set_var("SOMP_LEVEL", "paranoid!!");
        let r = SecurityLevel::effective(SecurityLevel::Strict);
        match prev {
            Some(v) => std::env::set_var("SOMP_LEVEL", v),
            None => std::env::remove_var("SOMP_LEVEL"),
        }
        assert!(r.is_err(), "unknown SOMP_LEVEL must fail closed, not guess");
    }
}
