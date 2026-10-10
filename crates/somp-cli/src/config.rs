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
    pub jev: JevCfg,
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
    /// Set guard.model_host + guard.model_port in config.yaml, or
    /// `somp model set <host> [port]`. Built-in preset: `somp model preset
    /// muse-spark` pins opencode.ai:443 (catalog baseUrl
    /// https://opencode.ai/zen/go/v1, verified in omp models.json).
    pub model_host: Option<String>,
    pub model_port: Option<u16>,
    /// Credential header Guard substitutes the secret into. Default
    /// "authorization" (template path). The muse-spark preset pins
    /// "x-api-key": omp's own wire code drops the auto-built Authorization
    /// header for opencode-go and emits X-Api-Key instead (packages/ai/src/
    /// providers/anthropic.ts, issue #6510), while the ModelOnly template
    /// hardcodes header=authorization (aiec-guard policy.rs template()).
    /// Any non-authorization value switches guard_json to an explicit
    /// GuardPolicy (the template path cannot express another header).
    #[serde(default = "default_credential_header")]
    pub model_credential_header: String,
    /// Path prefix the guest model path must live under. Default "/v1/".
    /// The muse-spark preset pins "/zen/go/v1/": the gateway forwards the
    /// stripped guest path verbatim ({scheme}://{host}:{port}{path}), and
    /// spark's responses API lives at https://opencode.ai/zen/go/v1, so the
    /// guest must address .../model/model-main/zen/go/v1 as its base.
    #[serde(default = "default_model_path")]
    pub model_path: String,
}

/// JEV bash-gate config: classifier that must Allow a command before exec.
/// Env TYPESAFE_API_KEY wins for the key (SDK convention, never baked in).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JevCfg {
    /// Classifier on/off. Default false (designed-not-wired → now wired,
    /// but opt-in until TYPESAFE_API_KEY is provisioned).
    #[serde(default)]
    pub enabled: bool,
    /// Model pinned so thresholds stay stable (docs: pin in production).
    #[serde(default = "default_jev_model")]
    pub model: String,
    /// Confirm-if-p(destructive) threshold. Default 0.15 (Jev docs pin).
    #[serde(default = "default_jev_threshold")]
    pub threshold: f64,
    /// Explicit operator escape hatch: allow ungoverned bash (audited).
    #[serde(default)]
    pub allow_ungoverned_bash: bool,
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
            SecurityLevel::Strict => "Firecracker microVM + Guard model-only + srt (needs worker egress caps)",
            SecurityLevel::Standard => "Docker container, NO network interface, srt (no Guard broker)",
            SecurityLevel::Off => "no sandboxing — governed work refused",
        }
    }


    /// Worker runtime this level dispatches to. Standard is honestly docker:
    /// previously both levels hardcoded firecracker, so `standard` lied about
    /// relaxing the microVM boundary.
    pub fn runtime(self) -> &'static str {
        match self {
            SecurityLevel::Strict => "firecracker",
            SecurityLevel::Standard => "docker",
            SecurityLevel::Off => "none",
        }
    }

    /// Tier enforcement per level: strict needs KVM-backed Firecracker;
    /// standard accepts any host (the Docker boundary lives on the worker).
    /// Off never reaches here (require_level bails first).
    pub fn require_tier(self, t: &crate::tier::TierCheck) -> Result<()> {
        match self {
            SecurityLevel::Strict => t.require_governed(),
            SecurityLevel::Standard => Ok(()),
            SecurityLevel::Off => anyhow::bail!("fail-closed: level is OFF"),
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
fn default_credential_header() -> String {
    "authorization".into()
}
fn default_model_path() -> String {
    "/v1/".into()
}
fn default_jev_model() -> String {
    "jev-latest".into()
}
fn default_jev_threshold() -> f64 {
    crate::jev_gate::P_DESTRUCTIVE_THRESHOLD
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
            model_credential_header: default_credential_header(),
            model_path: default_model_path(),
        }
    }
}
impl Default for JevCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_jev_model(),
            threshold: default_jev_threshold(),
            allow_ungoverned_bash: false,
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
    /// - environment.guard is a GuardConfig (aiec-guard policy.rs): either a
    ///   template ({policy_template kebab-case, model_endpoint?}) or an
    ///   explicit {policy}. ModelOnly REQUIRES an endpoint
    ///   (template(ModelOnly, None, _) is Err) — missing config is a
    ///   build-time bail, never a silent no-network downgrade.
    /// - Template path hardcodes credential header=authorization (policy.rs
    ///   template()). muse-spark needs x-api-key (omp drops Authorization
    ///   for opencode-go, #6510): any non-authorization header switches to
    ///   an explicit GuardPolicy pinning the same destination + header, with
    ///   POST-only + path prefix + binding-agrees-with-model + zone-covers-
    ///   egress invariants (policy.rs validate_model_binding,
    ///   validate_dns_egress_consistency). Request carries names only — the
    ///   secret lives in the worker-host file (AIEC_GUARD_CREDENTIALS_FILE).
    fn guard_json(&self) -> Result<serde_json::Value> {
        let template = self.guard.template.clone();
        let (Some(host), Some(port)) = (self.guard.model_host.clone(), self.guard.model_port) else {
            anyhow::bail!(
                "guard template {template:?} needs guard.model_host + guard.model_port \
                 in config.yaml (server refuses ModelOnly without an endpoint)"
            );
        };
        let header = self.guard.model_credential_header.clone();
        let path = self.guard.model_path.clone();
        if header.eq_ignore_ascii_case("authorization") && template == "model-only" && path == "/v1/" {
            return Ok(serde_json::json!({
                "policy_template": template,
                "model_endpoint": { "host": host, "port": port },
            }));
        }
        // Explicit policy: the template path cannot express a non-default
        // header or path. Shape pinned to GuardPolicy::validate() rules:
        // version 1, single egress rule + matching DNS zone + bound
        // credential, POST-only, explicit path prefix.
        if !path.starts_with('/') || path.contains(' ') || path.contains(|c: char| c.is_ascii_control()) {
            anyhow::bail!("guard.model_path {path:?} must start with '/' with no spaces/controls");
        }
        let header_lc = header.to_ascii_lowercase();
        if header_lc != "authorization" && header_lc != "x-api-key" {
            anyhow::bail!("guard.model_credential_header {header:?}: want authorization|x-api-key");
        }
        Ok(serde_json::json!({
            "topology": "inside",
            "policy": {
                "version": 1,
                "network": {
                    "dns": { "allowed_zones": [host], "allowed_record_types": ["A", "AAAA"] },
                    "egress": [{
                        "host": host, "port": port, "protocol": "tcp",
                        "allowed_methods": ["POST"], "allowed_paths": [path],
                    }],
                },
                "model": {
                    "host": host, "port": port, "scheme": "https",
                    "allowed_methods": ["POST"], "allowed_paths": [path],
                    "credential": "model-main",
                },
                "credentials": [{
                    "name": "model-main", "host": host, "port": port, "header": header_lc,
                }],
            },
        }))
    }

    /// Guard env per level (verified against AIec source 2026-10-10):
    /// - Strict pins firecracker + Guard: full sOMP boundary. Needs a worker
    ///   that can enforce egress (nft/CAP_NET_ADMIN on the worker host); the
    ///   plane fail-closes at placement otherwise — never silently ungoverned.
    /// - Standard runs Docker WITHOUT a guard env: Docker hardcodes
    ///   `network_policy:false` (docker.rs capabilities) so the scheduler can
    ///   never place guarded work on it, even with
    ///   AIEC_ALLOW_REDUCED_ISOLATION=1 (that flag only clears admission, not
    ///   placement). With `network.enabled=false` the guest gets NO network
    ///   interface at all, so egress is impossible by absence; container +
    ///   srt still bound the damage a malicious task can do. Documented in
    ///   `describe()`, never presented as Guard-enforced.
    fn environment_json(&self, level: SecurityLevel) -> Result<serde_json::Value> {
        match level {
            SecurityLevel::Strict => Ok(serde_json::json!({ "guard": self.guard_json()? })),
            SecurityLevel::Standard => Ok(serde_json::json!({})),
            SecurityLevel::Off => anyhow::bail!("fail-closed: level is OFF"),
        }
    }

    pub fn session_create_request(&self, args: &SessionArgs) -> Result<serde_json::Value> {
        let level = SecurityLevel::effective(self.security.level)?;
        Ok(serde_json::json!({
            "image": args.image.clone().unwrap_or_else(|| self.session.image.clone()),
            "cpu": args.cpus.unwrap_or(self.session.cpus),
            "memory_mb": args.mem.unwrap_or(self.session.mem_mb),
            "disk_mb": self.session.disk_mb,
            "timeout_seconds": self.session.ttl_s,
            "network": { "enabled": false },
            "environment": self.environment_json(level)?,
        }))
    }

    /// Disposable subagent sandbox: Guard on strict, no-NIC container on
    /// standard (see environment_json). Tight TTL.
    /// (No task label: upstream CreateSandboxRequest has no name/label slot;
    /// the sandbox id returned at create is the correlation handle.)
    pub fn subagent_create_request(
        &self,
        cpus: u32,
        mem_mb: u32,
        timeout_s: u64,
    ) -> Result<serde_json::Value> {
        let level = SecurityLevel::effective(self.security.level)?;
        Ok(serde_json::json!({
            "image": self.session.image.clone(),
            "cpu": cpus,
            "memory_mb": mem_mb,
            "disk_mb": self.session.disk_mb,
            "timeout_seconds": timeout_s,
            "network": { "enabled": false },
            "environment": self.environment_json(level)?,
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

    fn scrub_somp_level() -> Option<String> {
        // SOMP_LEVEL env wins over the config struct: every request-builder
        // test must scrub it first or the dev shell's export leaks in.
        // Returns the previous value for restore.
        let prev = std::env::var("SOMP_LEVEL").ok();
        std::env::remove_var("SOMP_LEVEL");
        prev
    }
    fn restore_somp_level(prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var("SOMP_LEVEL", v),
            None => std::env::remove_var("SOMP_LEVEL"),
        }
    }

    #[test]
    fn defaults_are_governed() {
        let prev = scrub_somp_level();
        let c = governed_cfg();
        assert_eq!(c.guard.template, "model-only");
        let req = c.session_create_request(&SessionArgs {
            image: None,
            cpus: None,
            mem: None,
        }).unwrap();
        let ok = req["network"] == serde_json::json!({"enabled": false})
            && req["environment"]["guard"]["policy_template"] == serde_json::json!("model-only")
            && req["environment"]["guard"]["model_endpoint"]["host"] == serde_json::json!("api.example-model.com");
        restore_somp_level(prev);
        assert!(ok, "default strict request must pin guard policy + endpoint");
    }
    #[test]
    fn missing_endpoint_is_build_error_not_downgrade() {
        let prev = scrub_somp_level();
        let c = Config::default();
        let r = c.session_create_request(&SessionArgs { image: None, cpus: None, mem: None }).is_err();
        restore_somp_level(prev);
        assert!(r, "model-only without endpoint must bail, never downgrade");
    }

    #[test]
    fn subagent_request_is_governed_short_lived() {
        let prev = scrub_somp_level();
        let c = governed_cfg();
        let req = c.subagent_create_request(1, 512, 600).unwrap();
        let ok = req["network"] == serde_json::json!({"enabled": false})
            && req["timeout_seconds"] == serde_json::json!(600);
        restore_somp_level(prev);
        assert!(ok, "subagent request must pin no-NIC + TTL");
    }
    #[test]
    fn standard_request_has_empty_environment() {
        let prev = scrub_somp_level();
        let mut c = governed_cfg();
        c.security.level = SecurityLevel::Standard;
        let req = c.subagent_create_request(1, 512, 600).unwrap();
        let ok = req["environment"] == serde_json::json!({});
        restore_somp_level(prev);
        assert!(ok, "standard environment must be empty {{}}");
    }

    #[test]
    fn strict_request_pins_guard_template() {
        let prev = scrub_somp_level();
        let mut c = governed_cfg();
        c.security.level = SecurityLevel::Strict;
        let req = c.subagent_create_request(1, 512, 600).unwrap();
        let ok = req["environment"]["guard"]["policy_template"] == serde_json::json!("model-only");
        restore_somp_level(prev);
        assert!(ok, "strict environment must pin guard.policy_template");
    }

    #[test]
    fn spark_wiring_pins_explicit_policy() {
        // muse-spark: x-api-key + /zen/go/v1/ cannot ride the template path
        // (template hardcodes authorization + /v1/), so guard_json must emit
        // an explicit GuardPolicy with the destination triple agreeing
        // across model / egress / binding (server validate_model_binding).
        let prev = scrub_somp_level();
        let mut c = governed_cfg();
        c.guard.model_host = Some("opencode.ai".into());
        c.guard.model_credential_header = "x-api-key".into();
        c.guard.model_path = "/zen/go/v1/".into();
        c.security.level = SecurityLevel::Strict;
        let req = c.subagent_create_request(1, 512, 600).unwrap();
        let g = &req["environment"]["guard"];
        let ok = g.get("policy_template").is_none()
            && g["topology"] == serde_json::json!("inside")
            && g["policy"]["model"]["host"] == serde_json::json!("opencode.ai")
            && g["policy"]["model"]["allowed_paths"] == serde_json::json!(["/zen/go/v1/"])
            && g["policy"]["credentials"][0]["header"] == serde_json::json!("x-api-key")
            && g["policy"]["credentials"][0]["name"] == g["policy"]["model"]["credential"]
            && g["policy"]["network"]["egress"][0]["host"] == serde_json::json!("opencode.ai")
            && g["policy"]["network"]["dns"]["allowed_zones"] == serde_json::json!(["opencode.ai"]);
        restore_somp_level(prev);
        assert!(ok, "spark wiring must emit explicit policy with agreeing triple");
    }

    #[test]
    fn bad_header_or_path_refuses() {
        let prev = scrub_somp_level();
        let mut c = governed_cfg();
        c.guard.model_credential_header = "x-custom-key".into();
        assert!(c.guard_json().is_err(), "unknown credential header must refuse");
        c.guard.model_credential_header = "x-api-key".into();
        c.guard.model_path = "zen/go/v1/".into();
        assert!(c.guard_json().is_err(), "relative model path must refuse");
        restore_somp_level(prev);
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

    #[test]
    fn level_runtime_mapping() {
        assert_eq!(SecurityLevel::Strict.runtime(), "firecracker");
        assert_eq!(SecurityLevel::Standard.runtime(), "docker");
    }

    #[test]
    fn off_never_reaches_tier() {
        use crate::tier::{Tier, TierCheck};
        let permissive = TierCheck { tier: Tier::Firecracker, kvm_present: true, kvm_module: true, kvm_openable: true, nft_usable: true, bwrap_ok: true };
        assert!(SecurityLevel::Off.require_tier(&permissive).is_err());
        let bare = TierCheck { tier: Tier::FallbackNoKvm, kvm_present: false, kvm_module: false, kvm_openable: false, nft_usable: false, bwrap_ok: true };
        // standard skips the host KVM gate (Docker boundary is worker-side)
        assert!(SecurityLevel::Standard.require_tier(&bare).is_ok());
        // strict keeps the KVM gate
        assert!(SecurityLevel::Strict.require_tier(&bare).is_err());
        assert!(SecurityLevel::Strict.require_tier(&permissive).is_ok());
    }
}
