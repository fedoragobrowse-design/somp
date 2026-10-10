//! somp: Secure OMP — run omp with AIec microVM isolation + srt inner sandbox + Guard egress.
//!
//! Fail-closed: any layer that cannot enforce its policy refuses the run.
//! This CLI never silently downgrades a governed task to an ungoverned tier.

mod aiec;
mod bench;
mod config;
mod dispatch;
mod secrets;
mod jev_gate;
mod tier;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "somp", version, about = "Secure OMP: hardened omp runtime")]
struct Cli {
    /// No subcommand opens the governed omp TUI (same as `somp tui`).
    /// NOTE: no top-level passthrough positional — a greedy trailing arg
    /// steals subcommand positionals (`somp level standard` silently routed
    /// to TUI extras). Passthrough lives on `somp tui -- <args>`.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the governed omp TUI (loads somp-ext with SOMP_GOVERNED=1).
    /// This is also what bare `somp` (no subcommand) does.
    Tui {
        /// Extra args passed through to omp.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },
    /// Manage the long-lived session VM.
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
    /// Dispatch one subagent task to a disposable governed VM.
    Dispatch(dispatch::DispatchArgs),
    /// Guard policy proposal helpers (submit + read journal; approval stays out-of-band).
    Policy {
        #[command(subcommand)]
        op: PolicyOp,
    },
    /// Benchmark baseline omp vs sOMP; writes raw JSON artifacts.
    Bench(bench::BenchArgs),
    /// Show or set the governed security level (strict|standard|off).
    /// No arg prints the effective level (SOMP_LEVEL env wins over config).
    Level { level: Option<String> },
    /// Model endpoint for the Guard model-only template: show, set, or apply
    /// a preset. `somp model preset muse-spark` pins opencode.ai:443
    /// (verified in omp models.json: opencode.ai/zen/go/v1).
    Model {
        #[command(subcommand)]
        op: ModelOp,
    },
    /// JEV bash-gate: show status, enable/disable, set model/threshold.
    /// Needs TYPESAFE_API_KEY in env (never stored in config).
    Jev {
        #[command(subcommand)]
        op: JevOp,
    },
    /// Update sOMP from YOUR repo (fedoragobrowse-design/somp): git pull +
    /// rebuild + reinstall links. Never touches upstream omp or npm.
    Update {
        /// Only check: fetch + report behind/ahead, change nothing.
        #[arg(long)]
        check: bool,
        /// Allow an origin that is not fedoragobrowse-design/somp (explicit
        /// opt-in for forks; without it foreign origins are refused).
        #[arg(long)]
        allow_foreign_origin: bool,
    },
    /// Check host tier (KVM/Firecracker candidacy, srt prerequisites).
    Doctor,
}

#[derive(Subcommand)]
enum SessionOp {
    /// Create (or attach to) the session VM.
    Up(config::SessionArgs),
    /// Snapshot the session workspace (name is a local label for the returned snapshot id).
    Snapshot { name: String },
    /// Restore a snapshot by its SNAPSHOT id (POST /v1/snapshots/{id}/restore).
    /// Creates a new sandbox from the snapshot; pass --kill-old to destroy the
    /// current session VM afterwards (restore does not mutate in place).
    Restore {
        snapshot: String,
        #[arg(long)]
        kill_old: bool,
    },
    /// Exec a command in the session VM.
    Exec { command: Vec<String> },
    /// Destroy the session VM.
    Destroy,
    /// Show session state.
    Show,
}

#[derive(Subcommand)]
enum ModelOp {
    /// Show the current Guard model endpoint (or lack of one).
    Show,
    /// Set host and optional port (default 443).
    Set { host: String, port: Option<u16> },
    /// Apply a named preset: `muse-spark` → opencode.ai:443.
    Preset { name: String },
}
#[derive(Subcommand)]
enum JevOp {
    /// Show JEV status: enabled, model, threshold, key presence (name only).
    Status,
    /// Enable the gate (needs TYPESAFE_API_KEY at exec time, not now).
    On,
    /// Disable the gate — refuses unless --allow-ungoverned-bash is explicit.
    Off {
        #[arg(long)]
        allow_ungoverned_bash: bool,
    },
    /// Pin the classifier model (default jev-latest).
    Model { name: String },
    /// Set the p(destructive) refuse threshold (default 0.15).
    Threshold { value: f64 },
}
#[derive(Subcommand)]
enum PolicyOp {
    /// Submit a Guard widening proposal (agent proposes; human approves out-of-band
    /// with a DIFFERENT key: POST .../proposals/{id}/approve).
    Propose {
        sandbox: String,
        /// host:port grants to add (repeatable). Narrowing is impossible by API design.
        #[arg(long)]
        add_host: Vec<String>,
        #[arg(long)]
        reason: String,
    },
    /// List Guard proposals for a sandbox (pending + decided: the journal).
    Proposals { sandbox: String },
    /// Show one proposal with its state.
    Show {
        sandbox: String,
        #[arg(long)]
        proposal: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Local plane CA for EVERY command (not just TUI): the 18443 plane
    // uses a self-signed CA at ~/.config/aiec/ca.pem. aiec.rs loads
    // AIEC_TLS_CA_CERT; without this hoist, dispatch/session/policy/bench
    // fail TLS verify unless the caller exports the var manually.
    ensure_local_ca();
    let cli = Cli::parse();
    // Bare `somp` (no subcommand) opens the governed TUI — this is the
    // primary operator entry point. `somp <extra...>` passes through.
    let cmd = cli.cmd.unwrap_or(Cmd::Tui { extra: Vec::new() });
    // TUI launch must not require a config file: launch first, load config
    // only for non-TUI subcommands.
    if let Cmd::Tui { extra } = cmd {
        return launch_governed_tui(extra);
    }
    let cfg = config::load()?;
    match cmd {
        Cmd::Tui { .. } => unreachable!("handled above"),
        Cmd::Doctor => tier::doctor(),
        Cmd::Level { level } => level_cmd(cfg, level),
        Cmd::Model { op } => model_cmd(cfg, op),
        Cmd::Jev { op } => jev_cmd(cfg, op),
        Cmd::Update { check, allow_foreign_origin } => update_cmd(check, allow_foreign_origin),
        Cmd::Session { op } => session(cfg, op).await,
        Cmd::Dispatch(args) => dispatch::run(&cfg, args).await,
        Cmd::Policy { op } => policy(cfg, op).await,
        Cmd::Bench(args) => bench::run(&cfg, args).await,
    }
}

/// Exec the governed omp TUI: same environment the somp-omp wrapper sets
/// (SOMP_GOVERNED=1 + explicit -e ext load), resolved from this binary's
/// checkout (ext/somp-ext.ts next to the repo root). Replaces this process
/// so signals/TTY behave exactly like `omp`.
fn launch_governed_tui(extra: Vec<String>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;
    let repo = somp_repo_dir()?;
    let ext = repo.join("ext/somp-ext.ts");
    if !ext.exists() {
        bail!("cannot launch governed TUI: {} missing", ext.display());
    }
    let somp_bin = std::env::current_exe().context("current exe")?;
    // CA already ensured in main(); keep the call as belt-and-braces
    // for direct reuse (harmless: ensure_local_ca is idempotent).
    ensure_local_ca();
    // SAFETY: single-threaded pre-exec setup.
    unsafe {
        std::env::set_var("SOMP_GOVERNED", "1");
        std::env::set_var("SOMP_BIN", &somp_bin);
    }
    let err = std::process::Command::new("omp")
        .arg("-e")
        .arg(&ext)
        .args(&extra)
        .exec();
    // exec only returns on failure.
    Err(anyhow::anyhow!("exec omp failed: {err} (is omp on PATH?)"))
}
/// Trust the local plane's self-signed CA unless the operator overrode
/// AIEC_TLS_CA_CERT explicitly. Idempotent; safe to call from main and TUI.
fn ensure_local_ca() {
    if std::env::var("AIEC_TLS_CA_CERT").is_err() {
        let ca = dirs_home_ca();
        if ca.exists() {
            // SAFETY: single-threaded startup; no other thread exists yet.
            unsafe { std::env::set_var("AIEC_TLS_CA_CERT", &ca) };
        }
    }
}

fn dirs_home_ca() -> std::path::PathBuf {
    let home = std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| std::path::PathBuf::from("/root"));
    home.join(".config/aiec/ca.pem")
}

/// Update sOMP from the operator's own repo. Source of truth is the `origin`
/// remote of the checkout this binary was installed from — resolved at
/// runtime via the `somp` symlink target (install.sh links
/// ~/.local/bin/somp -> <repo>/crates/somp-cli/target/release/somp).
/// Never consults npm, api.github.com, or any upstream omp channel.
const FALLBACK_REPO: &str = "https://github.com/fedoragobrowse-design/somp.git";

fn somp_repo_dir() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("current exe")?;
    let real = std::fs::read_link(&exe).unwrap_or(exe);
    // <repo>/crates/somp-cli/target/release/somp -> <repo>
    let mut dir = real.parent().context("exe has no parent")?.to_path_buf();
    for _ in 0..4 {
        dir = dir.parent().context("exe path too shallow")?.to_path_buf();
        if dir.join("install.sh").exists() && dir.join("ext/somp-ext.ts").exists() {
            return Ok(dir);
        }
    }
    anyhow::bail!("cannot locate sOMP checkout from exe (expected install.sh + ext/somp-ext.ts within 4 levels)");
}

fn update_cmd(check: bool, allow_foreign_origin: bool) -> Result<()> {
    let repo = somp_repo_dir()?;
    let remote = String::from_utf8(
        std::process::Command::new("git").args(["-C"]).arg(&repo).args(["remote", "get-url", "origin"])
            .output().context("git remote get-url")?.stdout,
    ).unwrap_or_default().trim().to_string();
    println!("somp repo: {}", repo.display());
    println!("origin:    {}", if remote.is_empty() { "(unset)" } else { &remote });
    // Exact-match origin gate: only fedoragobrowse-design/somp (https + ssh
    // forms) is trusted to rebuild the governed binary. A substring check
    // would let github.com/evil/somp.git pass — fail-closed on everything
    // else unless the operator passes --allow-foreign-origin explicitly.
    if !is_trusted_origin(&remote) && !allow_foreign_origin {
        bail!("refusing update: origin {remote:?} is not YOUR somp repo ({FALLBACK_REPO}) — pulling foreign code would rebuild the governed binary from it. Pass --allow-foreign-origin to override explicitly");
    }
    if allow_foreign_origin {
        println!("note: --allow-foreign-origin given; trusting configured origin (operator override)");
    }
    // Fetch first: --check reports without mutating the working tree.
    let st = std::process::Command::new("git").args(["-C"]).arg(&repo)
        .args(["fetch", "origin"]).status().context("git fetch")?;
    if !st.success() {
        bail!("git fetch origin failed in {}", repo.display());
    }
    // Branch-aware: resolve the upstream tracking branch (@{u}) instead of
    // hardcoding origin/main, so checkouts tracking another branch work.
    // Falls back to origin/HEAD when no tracking branch is configured.
    let upstream_ref = tracking_branch(&repo).unwrap_or_else(|| "origin/HEAD".to_string());
    let local = git_rev(&repo, "HEAD")?;
    let upstream = git_rev(&repo, &upstream_ref)?;
    if local == upstream {
        println!("already up to date ({})", &local[..12.min(local.len())]);
        return Ok(());
    }
    println!("behind: local {} -> {} {}", &local[..12.min(local.len())], upstream_ref, &upstream[..12.min(upstream.len())]);
    if check {
        println!("--check: not pulling. Run `somp update` to pull + rebuild + reinstall.");
        return Ok(());
    }
    // Pull the CURRENT branch from its tracking upstream — never a hardcoded
    // `origin main` (breaks checkouts on other branches).
    let branch = current_branch(&repo)?;
    let st = std::process::Command::new("git").args(["-C"]).arg(&repo)
        .args(["pull", "--ff-only"]).status().context("git pull")?;
    if !st.success() {
        bail!("git pull --ff-only failed on branch {branch:?} (local changes? stash first, then `somp update`)");
    }
    println!("== rebuild + reinstall ==");
    let installer = repo.join("install.sh");
    let st = std::process::Command::new("sh").arg(&installer).status().context("run install.sh")?;
    if !st.success() {
        bail!("install.sh failed after pull");
    }
    println!("updated to {}", &git_rev(&repo, "HEAD")?[..12]);
    Ok(())
}

fn git_rev(repo: &std::path::Path, rev: &str) -> Result<String> {
    let out = std::process::Command::new("git").args(["-C"]).arg(repo)
        .args(["rev-parse", rev]).output().context("git rev-parse")?;
    if !out.status.success() {
        bail!("git rev-parse {rev} failed (no upstream tracking branch? `git branch --set-upstream-to=origin/main`)");
    }
    Ok(String::from_utf8(out.stdout).unwrap_or_default().trim().to_string())
}

/// Only fedoragobrowse-design/somp, https and ssh forms. Exact match on the
/// path — substring checks let evil/somp.git pass.
fn is_trusted_origin(remote: &str) -> bool {
    let r = remote.trim().to_lowercase();
    r == "https://github.com/fedoragobrowse-design/somp.git"
        || r == "https://github.com/fedoragobrowse-design/somp"
        || r == "git@github.com:fedoragobrowse-design/somp.git"
        || r == "git@github.com:fedoragobrowse-design/somp"
        || r == "ssh://git@github.com/fedoragobrowse-design/somp.git"
        || r == "ssh://git@github.com/fedoragobrowse-design/somp"
}

/// Symbolic name of the current branch's tracking upstream (e.g.
/// `origin/main`), or None when unconfigured.
fn tracking_branch(repo: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("git").args(["-C"]).arg(repo)
        .args(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).unwrap_or_default().trim().to_string();
    if s.is_empty() || s == "@{u}" { None } else { Some(s) }
}

/// Short name of the checked-out branch (for error messages only).
fn current_branch(repo: &std::path::Path) -> Result<String> {
    let out = std::process::Command::new("git").args(["-C"]).arg(repo)
        .args(["branch", "--show-current"]).output().context("git branch --show-current")?;
    Ok(String::from_utf8(out.stdout).unwrap_or_default().trim().to_string())
}
fn level_cmd(cfg: config::Config, level: Option<String>) -> Result<()> {
    match level {
        None => {
            let eff = config::SecurityLevel::effective(cfg.security.level)?;
            let src = if std::env::var("SOMP_LEVEL").is_ok() { "SOMP_LEVEL env" } else { "config file" };
            println!("sandbox protection level: {} ({})", eff.badge(), eff.describe());
            println!("source: {src}");
            Ok(())
        }
        Some(want) => {
            let want = want.to_lowercase();
            if !["strict", "standard", "off"].contains(&want.as_str()) {
                bail!("level must be strict|standard|off, got {want:?}");
            }
            // Persist to config file; read-modify-write preserves other keys.
            // Ensure the `security` table exists first: indexing Null panics
            // in serde_yaml on configs written before the level feature.
            let path = config::config_path();
            let mut raw: serde_yaml::Value = if path.exists() {
                serde_yaml::from_str(&std::fs::read_to_string(&path)?)?
            } else {
                serde_yaml::Value::Mapping(Default::default())
            };
            if !raw.get("security").is_some_and(|v| v.is_mapping()) {
                raw["security"] = serde_yaml::Value::Mapping(Default::default());
            }
            raw["security"]["level"] = serde_yaml::Value::String(want.clone());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, serde_yaml::to_string(&raw)?)?;
            println!("security level set to {want} ({})", path.display());
            Ok(())
        }
    }
}
/// Read-modify-write one config subtree, creating parent tables on the fly
/// (same Null-index guard as level_cmd).
fn config_set(path: &[&str], value: serde_yaml::Value) -> Result<()> {
    let cfg_path = config::config_path();
    let mut raw: serde_yaml::Value = if cfg_path.exists() {
        serde_yaml::from_str(&std::fs::read_to_string(&cfg_path)?)?
    } else {
        serde_yaml::Value::Mapping(Default::default())
    };
    let mut node = &mut raw;
    for key in &path[..path.len() - 1] {
        if !node.get(*key).is_some_and(|v| v.is_mapping()) {
            node[*key] = serde_yaml::Value::Mapping(Default::default());
        }
        node = &mut node[*key];
    }
    node[path[path.len() - 1]] = value;
    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cfg_path, serde_yaml::to_string(&raw)?)?;
    Ok(())
}
/// Guard model endpoint: show/set/preset. Presets are pinned to catalog-
/// verified baseUrls (omp packages/catalog/src/models.json), not guesses.
fn model_cmd(cfg: config::Config, op: ModelOp) -> Result<()> {
    match op {
        ModelOp::Show => {
            match (&cfg.guard.model_host, cfg.guard.model_port) {
                (Some(h), Some(p)) => println!("guard model endpoint: {h}:{p} (template {})", cfg.guard.template),
                _ => println!("guard model endpoint: UNSET — governed dispatch will refuse until `somp model set <host> [port]` or `somp model preset muse-spark`"),
            }
            Ok(())
        }
        ModelOp::Set { host, port } => {
            let port = port.unwrap_or(443);
            if port == 0 {
                bail!("port 0 is not a valid model endpoint");
            }
            config_set(&["guard", "model_host"], serde_yaml::Value::String(host.clone()))?;
            config_set(&["guard", "model_port"], serde_yaml::Value::Number(port.into()))?;
            println!("guard model endpoint set to {host}:{port}");
            Ok(())
        }
        ModelOp::Preset { name } => {
            match name.to_lowercase().as_str() {
                "muse-spark" => {
                    config_set(&["guard", "model_host"], serde_yaml::Value::String("opencode.ai".into()))?;
                    config_set(&["guard", "model_port"], serde_yaml::Value::Number(443.into()))?;
                    // omp wire for opencode-go is X-Api-Key (never bearer:
                    // providers/anthropic.ts drops Authorization, #6510), and
                    // the responses API lives under /zen/go/v1, so the guest
                    // must address .../model/model-main/zen/go/v1 as its base.
                    config_set(&["guard", "model_credential_header"], serde_yaml::Value::String("x-api-key".into()))?;
                    config_set(&["guard", "model_path"], serde_yaml::Value::String("/zen/go/v1/".into()))?;
                    println!("guard model endpoint ← muse-spark preset: opencode.ai:443 (header x-api-key, path /zen/go/v1/)");
                    println!("(catalog baseUrl https://opencode.ai/zen/go/v1, openai-responses API)");
                    Ok(())
                }
                other => bail!("unknown preset {other:?}: want muse-spark"),
            }
        }
    }
}
/// JEV gate management. Key presence is name-only (never print bytes).
fn jev_cmd(cfg: config::Config, op: JevOp) -> Result<()> {
    match op {
        JevOp::Status => {
            let key = match std::env::var("TYPESAFE_API_KEY") {
                Ok(k) if !k.trim().is_empty() => "TYPESAFE_API_KEY: set (bytes hidden)",
                _ => "TYPESAFE_API_KEY: MISSING — gate will refuse until exported",
            };
            println!("jev gate: {} (model {}, threshold {})", if cfg.jev.enabled { "ON" } else { "OFF" }, cfg.jev.model, cfg.jev.threshold);
            println!("{key}");
            println!("unguarded-bash escape hatch: {}", if cfg.jev.allow_ungoverned_bash { "ALLOWED (explicit)" } else { "denied (default)" });
            Ok(())
        }
        JevOp::On => {
            config_set(&["jev", "enabled"], serde_yaml::Value::Bool(true))?;
            println!("jev gate enabled (needs TYPESAFE_API_KEY in env at exec time)");
            Ok(())
        }
        JevOp::Off { allow_ungoverned_bash } => {
            if !allow_ungoverned_bash {
                bail!("refusing: `somp jev off` without --allow-ungoverned-bash would silently unguard bash — pass the flag explicitly to own it");
            }
            config_set(&["jev", "enabled"], serde_yaml::Value::Bool(false))?;
            config_set(&["jev", "allow_ungoverned_bash"], serde_yaml::Value::Bool(true))?;
            println!("jev gate disabled WITH explicit unguarded-bash audit flag");
            Ok(())
        }
        JevOp::Model { name } => {
            config_set(&["jev", "model"], serde_yaml::Value::String(name.clone()))?;
            println!("jev model pinned to {name}");
            Ok(())
        }
        JevOp::Threshold { value } => {
            if !(0.0..=1.0).contains(&value) {
                bail!("threshold must be 0.0..=1.0, got {value}");
            }
            config_set(&["jev", "threshold"], serde_yaml::Value::Number(serde_yaml::Number::from(value)))?;
            println!("jev threshold set to {value}");
            Ok(())
        }
    }
}

async fn session(cfg: config::Config, op: SessionOp) -> Result<()> {
    let client = cfg.aiec_client()?;
    match op {
        SessionOp::Up(args) => {
            // Off refuses EVERY governed entry point, not just dispatch.
            let level = dispatch::require_level_for(&cfg, "session up")?;
            let dotier = tier::check()?;
            level.require_tier(&dotier)?;
            if let Some(existing) = config::session_state_load()? {
                let sb = client.get_sandbox(existing.id).await;
                if let Ok(sb) = sb {
                    println!("session already up: {} ({})", sb.id, sb.state);
                    return Ok(());
                }
                eprintln!("stale session record (sandbox gone); recreating");
            }
            let req = cfg.session_create_request(&args)?;
            let sb = client
                .create_sandbox_with_runtime(&req, level.runtime())
                .await
                .context("create session VM")?;
            config::session_state_store(sb.id)?;
            println!("session up: {} state={}", sb.id, sb.state);
            Ok(())
        }
        SessionOp::Snapshot { name } => {
            let st = config::session_state_load()?.context("no session (somp session up first)")?;
            // kind is the only server-accepted field; the CLI name is a local label.
            let snap: serde_json::Value = client.create_snapshot(st.id, None).await?;
            println!("snapshot [{name}]: {}", serde_json::to_string_pretty(&snap)?);
            println!("restore with: somp session restore --snapshot <snapshot-id-from-above>");
            Ok(())
        }
        SessionOp::Restore { snapshot, kill_old } => {
            let snap_id: uuid::Uuid = snapshot.parse().context("snapshot must be a UUID")?;
            let sb: serde_json::Value = client.restore_snapshot(snap_id).await?;
            let new_id: uuid::Uuid = sb
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .parse()
                .context("restore response missing sandbox id")?;
            let old = config::session_state_load()?;
            config::session_state_store(new_id)?;
            println!("restored from {snap_id}: new session {new_id}");
            if kill_old {
                if let Some(st) = old {
                    client.delete_sandbox(st.id).await?;
                    println!("old session {} destroyed", st.id);
                }
            }
            Ok(())
        }
        SessionOp::Exec { command } => {
            if command.is_empty() {
                bail!("nothing to exec");
            }
            // Fail-closed ordering: deny → classify → touch session/plane.
            // An unclassified command never even reads session state.
            crate::secrets::deny_secret_paths_in_dispatch("", &command, &[])?;
            crate::jev_gate::gate(&command.join(" "), &cfg.jev).await?;
            let st = config::session_state_load()?.context("no session (somp session up first)")?;
            let r = client.exec_command(st.id, command, None, 300).await?;
            // Same print boundary as dispatch: scrub before persisting to terminal.
            print!("{}", crate::secrets::scrub(&r.stdout));
            eprint!("{}", crate::secrets::scrub(&r.stderr));
            if r.exit_code != 0 {
                bail!("remote exit {}", r.exit_code);
            }
            Ok(())
        }
        SessionOp::Destroy => {
            let st = config::session_state_load()?.context("no session")?;
            client.delete_sandbox(st.id).await?;
            config::session_state_clear()?;
            println!("session destroyed");
            Ok(())
        }
        SessionOp::Show => {
            match config::session_state_load()? {
                None => println!("no session"),
                Some(st) => match client.get_sandbox(st.id).await {
                    Ok(sb) => println!("{} state={} runtime={}", sb.id, sb.state, sb.runtime),
                    Err(e) => println!("{} unreachable: {:#}", st.id, e),
                },
            }
            Ok(())
        }
    }
}

async fn policy(cfg: config::Config, op: PolicyOp) -> Result<()> {
    let client = cfg.aiec_client()?;
    match op {
        PolicyOp::Propose { sandbox, add_host, reason } => {
            let id: uuid::Uuid = sandbox.parse().context("sandbox must be a UUID")?;
            // add_host entries are host or host:port; default port 443/tcp.
            // Methods/paths stay empty (opaque grant), so the summary MUST say
            // out loud what the destination is for (server-enforced).
            let mut allow = Vec::new();
            for h in &add_host {
                // Bare IPv6 (`::1`) is ambiguous with host:port — require
                // brackets. Anything else with >1 colon is refused, not guessed.
                if h.contains(':') && !(h.starts_with('[') && h.contains("]:")) && h.matches(':').count() != 1 {
                    bail!("--add-host IPv6 must be [addr]:port, got {h:?}");
                }
                let (host, port) = match h.rsplit_once(':') {
                    // Bracketed [addr]:port: strip brackets, strict port parse
                    // (garbage port silently becoming 443 would widen egress).
                    Some((host, p)) if h.matches(':').count() == 1 || h.contains("]:") => {
                        let host = host.strip_prefix('[').unwrap_or(host);
                        let (host, _) = host.split_once(']').unwrap_or((host, ""));
                        let port: u16 = p.parse().with_context(|| format!("--add-host port must be 1-65535, got {p:?}"))?;
                        if port == 0 {
                            bail!("--add-host port must be 1-65535, got {p:?}");
                        }
                        (host.to_string(), port)
                    }
                    _ => (h.clone(), 443),
                };
                allow.push(serde_json::json!({ "host": host, "port": port }));
            }
            let out = client.submit_proposal(id, &reason, allow).await?;
            println!("proposal submitted (independent-human approval required out-of-band):");
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        PolicyOp::Proposals { sandbox } => {
            let id: uuid::Uuid = sandbox.parse().context("sandbox must be a UUID")?;
            let list = client.list_proposals(id).await?;
            println!("{}", serde_json::to_string_pretty(&list)?);
            Ok(())
        }
        PolicyOp::Show { sandbox, proposal } => {
            let id: uuid::Uuid = sandbox.parse().context("sandbox must be a UUID")?;
            let pid: uuid::Uuid = proposal.parse().context("proposal must be a UUID")?;
            let p = client.get_proposal(id, pid).await?;
            println!("{}", serde_json::to_string_pretty(&p)?);
            Ok(())
        }
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;

    #[test]
    fn upstream_origin_refused() {
        assert!(!is_trusted_origin("https://github.com/can1357/oh-my-pi.git"));
        assert!(!is_trusted_origin("git@github.com:someone/oh-my-pi.git"));
        assert!(!is_trusted_origin("https://github.com/other/oh_my_pi.git"));
    }

    #[test]
    fn evil_somp_lookalike_refused() {
        // The old substring gate (!contains("somp")) let these pass — the
        // exact-match gate must refuse them.
        assert!(!is_trusted_origin("https://github.com/evil/somp.git"));
        assert!(!is_trusted_origin("https://github.com/evil/somp-fork.git"));
        assert!(!is_trusted_origin("https://github.com/someone/random-tool.git"));
        assert!(!is_trusted_origin("https://github.com/fedoragobrowse-design/somp-evil.git"));
        assert!(!is_trusted_origin("https://github.com/fedoragobrowse-design/evil-somp.git"));
        assert!(!is_trusted_origin(""));
    }

    #[test]
    fn own_repo_allowed_all_forms() {
        assert!(is_trusted_origin("https://github.com/fedoragobrowse-design/somp.git"));
        assert!(is_trusted_origin("https://github.com/fedoragobrowse-design/somp"));
        assert!(is_trusted_origin("git@github.com:fedoragobrowse-design/somp.git"));
        assert!(is_trusted_origin("git@github.com:fedoragobrowse-design/somp"));
        assert!(is_trusted_origin("ssh://git@github.com/fedoragobrowse-design/somp.git"));
        // Case-insensitive: git remotes vary in case.
        assert!(is_trusted_origin("HTTPS://GITHUB.COM/FEDORAGOBROWSE-DESIGN/SOMP.GIT"));
    }
}
