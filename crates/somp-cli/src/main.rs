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
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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
    /// Update sOMP from YOUR repo (fedoragobrowse-design/somp): git pull +
    /// rebuild + reinstall links. Never touches upstream omp or npm.
    Update {
        /// Only check: fetch + report behind/ahead, change nothing.
        #[arg(long)]
        check: bool,
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
    let cli = Cli::parse();
    let cfg = config::load()?;
    match cli.cmd {
        Cmd::Doctor => tier::doctor(),
        Cmd::Level { level } => level_cmd(cfg, level),
        Cmd::Update { check } => update_cmd(check),
        Cmd::Session { op } => session(cfg, op).await,
        Cmd::Dispatch(args) => dispatch::run(&cfg, args).await,
        Cmd::Policy { op } => policy(cfg, op).await,
        Cmd::Bench(args) => bench::run(&cfg, args).await,
    }
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

fn update_cmd(check: bool) -> Result<()> {
    let repo = somp_repo_dir()?;
    let remote = String::from_utf8(
        std::process::Command::new("git").args(["-C"]).arg(&repo).args(["remote", "get-url", "origin"])
            .output().context("git remote get-url")?.stdout,
    ).unwrap_or_default().trim().to_string();
    println!("somp repo: {}", repo.display());
    println!("origin:    {}", if remote.is_empty() { "(unset)" } else { &remote });
    if !remote.is_empty() && remote != FALLBACK_REPO {
        println!("note: origin is not {FALLBACK_REPO} — pulling from YOUR configured origin, not upstream omp.");
    }
    // Fetch first: --check reports without mutating the working tree.
    let st = std::process::Command::new("git").args(["-C"]).arg(&repo)
        .args(["fetch", "origin"]).status().context("git fetch")?;
    if !st.success() {
        bail!("git fetch origin failed in {}", repo.display());
    }
    let local = git_rev(&repo, "HEAD")?;
    let upstream = git_rev(&repo, "@{u}")?;
    if local == upstream {
        println!("already up to date ({})", &local[..12.min(local.len())]);
        return Ok(());
    }
    println!("behind: local {} -> origin {}", &local[..12.min(local.len())], &upstream[..12.min(upstream.len())]);
    if check {
        println!("--check: not pulling. Run `somp update` to pull + rebuild + reinstall.");
        return Ok(());
    }
    let st = std::process::Command::new("git").args(["-C"]).arg(&repo)
        .args(["pull", "--ff-only", "origin", "main"]).status().context("git pull")?;
    if !st.success() {
        bail!("git pull --ff-only failed (local changes? stash first, then `somp update`)");
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
            let path = config::config_path();
            let mut raw: serde_yaml::Value = if path.exists() {
                serde_yaml::from_str(&std::fs::read_to_string(&path)?)?
            } else {
                serde_yaml::Value::Mapping(Default::default())
            };
            raw["security"]["level"] = serde_yaml::Value::String(want.clone());
            std::fs::write(&path, serde_yaml::to_string(&raw)?)?;
            println!("sandbox protection level set to {want} ({})", path.display());
            Ok(())
        }
    }
}

async fn session(cfg: config::Config, op: SessionOp) -> Result<()> {
    let client = cfg.aiec_client()?;
    match op {
        SessionOp::Up(args) => {
            let dotier = tier::check()?;
            dotier.require_governed()?;
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
                .create_sandbox_with_runtime(&req, "firecracker")
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
            let st = config::session_state_load()?.context("no session (somp session up first)")?;
            crate::secrets::deny_secret_paths_in_dispatch("", &command, &[])?;
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
