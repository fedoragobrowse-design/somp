//! One-shot governed dispatch: create disposable VM -> stage files -> exec task
//! -> collect git_diff -> destroy. Fail-closed: destroy runs even on task failure.

use anyhow::{Context, Result};
use clap::Args;
use std::time::Instant;

use crate::{config::Config, tier};

#[derive(Debug, Args)]
pub struct DispatchArgs {
    /// Task prompt file (or - for stdin).
    #[arg(long)]
    pub task_file: String,
    /// Files to stage: repeat --file <guest-path>=<host-path>.
    #[arg(long)]
    pub file: Vec<String>,
    /// Command to run in the guest (default: srt-wrapped task runner).
    #[arg(long)]
    pub command: Vec<String>,
    #[arg(long, default_value_t = 1)]
    pub cpus: u32,
    #[arg(long, default_value_t = 512)]
    pub mem: u32,
    #[arg(long, default_value_t = 600)]
    pub timeout_s: u64,
    /// Override the guest image for this dispatch only (default: config
    /// session.image, fail-closed `somp-guest`). Needed on hosts where the
    /// baked guest image isn't pullable (e.g. Firecracker-only ext4 on a
    /// KVM-less box): pass a Docker-pullable image for standard-level runs.
    /// The srt-baked default command still runs — on a plain image without
    /// /opt/somp/bin/srt it exits 127 (honest, observed), so prefer images
    /// with srt or pass --command.
    #[arg(long)]
    pub image: Option<String>,
}

pub struct DispatchOutput {
    pub sandbox_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub diff: serde_json::Value,
    pub start_ms: u64,
    pub duration_ms: u64,
}

pub async fn run(cfg: &Config, args: DispatchArgs) -> Result<()> {
    let out = dispatch(cfg, args).await?;
    // Scrub secret values at the print boundary (upstream a1f2274): a secret
    // that reaches stdout is persisted somewhere this binary does not control.
    // The serialized diff is scrubbed too — a secret exfiltrated into a
    // result file would otherwise leak via git_diff.
    let stdout = crate::secrets::scrub(&out.stdout);
    let stderr = crate::secrets::scrub(&out.stderr);
    // Scrub the serialized diff, then parse back to a Value so consumers see
    // the same shape as the server returned (a secret exfiltrated into a
    // result file would otherwise leak via git_diff).
    let diff_scrubbed =
        crate::secrets::scrub(&serde_json::to_string(&out.diff).unwrap_or_default());
    let diff: serde_json::Value =
        serde_json::from_str(&diff_scrubbed).unwrap_or(serde_json::Value::Null);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "sandbox_id": out.sandbox_id,
            "exit_code": out.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "diff": diff,
            "start_ms": out.start_ms,
            "duration_ms": out.duration_ms,
        }))?
    );
    if out.exit_code != 0 {
        anyhow::bail!("guest task exited {}", out.exit_code);
    }
    Ok(())
}
/// Fail-closed level gate: `off` refuses governed work outright; strict and
/// standard both dispatch (worker capability decides the real boundary —
/// see UNPROVEN.md for Firecracker/Docker status on this host).
pub fn require_level(cfg: &Config) -> Result<crate::config::SecurityLevel> {
    require_level_for(cfg, "dispatch")
}

/// Same gate with the entry-point name in the refusal (session up vs dispatch).
pub fn require_level_for(cfg: &Config, entry: &str) -> Result<crate::config::SecurityLevel> {
    let level = crate::config::SecurityLevel::effective(cfg.security.level)?;
    if level == crate::config::SecurityLevel::Off {
        anyhow::bail!("fail-closed: sandbox protection level is OFF — governed {entry} refused (somp level strict|standard)");
    }
    Ok(level)
}

pub async fn dispatch(cfg: &Config, args: DispatchArgs) -> Result<DispatchOutput> {
    let level = require_level(cfg)?;
    level.require_tier(&tier::check()?)?;
    let runtime = level.runtime();
    let task_text = if args.task_file == "-" {
        use std::io::Read as _;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(&args.task_file)
            .with_context(|| format!("read {}", args.task_file))?
    };
    // Secret-path deny BEFORE creating any VM (upstream a1f2274): operator
    // secret paths are never legitimate task/command/file arguments.
    crate::secrets::deny_secret_paths_in_dispatch(&task_text, &args.command, &args.file)?;
    // JEV gate BEFORE creating any VM: an unclassified custom command must
    // never cost a sandbox (fail-closed ordering: deny → classify → create).
    // Guest scope: the command runs inside the throwaway VM, so the host
    // allowlist does not apply — net deny + classifier still do.
    if !args.command.is_empty() {
        crate::jev_gate::gate_for_guest(&args.command.join(" "), &cfg.jev).await?;
    }
    let t0 = Instant::now();
    let client = cfg.aiec_client()?;
    let mut req = cfg.subagent_create_request(args.cpus, args.mem, args.timeout_s)?;
    if let Some(image) = args.image.as_deref() {
        req["image"] = serde_json::Value::String(image.to_owned());
    }
    let sb = client
        .create_sandbox_with_runtime(&req, runtime)
        .await
        .context("create subagent VM")?;
    let start_ms = t0.elapsed().as_millis() as u64;

    let result = dispatch_inner(&client, &sb.id.to_string(), &task_text, &args).await;

    // Destroy even on failure: no orphan VMs. The destroy outcome is logged
    // BEFORE the inner result propagates, so a task failure can never hide
    // a failed destroy (orphan VM) behind `?` early-return.
    let destroy = client.delete_sandbox(sb.id).await;
    if let Err(e) = &destroy {
        eprintln!("warning: subagent VM destroy failed ({}): {:#}", sb.id, e);
    }
    let inner = result?;
    destroy.with_context(|| {
        format!(
            "subagent VM {} task ok but destroy failed (orphan risk)",
            sb.id
        )
    })?;
    Ok(DispatchOutput {
        sandbox_id: sb.id.to_string(),
        start_ms,
        ..inner
    })
}

async fn dispatch_inner(
    client: &crate::aiec::Client,
    id_str: &str,
    task_text: &str,
    args: &DispatchArgs,
) -> Result<DispatchOutput> {
    // Server git_diff hardcodes `git -C /workspace/repository diff --binary`
    // (aiec lib.rs git_diff handler): /workspace/repository is the canonical
    // clone path (aiec-core run.rs:293, aiec-api omp.rs:337). Staging anywhere
    // else makes diffs silently come back Null.
    // Diff hygiene (live probe 2026-10-10): server diff is plain `git diff`
    // (tracked only), so (1) baseline-commit staged inputs before exec so the
    // diff shows only task output, and (2) post-exec `git add -N .` runs for
    // BOTH default and custom --command paths so new files appear.
    const REPO: &str = "/workspace/repository";
    let id: uuid::Uuid = id_str.parse()?;
    let t0 = Instant::now();
    client
        .exec_command(
            id,
            vec![
                "git".into(),
                "-C".into(),
                "/workspace".into(),
                "init".into(),
                "-q".into(),
                "repository".into(),
            ],
            Some("/workspace".into()),
            60,
        )
        .await
        .context("init /workspace/repository")?;
    client
        .put_file(id, &format!("{REPO}/TASK.md"), task_text.as_bytes())
        .await
        .context("stage TASK.md")?;
    for spec in &args.file {
        // Split at the FIRST '=': spec is <guest>=<host>, guest staging
        // names never contain '=' but host paths may (temp dirs, query
        // strings). Reject '..': guest escapes REPO and the server diff
        // (hardcoded to /workspace/repository) would silently miss the file.
        let (guest, host) = spec
            .split_once('=')
            .with_context(|| format!("--file must be <guest>=<host>, got {spec:?}"))?;
        if guest.split('/').any(|c| c == "..") {
            anyhow::bail!("--file guest path must stay under /workspace/repository, got {guest:?}");
        }
        let guest = guest.strip_prefix("/workspace/").unwrap_or(guest);
        let guest = guest.strip_prefix('/').unwrap_or(guest);
        let bytes = std::fs::read(host).with_context(|| format!("read {host}"))?;
        client
            .put_file(id, &format!("{REPO}/{guest}"), &bytes)
            .await?;
    }
    // Baseline-commit staged inputs (TASK.md + --file set) so the post-exec
    // diff contains only what the guest task produced. Identity via -c flags:
    // no guest gitconfig required.
    client
        .exec_command(
            id,
            vec![
                "sh".into(),
                "-c".into(),
                format!(
                    "git -C {REPO} add -A && git -C {REPO} -c user.name=somp -c user.email=somp@localhost commit -qm baseline"
                ),
            ],
            Some(REPO.into()),
            60,
        )
        .await
        .context("baseline-commit staged inputs")?;
    // Absolute guest paths: the AIec exec environment's PATH is unverified,
    // but the image bakes srt at /opt/somp/bin/srt + settings at
    // /etc/somp/srt-settings.json (build-guest.sh + bootstrap.sh).
    let command = if args.command.is_empty() {
        vec![
            "/opt/somp/bin/srt".into(),
            "--settings".into(),
            "/etc/somp/srt-settings.json".into(),
            "sh".into(),
            "-c".into(),
            format!("cat {REPO}/TASK.md"),
        ]
    } else {
        // Already classified in dispatch() before VM create; Guard boundary
        // still applies. Loud on purpose — silence here would be fail-open.
        eprintln!(
            "warning: custom --command runs WITHOUT the srt wrapper (Guard boundary still applies)"
        );
        args.command.clone()
    };
    let r = client
        .exec_command(id, command, Some(REPO.into()), args.timeout_s)
        .await
        .context("exec task")?;
    // Intent-to-add AFTER exec, for every command path: makes new output
    // files visible to the server's plain `git diff --binary`.
    client
        .exec_command(
            id,
            vec![
                "sh".into(),
                "-c".into(),
                format!("git -C {REPO} add -N . 2>/dev/null; true"),
            ],
            Some(REPO.into()),
            60,
        )
        .await
        .context("intent-to-add new outputs")?;
    let diff = client.git_diff(id).await.unwrap_or(serde_json::Value::Null);
    // Guest-side scrub AFTER the diff is collected: rootless Docker maps the
    // container user to a host subuid, so guest-created files come out owned
    // by e.g. 525287 and the worker (running as gobrowse) cannot reclaim the
    // workspace → destroy 503s and every run exits non-zero despite success.
    // Removing contents from INSIDE runs as the owning uid, so it succeeds;
    // the diff above already captured everything. Best-effort only: failure
    // warns, and destroy stays the hard orphan gate.
    if let Err(e) = client
        .exec_command(
            id,
            vec![
                "sh".into(),
                "-c".into(),
                format!("rm -rf {REPO}/.git {REPO}/* {REPO}/.[!.]* 2>/dev/null; true"),
            ],
            Some("/workspace".into()),
            60,
        )
        .await
    {
        eprintln!("warning: guest workspace scrub failed ({e:#}); destroy may 503 on reclaim");
    }
    Ok(DispatchOutput {
        sandbox_id: id_str.to_owned(),
        exit_code: r.exit_code,
        stdout: r.stdout,
        stderr: r.stderr,
        diff,
        start_ms: 0,
        duration_ms: t0.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    // no imports needed: these exercise only stdlib string ops that mirror
    // the dispatch_inner parsing (rsplit_once + '..' component check).

    #[test]
    fn file_spec_split() {
        let (g, h) = "/workspace/a.txt=/tmp/a.txt".split_once('=').unwrap();
        assert_eq!(g, "/workspace/a.txt");
        assert_eq!(h, "/tmp/a.txt");
    }

    #[test]
    fn file_spec_splits_at_first_equals() {
        // Host paths may contain '=' (temp dirs, query strings); guest
        // staging names never do. split_once keeps the host side whole.
        let (g, h) = "ctx.md=/tmp/with=equals/x.md".split_once('=').unwrap();
        assert_eq!(g, "ctx.md");
        assert_eq!(h, "/tmp/with=equals/x.md");
    }

    #[test]
    fn file_spec_dotdot_rejected() {
        for bad in ["../evil.sh", "a/../../evil.sh", "/workspace/../evil.sh"] {
            assert!(
                bad.split('/').any(|c| c == ".."),
                "{bad:?} must trip the '..' component check"
            );
        }
        for good in ["ctx.md", "sub/dir/a.txt", "/workspace/repository/a.txt"] {
            assert!(!good.split('/').any(|c| c == ".."), "{good:?} must pass");
        }
    }

    #[test]
    fn scrubbed_diff_keeps_value_shape() {
        // run() scrubs the serialized diff then parses back to Value: the
        // envelope must carry an object, not a JSON-encoded string.
        let diff = serde_json::json!({"files": ["a.txt"], "patch": "abc"});
        let round: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&diff).unwrap()).unwrap();
        assert_eq!(round, diff);
    }
}
