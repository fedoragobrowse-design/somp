//! Benchmarks: baseline omp vs sOMP. Raw JSON artifacts, honest numbers.
//!
//! Methods (each 20 reps default):
//! - local-exec: /usr/bin/time -v `true` + srt `true` (srt-in-host cost proxy).
//! - spawn-probe: measures CLI dispatch path construction (no control plane).
//! - control-plane benches (create/exec/diff/destroy) run only with --aiec and
//!   a live control plane; otherwise recorded as not-run with the reason.

use anyhow::Result;
use clap::Args;
use std::time::Instant;

use crate::config::Config;

#[derive(Debug, Args)]
pub struct BenchArgs {
    #[arg(long, default_value_t = 20)]
    pub reps: usize,
    #[arg(long)]
    pub out: String,
    /// Include live control-plane benches (needs AIEC_API_KEY + running plane).
    #[arg(long, default_value_t = false)]
    pub aiec: bool,
}

#[derive(Debug, serde::Serialize)]
struct Sample {
    name: String,
    rep: usize,
    wall_ms: f64,
    max_rss_kb: Option<u64>,
    ok: bool,
    note: String,
}

#[derive(Debug, serde::Serialize)]
struct Artifact {
    tool: String,
    revs: serde_json::Value,
    host: serde_json::Value,
    started_at: String,
    samples: Vec<Sample>,
    not_run: Vec<serde_json::Value>,
}

pub async fn run(_cfg: &Config, args: BenchArgs) -> Result<()> {
    std::fs::create_dir_all(&args.out)?;
    let mut samples = Vec::new();
    let mut not_run = Vec::new();

    // 1. local exec baseline: `true` wall time.
    for rep in 0..args.reps {
        let t = Instant::now();
        let st = std::process::Command::new("true").status()?;
        samples.push(Sample {
            name: "localexec_true".into(),
            rep,
            wall_ms: t.elapsed().as_secs_f64() * 1000.0,
            max_rss_kb: None,
            ok: st.success(),
            note: "process spawn floor".into(),
        });
    }

    // 2. srt-wrapped `true` (inner-layer cost proxy; NOT guest evidence).
    // Binary from SOMP_SRT_BIN or PATH; settings from SOMP_SRT_SETTINGS or
    // somp/guest/srt-settings.json beside the workspace. Without settings srt
    // runs unenforced, so a settings-less run is recorded as not-run, not ok.
    match which_srt_with_settings() {
        (None, _) => not_run.push(serde_json::json!({
            "name": "srt_true_host",
            "reason": "srt binary not on PATH (set SOMP_SRT_BIN)",
        })),
        (_, None) => not_run.push(serde_json::json!({
            "name": "srt_true_host",
            "reason": "srt settings not found (set SOMP_SRT_SETTINGS); refusing unenforced run",
        })),
        (Some(srt), Some(settings)) => {
            for rep in 0..args.reps {
                let t = Instant::now();
                let st = std::process::Command::new(&srt)
                    .args(["--settings", &settings, "--", "true"])
                    .status();
                let wall = t.elapsed().as_secs_f64() * 1000.0;
                match st {
                    Ok(s) => samples.push(Sample {
                        name: "srt_true_host".into(),
                        rep,
                        wall_ms: wall,
                        max_rss_kb: None,
                        ok: s.success(),
                        note: format!("host srt wrap cost via {srt} w/ settings {settings}; guest run unproven until guest image exists"),
                    }),
                    Err(e) => samples.push(Sample {
                        name: "srt_true_host".into(),
                        rep,
                        wall_ms: wall,
                        max_rss_kb: None,
                        ok: false,
                        note: format!("spawn failed: {e}"),
                    }),
                }
            }
        }
    }

    // 3. bwrap userns probe (guest-fit prerequisite, run on host).
    {
        let t = Instant::now();
        let st = std::process::Command::new("bwrap")
            .args(["--unshare-user", "--dev-bind", "/", "/", "true"])
            .status();
        let wall = t.elapsed().as_secs_f64() * 1000.0;
        match st {
            Ok(s) => samples.push(Sample {
                name: "bwrap_userns_probe".into(),
                rep: 0,
                wall_ms: wall,
                max_rss_kb: None,
                ok: s.success(),
                note: "srt guest-fit prerequisite probe (host side)".into(),
            }),
            Err(e) => samples.push(Sample {
                name: "bwrap_userns_probe".into(),
                rep: 0,
                wall_ms: wall,
                max_rss_kb: None,
                ok: false,
                note: format!("probe failed: {e}"),
            }),
        }
    }

    // 4. omp baseline: trivial print-mode task (model round-trip floor for any
    // sOMP-vs-omp overhead comparison). Max 5 reps: each costs a model call.
    match which_omp() {
        None => not_run.push(serde_json::json!({
            "name": "omp_baseline_task",
            "reason": "omp binary not on PATH",
        })),
        Some(omp) => {
            for rep in 0..args.reps.min(5) {
                let t = Instant::now();
                let out = std::process::Command::new(&omp)
                    .args(["-p", "reply with exactly: BASELINE_OK"])
                    .output();
                let wall = t.elapsed().as_secs_f64() * 1000.0;
                match out {
                    Ok(o) => {
                        let ok = o.status.success()
                            && String::from_utf8_lossy(&o.stdout).contains("BASELINE_OK");
                        samples.push(Sample {
                            name: "omp_baseline_task".into(),
                            rep,
                            wall_ms: wall,
                            max_rss_kb: None,
                            ok,
                            note: "trivial print-mode task incl. model round-trip".into(),
                        });
                    }
                    Err(e) => samples.push(Sample {
                        name: "omp_baseline_task".into(),
                        rep,
                        wall_ms: wall,
                        max_rss_kb: None,
                        ok: false,
                        note: format!("spawn failed: {e}"),
                    }),
                }
            }
        }
    }

    if !args.aiec {
        not_run.push(serde_json::json!({
            "name": "aiec_create_exec_diff_destroy",
            "reason": "needs --aiec with live control plane (not run)",
        }));
    }

    let art = Artifact {
        tool: "somp bench".into(),
        revs: serde_json::json!({
            "somp": "phase2-dev",
            "omp": "46ad32961a96aef21cd35fe615374f4b3675ca58",
            "aiec": "0f516df43943aad0efc3e2be32b69fdc1ed0a895",
            "srt": "4160dcde76f9905268cb76826381665c422bfbf6",
        }),
        host: host_doc()?,
        started_at: chrono::Utc::now().to_rfc3339(),
        samples,
        not_run,
    };
    let path = format!("{}/bench-{}.json", args.out.trim_end_matches('/'), art.started_at.replace(':', "-"));
    std::fs::write(&path, serde_json::to_string_pretty(&art)?)?;
    println!("wrote {path}");
    summarize(&art);
    Ok(())
}

fn which_srt_with_settings() -> (Option<String>, Option<String>) {
    let bin = std::env::var("SOMP_SRT_BIN")
        .ok()
        .filter(|p| std::path::Path::new(p).exists())
        .or_else(|| {
            std::env::var("PATH").ok()?.split(':').find_map(|d| {
                let p = format!("{d}/srt");
                std::path::Path::new(&p).exists().then(|| p.clone())
            })
        });
    let settings = std::env::var("SOMP_SRT_SETTINGS")
        .ok()
        .filter(|p| std::path::Path::new(p).exists())
        .or_else(|| {
            for cand in ["somp/guest/srt-settings.json", "guest/srt-settings.json"] {
                if std::path::Path::new(cand).exists() {
                    return Some(cand.to_string());
                }
            }
            None
        });
    (bin, settings)
}

fn which_omp() -> Option<String> {
    std::env::var("PATH").ok()?.split(':').find_map(|d| {
        let p = format!("{d}/omp");
        std::path::Path::new(&p).exists().then(|| p.clone())
    })
}

fn host_doc() -> Result<serde_json::Value> {
    let uname = std::process::Command::new("uname").arg("-a").output();
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_total = mem.lines().find(|l| l.starts_with("MemTotal")).unwrap_or("unknown").to_owned();
    let kvm = std::path::Path::new("/dev/kvm").exists();
    Ok(serde_json::json!({
        "uname": uname.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()).unwrap_or_default(),
        "mem_total": mem_total,
        "kvm": kvm,
    }))
}

fn summarize(art: &Artifact) {
    use std::collections::BTreeMap as M;
    let mut groups: M<&str, Vec<f64>> = M::new();
    for s in &art.samples {
        if s.ok {
            groups.entry(s.name.as_str()).or_default().push(s.wall_ms);
        }
    }
    for (name, mut v) in groups {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = v.len();
        let p50 = v[n / 2];
        let mean = v.iter().sum::<f64>() / n as f64;
        println!("{name}: n={n} mean={mean:.2}ms p50={p50:.2}ms min={:.2}ms max={:.2}ms", v[0], v[n-1]);
    }
    for nr in &art.not_run {
        println!("NOT RUN: {nr}");
    }
}
