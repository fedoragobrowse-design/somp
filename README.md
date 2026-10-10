# sOMP — Secure omp

Run your normal `omp` (skills, MCP servers, models, history — all yours, all
unchanged), but every **subagent** the model spawns runs inside a **disposable
AIec microVM**, wrapped in **srt**, with **Guard-brokered egress**. The
governed boundary is around subagent execution, not around you.

```
you → somp (governed omp TUI, your skills + MCP intact)
        └─ model spawns subagent (task tool — blocked locally)
             └─ somp_task → AIec microVM → srt-wrapped exec → git diff → destroy
```

## One-line install

```sh
git clone https://github.com/fedoragobrowse-design/somp.git ~/code/somp && ~/code/somp/install.sh
```

What the installer does (idempotent, safe to re-run):

1. Builds the `somp` CLI (release) and links `~/.local/bin/somp`.
2. Writes the `~/.local/bin/somp-omp` wrapper — opt-in governed omp.
3. Seeds `~/.config/somp/config.yaml` if absent (you edit `guard.model_host`
   + `aiec` plane settings).
4. Verifies `somp doctor` + the extension bundles; removes stale ambient
   extension links that would leak sOMP into plain `omp`.

What it never does: touch `~/.omp`, your omp config, skills, MCP servers, or
shell rc. **Plain `omp` runs exactly as before.**

Prerequisites: `cargo`, `bun`, and `omp` itself on `PATH`
([oh-my-pi](https://github.com/can1357/oh-my-pi)). The installer tells you
what's missing instead of failing halfway.

## Daily use

| Command | What it does |
|---|---|
| `somp` | Opens the **governed omp TUI** (your normal omp + sOMP extension) |
| `somp-omp` | Same thing via the wrapper (identical; `somp` just execs this path) |
| `omp` | Plain omp — untouched, ungoverned, exactly as upstream ships it |
| `somp level [strict\|standard\|off]` | Show/set sandbox protection level |
| `somp model [show\|set <host> [port]\|preset muse-spark]` | Show/set Guard model endpoint (muse-spark pins `opencode.ai:443`) |
| `somp jev [status\|on\|off --allow-ungoverned-bash\|model <n>\|threshold <v>]` | JEV bash-gate: needs `TYPESAFE_API_KEY` in env, fail-closed |
| `somp update [--check]` | Pull + rebuild from **your** repo only (never upstream omp/npm) |

Inside the TUI:

- Status bar shows `sandbox 🛡️ STRICT` (or 🔶 STANDARD / ⚠️ OFF).
- `/somp-status` — mode, level, tier evidence.
- `/somp-level [strict|standard|off]` — switch live.
- `/somp-model [show|set <host> [port]|preset muse-spark]` — Guard endpoint.
- `/somp-jev [status|on|off --allow-ungoverned-bash|model <n>|threshold <v>]` — bash-gate.
- Resume governed with `somp-omp --resume <id>` (the extension rewrites
  omp's `omp --resume` hint in history; a shutdown reminder says so too).

## Protection levels

- **strict** (default): Firecracker microVM + Guard model-only egress + srt.
  Needs KVM; refuses governed work without it.
- **standard**: Docker worker + Guard + srt. Dev only — no microVM boundary.
- **off**: no sandboxing; `dispatch` and `session up` refuse fail-closed.

`SOMP_LEVEL` env overrides config; unknown values fail closed.

## Your skills and MCP servers

`somp-omp` **is** `omp` with one extra extension loaded (`-e`). Skills
(`~/.omp/skillshare`, project dirs) and MCP servers (omp's MCP config) load
exactly as in plain `omp` — same binary, same `~/.omp`, nothing filtered.
The extension only hooks `task` (blocked → `somp_task`) and `bash` (srt
rewrite). Subagent guests get staged files + task text only; MCP credentials
are not forwarded into VMs.

## Updating

- `somp update` → pulls **only** `fedoragobrowse-design/somp` (exact-match
  origin gate; `evil/somp.git` is refused), branch-aware, then rebuilds +
  reinstalls. `--check` reports without changing anything.
- `omp update` → upstream omp, untouched by sOMP. **Updating omp does not
  break the wrapper**: it execs `omp` from `PATH` with an explicit `-e` flag,
  so upstream changes flow through; if a future omp ever breaks the
  extension seam, `bun build` in the installer verify step catches it loudly
  instead of silently running ungoverned.

## Layout

```
crates/somp-cli/   Rust CLI (doctor/level/update/session/dispatch/policy/bench)
ext/somp-ext.ts    omp extension (governed task block, somp_task, srt rewrite)
guest/             microVM guest files (srt settings, bootstrap, image build)
policies/          Guard policy presets
bench/             raw-JSON benchmark artifacts (git-ignored)
docs/              config-sample.yaml, UNPROVEN.md (honest unproven list)
```

## Status & honesty

This is a working research prototype. `docs/UNPROVEN.md` lists what is
measured vs claimed — warm-start <1s and per-subagent RSS need Firecracker
E2E; host-side srt numbers are proxies, not guest evidence. Failures are
loud and fail-closed, never silent ungoverned fallbacks.
