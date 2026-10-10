# sOMP (Secure OMP)

Run omp with three layers: omp CLI in a long-lived AIec session VM, each
subagent in a disposable AIec microVM, srt wrapping tool execution in every
guest, Guard egress defaulting to model-endpoint-only with proxy tokens.

## Install

`./install.sh` (idempotent; `--prefix DIR`, default `~/.local`): builds
release, links `~/.local/bin/somp`, writes the `~/.local/bin/somp-omp`
wrapper, seeds `~/.config/somp/config.yaml` if absent, verifies
`somp doctor` + ext bundle, removes stale ambient extension links. Touches
nothing in omp's own setup — plain `omp` runs exactly as before.

Then copy `docs/config-sample.yaml` to `~/.config/somp/config.yaml`; set
`aiec.base_url` + `key_file` (file-first, never secret bytes in env/config),
`guard.model_host`/`model_port`, and `AIEC_TLS_CA_CERT` for the self-signed
plane. Guest image: `AIEC_KERNEL=<uncompressed kernel> guest/build-guest.sh`.

## Usage

- `somp` (bare) — opens the governed omp TUI (same as `somp tui`).
- `somp level [strict|standard|off]` — show/set sandbox protection level
  (`SOMP_LEVEL` env wins over config; unknown values fail closed).
  Standard dispatches to the Docker worker, strict to Firecracker; off
  refuses `dispatch` and `session up`.
- `somp update [--check] [--allow-foreign-origin]` — pull + rebuild +
  reinstall from YOUR repo (`fedoragobrowse-design/somp`) only. Exact-match
  origin gate refuses upstream omp or lookalikes (`evil/somp.git` proven
  refused); branch-aware (`@{u}`, falls back to `origin/HEAD`). Never npm.
- `somp doctor` — tier candidacy (KVM open-probe, bwrap userns, nft note).
- `somp session up|snapshot|restore|exec|destroy|show` — long-lived session VM.
- `somp dispatch --task-file TASK.md [--file <guest>=<host>...] [-- command...]`
  — one governed subagent run (create → stage → exec → diff → destroy).
- `somp policy propose --add-host h[:port] --reason ...` — Guard widening
  proposal (agent proposes; a DIFFERENT human key approves out-of-band).
  `somp policy proposals|show` reads the journal.
- `somp bench --out bench/out --reps N [--aiec]` — raw-JSON benchmarks.

omp integration: `ext/somp-ext.ts` exports `sompExt` (governed `task` block +
`somp_task` tool + bash `srt` rewrite + `/somp-status` + `/somp-level` +
status-bar `sandbox <LEVEL>` badge + shutdown resume reminder +
`assistant_message` rewrite of `omp --resume` → `somp-omp --resume` in
persisted history). In-TUI `/resume` needs no rewrite (ext already loaded).

## Threat model

- Outer boundary: Firecracker microVM per subagent at strict; standard uses
  the Docker worker (dev only, no microVM — `describe()` says so honestly).
- Inner boundary: srt (`allowWrite /workspace,/tmp`; narrow `.git` carve-outs;
  deny-before-allow precedence verified in source).
- Egress: Guard broker, model-endpoint-only default; real keys never enter the
  guest (`placeholder://` broker); widening is add-only + independent-reviewer.
- Session persistence: recreate + `SnapshotKind::Workspace` (no warm pools).
- Update: exact-match origin gate; foreign code cannot rebuild the binary
  without `--allow-foreign-origin`.

## Limitations (see UNPROVEN.md)

Warm-start <1s and per-subagent RSS unmeasured (needs Firecracker E2E).
Host-side srt numbers (~0.3s wrap, ~2.0s trivial omp task) are proxies, not
guest evidence. Docker-worker destroy reclaim bug is worker-side (see UNPROVEN).
