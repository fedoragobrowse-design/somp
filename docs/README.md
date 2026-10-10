# sOMP (Secure OMP)

Run omp with three layers: omp CLI in a long-lived AIec session VM, each
subagent in a disposable AIec microVM, srt wrapping tool execution in every
guest, Guard egress defaulting to model-endpoint-only with proxy tokens.

## Install

1. Build the CLI: `(cd crates/somp-cli && cargo build)` → `target/debug/somp`.
2. Copy `docs/config-sample.yaml` to `~/.config/somp/config.yaml`; set
   `guard.model_host`/`model_port` to the real model endpoint and export
   `AIEC_API_KEY` (or set `aiec.key_file`).
3. Build the guest image: `AIEC_KERNEL=<uncompressed kernel> guest/build-guest.sh`
   (needs root + `$AIEC_REPO` checkout; validates `srt-settings.json` against
   the pinned srt schema before baking).

## Usage

- `somp doctor` — tier candidacy (KVM, bwrap userns, nft note).
- `somp session up|snapshot|restore|exec|destroy|show` — long-lived session VM.
- `somp dispatch --task-file TASK.md [--file <guest>=<host>...] [-- command...]`
  — one governed subagent run (create → stage → exec → diff → destroy).
- `somp policy propose --add-host h[:port] --reason ...` — Guard widening
  proposal (agent proposes; a DIFFERENT human key approves out-of-band).
  `somp policy proposals|show` reads the journal.
- `somp bench --out bench/out --reps N [--aiec]` — raw-JSON benchmarks.

omp integration: `ext/somp-ext.ts` exports `sompExt` (governed `task` block +
`somp_task` tool + bash `srt` rewrite + `/somp-status`).

## Threat model

- Outer boundary: Firecracker microVM per subagent (Tier::Firecracker only
  governed tier; Docker/Bubblewrap refuse governed work — fail-closed).
- Inner boundary: srt (`allowWrite /workspace,/tmp`; narrow `.git` carve-outs;
  deny-before-allow precedence verified in source).
- Egress: Guard broker, model-endpoint-only default; real keys never enter the
  guest (`placeholder://` broker); widening is add-only + independent-reviewer.
- Session persistence: recreate + `SnapshotKind::Workspace` (no warm pools).

## Limitations (see UNPROVEN.md)

No live control plane has been touched: session/dispatch/snapshot E2E,
warm-start <1s, and per-subagent RSS are unmeasured. Host-side srt numbers
(~0.3s wrap, ~2.0s trivial omp task) are proxies, not guest evidence.
