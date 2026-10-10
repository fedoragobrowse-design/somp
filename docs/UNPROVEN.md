# UNPROVEN (must verify before any security claim)

## AIec-box proof 2026-10-10 (public repo, docker worker)

- Proof ran INSIDE an AIec box (`python:3.13`, docker) via file-tool staging:
  `bootstrap.sh` sha256 matches commit `9dda0810…` byte-identical,
  `bash -n` clean, `srt-settings.json` parses (network+filesystem keys).
- `secrets.rs` deny/scrub + `jev_gate.rs` decide() re-implemented in Python
  in-box, same assertions as Rust tests: **5/5 passed** (logic-equivalence,
  NOT a Rust compile proof — no cargo in box).
- Honest limits: `rust:stable` image pull blocked by expired worker registry
  cert; `git clone github.com` in-box blocked by worker-TLS interception
  (egress MITM with expired box CA — do NOT bypass with `GIT_SSL_NO_VERIFY`);
  no node in box so ext surface check not run.
- Full `cargo build`+`cargo test` in-box proof BLOCKED on worker infra
  (registry cert + TLS interception), not on the repo. Host ran 15/15 green.
- Destroy hit the known Docker-worker reclaim bug (`Permission denied`
  os error 13, box awaiting TTL) — same class as earlier orphan.

## Security rotation 2026-10-10 (operator key leaked into transcript)

- `cat ~/.config/aiec/api-key` printed the live bootstrap-admin key into the
  transcript. Rotated: minted `operator-console-2026-10-10` (4 scopes) +
  `bootstrap-replacement-2026-10-10` (admin) via key-file-passed Bearer only;
  revoked bootstrap `01a0e4b5…` + 5 stale keys; leaked file shredded.
- Verified by status code only: leaked → 401, both replacements → 200.
- Revoke works (throwaway 200→401); `GET /v1/keys` lists revoked keys too
  (no `revoked_at` filter in `list_keys_for`) — presence in list proves nothing.
- Upstream `a1f2274` ported into somp: `crates/somp-cli/src/secrets.rs`
  (argv secret-path deny + output scrub at print boundary); dispatch refuses
  before VM create, never `cat`s key files. `cargo build` clean, 15/15 tests.
- NEVER `cat` key files to stdout again: `ls -l`/`test -f` for presence,
  `AIEC_API_KEY_FILE`/fd for passing.

## Proven live 2026-10-10 (local AIec MCP, docker runtime)

- Control plane reachable: `aiec_health` ok (`https://127.0.0.1:18443`).
- Dispatch-shaped skeleton E2E green on `alpine:3.21` docker 1cpu/512MB:
  write TASK.md → exec cat → exec write RESULT.md → ls+md5sum →
  read RESULT.md (`DISPATCH_OK`, md5 `bff2f484…`) → destroy confirmed.
  Raw: `bench/out/live-docker-skeleton-2026-10-10.json`.
- Exec round-trip `duration_ms` ~39–43ms server-side; create→running ~14s
  wall (single sample, docker pull likely included — NOT a warm-start claim).
- Guest is bare alpine: no bun/node/python3/cargo; somp-guest image still
  unbuilt (needs `AIEC_KERNEL` + root builder).
- Firecracker unavailable from here: `nft ... Operation not permitted`
  (needs root); first docker attempt hit `LOCAL_CAPACITY_UNAVAILABLE`,
  retry ~1min later scheduled clean.
- Docker-worker destroy bug (live 2026-10-10, `01a1236f`): container gone
  (exec 404s) but `destroy` fails 2x `Permission denied (os error 13)` —
  guest-created files owned by a user the worker cannot remove; record stuck
  `running` till TTL. Orphaned workspace on the KVM host needs a worker-side
  fix. `dispatch` already treats destroy-failure as hard error (no silent orphan).
- `git add -N` + plain `git diff --binary` verified on host (exit 0, exact
  new-file diff) — matches the server `git_diff` command shape.
- Dispatch `git_diff` mismatch FIXED (found live 2026-10-10, `dispatch.rs`):
  server `git_diff` hardcodes `git -C /workspace/repository diff --binary`
  (tracked-only, no `--cached`); dispatch staged to `/workspace/` → diffs
  would silently return Null. Now: `git init repository` + stage under
  `/workspace/repository/`, default command ends with `git add -N .` so new
  files appear in the diff. `ext/somp-ext.ts` `--file` paths aligned.
  `cargo build` clean, `cargo test` 6/6. Raw: `bench/out/live-docker-gitdiff-*.json`.
  Still unproven: real `somp dispatch` run (needs API key wiring to plane).

## Approved 2026-10-10 (user): NUC + model key + latest AIec + JEV gate

- NUC build host APPROVED for builds (user 2026-10-10): KVM present, guest
  kernel present, container runtime available. Guest-image build +
  Firecracker E2E unblocked (next: run builder there). Host identity, paths,
  and versions kept out of this public file — see operator runbook.
- AIec pinned to latest `ebc41ac` (was `0f516df`): +449/-20 across 10 files.
  Reviewed `a1f2274` (exfil-chain fix, ported to `secrets.rs`) + `a00cda6`
  (operator-context hardening) + steering same-turn fix. No API-shape drift
  at our seams (keys/sandboxes/exec/diff routes unchanged); client untouched.
- Model endpoint: user's `mise park 1.3 contributor` (opencode-go
  subscription) key APPROVED for `api.meta.ai/muse-code/key` device-code flow
  (`packages/ai/src/registry/oauth/muse-code.ts`). NOT YET WIRED: needs
  `OMP_MUSE_SPARK_KEY` (or device flow) + Guard `model_host/model_port`
  pointed at `api.meta.ai:443` + live proposal round-trip. `config-sample.yaml`
  still shows `api.example-model.com` placeholder — replace before any
  model-egress run.
- JEV bash gate DESIGNED (addition 2026-10-10): TypeSafe `jev.systemOne`
  (`destructive` noul + `action` allow/confirm/block, threshold p>0.15,
  key via `TYPESAFE_API_KEY`). Policy pure fn `crates/somp-cli/src/jev_gate.rs`
  (6/6 new tests, 15/15 total); secret-deny stays independent (Jev `allow`
  never overrides). Live classifier wiring NOT IMPLEMENTED (needs
  `TYPESAFE_API_KEY` + SDK check). No bash runs through the gate until wired.

## Proven on host (not guest evidence)

- `srt-settings.json` VALID vs srt 4160dcd `SandboxRuntimeConfigSchema`.
- srt spawn deterministic (exit-propagation 3/3/3); fs deny+allow enforced;
  egress `ENETUNREACH`; cold wrap 0.17–0.41s (bun) / 0.23–0.34s (dist).
- `denyRead /proc/*/mem|maps` removed: glob expands to live PIDs, exiting PID
  aborts spawn (racy). Guest PID namespace covers this instead.
- API shapes verified in source (route table lib.rs, proposals, snapshots,
  GuardConfig, NetworkPolicy wire format) — client matches, but no 200 seen.

## Source-verified, behavior-unproven

- AIec 0f516df route/handler contracts (no live 200/403 observed).
- srt deny-before-allow (`linux-violation-monitor.ts isDenied`) — enforced on
  host probes, guest kernel path untested.

## Fixed 2026-10-10 (review backlog, source-verified)

- dispatch default command uses absolute `/opt/somp/bin/srt` + `/etc/somp/...`
  paths (guest exec PATH unverified; image bakes these exact paths).
- `session restore` now stores the NEW sandbox id as session state before
  `--kill-old` deletes the old VM (previously state was cleared/lost).
- bench `srt_true_host` note records the invoking binary + settings path.
- build manifest lists the true overlay (bootstrap + srt/node/bun + dist);
  bwrap/socat/rg come from the AIec base image, probed at boot (fail-closed).
