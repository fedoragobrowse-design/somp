# UNPROVEN (must verify before any security claim)
## Wire batch 2026-10-10 (OpenRouter 400, muse-spark endpoint, JEV live, blockers)

### OpenRouter `mistral-large-4-0` 400 — root-caused in omp source
- Failing request (`~/.omp/logs/http-400-requests/1791641872271-*.json`):
  `include: ["reasoning.encrypted_content"]` + `reasoning: {effort: high}`
  against `openrouter/mistralai/mistral-large-4-0` → provider 400.
- `include` comes from `applyResponsesCompatPolicy`
  (`packages/ai/src/providers/openai-shared.ts:4051`): the catalog entry
  (`packages/catalog/src/models.json`: `openrouter/mistralai/mistral-large-4-0`)
  sets `compat.includeEncryptedReasoning: true`, so omp unconditionally
  pushes `reasoning.encrypted_content` — the provider rejects it.
  Same entry maps `reasoning: true` + `thinking.mode: effort` (high valid),
  so effort is fine; the encrypted-content include is the break.
- sOMP-side fix (operator, no omp fork): avoid that model on OpenRouter, or
  retry with reasoning disabled (`forceReasoningOff` path sends
  `reasoning: {effort: none}` and skips the include push). Upstream fix
  belongs in omp's compat table (drop `includeEncryptedReasoning` for this
  model) — sOMP keeps omp changes minimal/upstreamable, so not patched here.
- 403 `Key limit` (`63b18fa5`) is the OpenRouter key's spend cap, not a bug.
- Recommended lane stays `opencode-go/muse-spark-1.3-contributor`
  (`baseUrl https://opencode.ai/zen/go/v1`, `api openai-responses`,
  verified 2026-10-10) — `somp model preset muse-spark` pins it.

### JEV bash-gate: live (needs TYPESAFE_API_KEY + `somp jev on`)
- `crates/somp-cli/src/jev_gate.rs`: `gate()` POSTs
  `{TYPESAFE_BASE_URL|https://api.typesafe.ai}/v1/systemone`
  (shape mirrors omp `ai/src/judgment/typesafe.ts`), `decide_with_threshold`
  enforces `cfg.jev.threshold` (default 0.15). Fail-closed: disabled without
  explicit `--allow-ungoverned-bash`, missing/empty key, unreachable,
  timeout (10s), non-2xx, malformed = REFUSE. Secret-deny independent.
- Wired into `dispatch --command` + `session exec` (2026-10-10); default
  `cat TASK.md` path needs no classification. Manage via `somp jev …`
  + `/somp-jev …` in TUI. UNPROVEN: no live classifier 200 yet (no key
  provisioned) — gate proven only by fail-closed refusal paths + unit tests.

### Guest image (somp-guest) — build runbook
- Builder: `AIec/scripts/build-firecracker-guest.sh` (AIec checkout), needs
  `AIEC_KERNEL` (guest vmlinux) + root. Overlays our `guest/bootstrap.sh`
  (bakes srt to `/opt/somp/bin/srt`, settings to `/etc/somp/srt-settings.json`)
  onto the AIec base (bwrap/socat/rg come from base, probed at boot).
- Status: UNBUILT on this host. NUC approved 2026-10-10 (KVM + guest kernel
  present) — run the builder there, register image as `somp-guest`, then
  `somp session up --image somp-guest`.

### Docker-worker destroy reclaim — upstream bug, precisely located
- `01a1236f` class: container gone (exec 404s) but `destroy` fails
  `Permission denied (os error 13)`, record stuck `running` till TTL.
- Root: `aiec-runtime/src/docker.rs:1273 reclaim_workspace` →
  `remove_dir_all` on guest-created files owned by a UID the worker cannot
  `restore_owner_access`+remove; error maps to `Unavailable`, and
  `aiec-api/src/runs.rs:1666 is_transient_destroy_error` retries
  `Unavailable` 4x (400ms backoff) then surfaces terminal. Retry is correct
  (transient kill/remove hiccups must not orphan), but an ownership failure
  is PERMANENT — retry never converges. Upstream fix: chown-to-worker or
  rootless-removal fallback in `reclaim_workspace`, or classify ownership
  failures non-transient. sOMP already treats destroy-failure as hard error.
### Local plane TLS+auth fixed 2026-10-10 (`7232430`); plane-side blockers remain
* sOMP fixes (shipped): `aiec.rs Client::new` ignored `AIEC_TLS_CA_CERT`
  (always failed TLS verify against self-signed 18443); `main.rs` set the CA
  fallback only on the TUI path. Fix: PEM load via `Certificate::from_pem` +
  `add_root_certificate` (never insecure), `ensure_local_ca()` hoisted to top
  of `main()` for every command. Auth: NUC env bootstrap key (`88b0…`) 401'd
  — Neon DB digest no longer matched (Oct 9 rotation revoked it); minted a
  format-valid key (`af_live_`+48 hex, `validate_api_key` rejects anything
  else) and INSERTed its SHA256 digest as Admin for the plane tenant
  (`01a12651-c5aa-…`). Proven: `session show` + `/v1/keys` 200, no manual env.
* Plane-side (NOT sOMP, needs NUC operator action): strict+firecracker create
  → 503 `scheduler_unavailable` (all 3 workers alive on NUC, heartbeats stale
  or capacity pinned); standard+docker create → 400
  `guard_runtime_unavailable` (Guard env in request needs microVM; plane
  requires `AIEC_ALLOW_REDUCED_ISOLATION=1` to accept docker downgrade);
  two stale docker sandboxes (`01a12388`, `01a1236f`) un-destroyable (503 on
  DELETE = the reclaim ownership bug above). Default image stays `somp-guest`
  (UNBUILT); `alpine:3.21` is the plane-known reference (content-id
  `afimg1_b3fe…` must NOT be sent as the image string — `resolve()` expects
  the reference). Live governed dispatch 200 UNPROVEN until plane recovers.
### AIec upstream checked 2026-10-10: 4 new commits, none plane-side
* `0f516df..ebc41ac` (Oct 9): `a1f2274` (already ported), `a00cda6` operator
  context + steering hardening, `ed103bb` env bindings restore, `ebc41ac`
  same-turn steering — all `harness/`-scoped. No storage/runtime/api change:
  no upstream fix for destroy-reclaim or scheduler capacity. Nothing to port.


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

## Local-DB migration + Guard placement root cause (2026-10-10, operator-approved)

- Neon dead (host-side TCP RST on 5432/6543, NUC egress 80/443-only) → moved
  plane to NUC-local Postgres: `podman run postgres:16` (cached image; Docker
  Hub pull blocked by stale Synology MITM cert), loopback-only 5432,
  password in `~/.config/aiec/pgpass-local` (NUC-side only, never in chat).
  Old Neon `DATABASE_URL` kept in `~/aiec/env.systemd.neon-bak-2026-10-10`.
- Fresh DB → old keys 401 (correct); NUC env bootstrap key now live (200).
  `somp session show` healthy again (`no session` = correct empty state).
- Governed dispatch 503 root-caused to PLACEMENT FILTER, not capacity:
  all 3 workers healthy/accepting with free vCPU, but guarded requests
  demand `network_policy:true` (`create_sandbox` lib.rs: guarded → required),
  and the NUC firecracker worker advertises `false`.
- Capability chain: `FirecrackerRuntime::capabilities()` asks its network
  backend; `GuardNetworkManager` reports `can_enforce = probe_enforcement()`
  = `nft list ruleset` success. Worker runs as unprivileged user unit →
  `Operation not permitted`. Operator granted nft caps (keep scoped per
  review: prefer system unit `AmbientCapabilities=CAP_NET_ADMIN` over
  global `/usr/bin/nft` setcap; nft upgrades strip file caps — runbook item).
- Twist: deployed `~/aiec/bin/aiec` (2026-10-08) contains NO
  `probe_enforcement`/`can_enforce` strings — predates the Guard probe, so
  its fc backend reports `network_policy:false` unconditionally. Rebuilding
  worker from `~/aiec-build` (has Guard wiring) via
  `cargo build --release -p aiec-cli`; then swap binary + restart worker +
  re-probe caps + prove `somp dispatch`. PENDING build (bg_64).

## Worker binary rebuild + TUN gap (2026-10-10, pending operator setcap)

- Deployed `~/aiec/bin/aiec` predated Guard probe (`probe_enforcement` absent
  from strings) → rebuilt from `~/aiec-build` (`cargo build --release -p
  aiec-cli`, backup `~/aiec/bin/aiec.pre-guard-2026-10-10`). Swap needed full
  `systemctl --user stop` + `pkill -x aiec` first (Text file busy otherwise);
  inode changed 3031636 size 35384448 → 35287336. Old binary kept for rollback.
- New binary + operator nft caps → fc worker now advertises
  `network_policy:true` (probed live). Governed placement 503 SOLVED.
- Next failure one layer deeper: `backend_unavailable: ip failed:
  ioctl(TUNSETIFF): Operation not permitted` — worker process itself needs
  CAP_NET_ADMIN for tap devices (`/dev/net/tun` perms fine 666). `setcap`
  as unprivileged user fails (`Operation not permitted`); needs one root
  line: `sudo setcap cap_net_admin+ep ~/aiec/bin/aiec`, then the global
  `/usr/bin/nft` cap can come off (worker children inherit). Binary swaps
  need re-cap (runbook).
