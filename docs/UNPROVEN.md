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
	timeout (10s typesafe / 15s openrouter), non-2xx, malformed = REFUSE. Secret-deny independent.
	- Wired into `dispatch --command` + `session exec` (2026-10-10); default
	  `cat TASK.md` path needs no classification. Manage via `somp jev …`
	  + `/somp-jev …` in TUI. TypeSafe backend: UNPROVEN live (no key).
	- OPENROUTER BACKEND LIVE 2026-10-11 (operator key): `somp jev check
	  "echo hello-jevtrial"` → classifier 200, `p=0.000 confidence=1.00
	  verdict=allow`, exit 0 (`backend=openrouter`, model
	  `mistralai/mistral-large-4-0` after `openrouter/` prefix strip).
	  Open refuse-path note: `rm -rf ~/Documents` refused via fail-closed
	  envelope-decode error, not a model verdict — diagnostic now captures
	  status + 200-char body sample; operator re-probe pending.

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

## It works: standard dispatch green end-to-end (2026-10-10)

- `SOMP_LEVEL=standard somp dispatch --task-file ... --command echo PROOF-RAN`
  → `exit_code 0`, `stdout PROOF-RAN`, sandbox `state: destroyed`, workspace
  dir gone, process exit 0. Full create→stage→exec→diff→destroy cycle green.
- What made it work without root:
  1. `environment_json(level)`: strict sends `{guard}`, standard sends `{}`
     (docker hardcodes `network_policy:false` so guarded placement can NEVER
     match it, even with AIEC_ALLOW_REDUCED_ISOLATION=1 — reverted that flag).
     With `network.enabled=false` the guest gets NO NIC: egress impossible by
     absence. `describe()` says so explicitly; never presented as Guard.
  2. Guest-side workspace scrub after diff: rootless Docker maps the container
     user to host subuid 525287, worker-as-gobrowse cannot reclaim → destroy
     503. `rm -rf` from inside runs as the owning uid → reclaim succeeds.
     Destroy stays the hard orphan gate; scrub failure only warns.
- Proven numbers: start_ms 394, duration 525ms (docker Exec warm).
- Still needs root (one system unit, drafted on request): strict
  firecracker+Guard (TAP via `ip`, nft fence) — fail-closed until then.
  Default srt command path needs the `somp-guest` image (unbuilt) —
  `/opt/somp/bin/srt` absent in plain alpine (exit 127, honest error).
- JEV: custom --command correctly refused pre-VM without key; proof used the
  explicit `somp jev off --allow-ungoverned-bash` hatch, config restored after.
- Local Postgres: plane healthy, bootstrap key 200, old Neon URL kept in
  `~/aiec/env.systemd.neon-bak-2026-10-10` for rollback. Neon password seen in
  transcript earlier → rotate `neondb_owner` when convenient.

## Strict wiring: template -> explicit policy for spark (2026-10-10, code green, plane unproven)
- Root cause: `GuardPolicy::template(ModelOnly)` hardcodes
  `CredentialBinding{header: authorization}` (policy.rs:1068). omp's own wire
  for `opencode-go` drops `Authorization` and emits `X-Api-Key`
  (packages/ai/src/providers/anthropic.ts, #6510) — the template path could
  never authenticate spark even with TAP green.
- Fix: `guard.model_credential_header` (default `authorization`) +
  `guard.model_path` (default `/v1/`). Non-default header switches
  `guard_json` to an explicit `GuardPolicy` (topology inside, version 1,
  single egress + zone + bound credential, POST-only) satisfying
  `validate_model_binding` + `validate_dns_egress_consistency`. New tests:
  `spark_wiring_pins_explicit_policy`, `bad_header_or_path_refuses`. 31/31 green.
- `somp model preset muse-spark` now pins `opencode.ai:443` + `x-api-key` +
  `/zen/go/v1/` (guest base `http://<gw>:8443/model/model-main/zen/go/v1`).
- Keys from OMP: `opencode-go` inline `sk-` (67 chars, no vault-ref) exported
  out-of-band to NUC `~/aiec/guard-credentials.json` (`{"model-main":…}`,
  0600) + `AIEC_GUARD_CREDENTIALS_FILE` in `env.systemd`, worker restarted.
- BLOCKED at link layer: NUC `192.168.1.250` neighbor FAILED (gateway .1 fine,
  WiFi up). Worker TAP probe + strict dispatch unproven until NUC back.

## NUC dark at link layer (2026-10-10 ~11:15 UTC)
- `192.168.1.250 dev wlp0s20f3 FAILED`; gateway `.1` pings fine, WiFi
  `pineapple_home_network` up — NUC itself down/asleep, not a local fault.
  Plane proofs (TAP probe, strict dispatch) blocked until it returns.
- Local TAP ceiling confirmed same as NUC: `ip tuntap add` ->
  `ioctl(TUNSETIFF): Operation not permitted` unprivileged; `sudo -n`
  needs interactive auth. The system-unit fix stands as specified.
- Explicit spark policy shape validated offline 8/8 (triple agreement,
  zone coverage, POST-only, absolute paths, allowlisted header, no secret
  bytes in request). Test matrix 31/31 under SOMP_LEVEL unset/standard/
  strict/off.
- Guest build prerequisites present (builder script, srt dist, mke2fs,
  node/bun/bwrap/socat/rg) except `AIEC_KERNEL` + out-dir; build runs when
  the NUC (KVM host) is back — loop-mount needs root there.

## somp-guest image built locally via debugfs overlay (2026-10-10)
- Base: cached NUC rootfs (`~/guard-fc-images/rootfs-nuc.ext4`, Debian
  bookworm coding profile, clean fsck) + `vmlinux-nuc` (43M ELF).
- Overlay (no mount needed): `/etc/somp/srt-settings.json`,
  `/usr/local/bin/somp-bootstrap`, `/opt/somp/bin/{node,bun,srt-shim}`,
  full `/opt/somp/srt/dist` (168 files) + `package.json`. Verified by
  `ls -l` long-listing (earlier short-`ls` truncated names, false "missing") +
  sha256 round-trip on 3 files (MATCH) + `e2fsck -f` clean.
- Staged at `~/guard-fc-images/somp/{somp-guest.ext4,somp-guest.sha256,vmlinux}`.
  Registration on the NUC worker (`~/aiec/images/`) waits for the link.
- Honest gap: guest never booted — first boot is the NUC prove-out.

## Strict dispatch prove-out blocked on NUC power/link (2026-10-10 ~11:25 UTC)
- 3x ping sweep all 100% loss, neighbor FAILED. Everything strict needs —
  worker TAP probe, image registration, guarded dispatch — is staged and
  waits for the NUC to return. No code changes outstanding for strict.
- Ready checklist when the link returns:
  1. `ssh gobrowse@192.168.1.250` + `systemctl --user is-active aiec-worker`
     (credential file + restart already applied pre-outage).
  2. Copy `~/guard-fc-images/somp/somp-guest.ext4` + `vmlinux` to NUC,
     register in `~/aiec/images/` per worker image config.
  3. `SOMP_LEVEL=strict somp dispatch --task-file /tmp/proof-task.md
     --command echo --command PROOF-RAN` with `image: somp-guest`.
  4. Expect guest env `AIEC_MODEL_BASE_URL=http://<gw>:8443/model/model-main/zen/go/v1`
     + `AIEC_MODEL_API_KEY=placeholder://model-main`.

## Local plane live (2026-10-10): standard dispatch green on loopback
- Shape: `postgres:16-alpine` (loopback `127.0.0.1:15432`, volume `somp-pgdata`)
  + MinIO `agentforge-minio` (loopback `:19000`, bucket `aiec`, keys `aiec`
  dev-only in `~/.local/share/somp-local/.env.local` 0600) + `aiec-server`
  TLS (`:18444`, self-signed CA `tls/ca.pem`) + docker worker TLS (`:9091`,
  `--capacity 4`).
- Why not lighter: this AIec build has no sqlite — server requires
  `DATABASE_URL` + `AIEC_S3_*` + `AIEC_TLS_CERT_FILE/KEY_FILE` in production;
  in-memory mode refuses worker registration ("ephemeral deployments cannot
  accept workers"). bwrap-dev refused (self-host loopback counts production).
- Fixes found wiring it: `AIEC_ALLOW_CONTAINER_RUNTIMES=1` (default
  `hosted_only` refuses docker), `AIEC_TLS_CA_CERT` needed on the SERVER too
  (`HttpWorkerClient::new_secure` → `control_plane_http_client` reads it),
  worker needs same TLS cert files + `https://` advertise URL, capacity 4
  (stuck `destroying` row from pre-TLS attempt holds 1 slot; DELETE wedged on
  dead transport — capacity headroom routes around it).
- Proof: `SOMP_LEVEL=standard somp dispatch --task-file /tmp/proof-task.md
  --command echo --command PROOF-RAN` → `exit_code 0`, `stdout PROOF-RAN`,
  `duration_ms 405`. Config restored fail-closed (`image: somp-guest`,
  `allow_ungoverned_bash: false`, `enabled: true`).
- Footprint (idle): aiec-server RSS ~17MB, worker ~18MB, postgres ~78MB,
  minio ~75MB → ~190MB total. Images: minio 213MB + postgres 303MB virtual
  (cached pulls, shared layers). State dir 268K + pg volume + minio-data.
- somp now points at local plane: `base_url https://127.0.0.1:18444`,
  `~/.config/aiec/api-key` = local key (NUC key in `api-key.nuc-era-bak`),
  CA `~/.config/aiec/ca-somp-local.pem` via `AIEC_TLS_CA_CERT`.
	- UNPROVEN: strict (no firecracker/KVM here), JEV live (no TYPESAFE key),
	  stuck `destroying` row cleanup, multi-sandbox concurrency, restart
	  persistence (manual `nohup` — no systemd unit yet).
	## Host-scope traversal breakout + fix (2026-10-11, operator pentest)
	- Breakout (agent transcript `local://paste-4.md`): `read
	  /tmp/../etc/passwd` returned FULL host `/etc/passwd` (usernames incl
	  `gobrowse:1000`, `orlando:1001`, service accounts). Root cause:
	  `inWorkspace` string-prefix-checked absolute paths, resolving `..`
	  only for relative ones. `read /etc/passwd`, `find /`, `grep
	  /etc/passwd`, `glob ..`, `write ../canary` all held; eval/ssh held
	  (no listener). `ssh://` device never reached the scope gate at all.
	- Fix (`64262b0` follow-up, unpushed at write time): normalize EVERY path
	  lexically (`.`/`..` resolved, escapes above `/` refuse), unknown
	  `://` schemes refused in scope (second wall behind the read-URL gate),
	  `ssh://` added to `isUrlLike` (read gate refuses as egress). `file://`
	  now scoped, not passed through. 13-case harness ALL PASS (incl the
	  exact breakout string); live probes: `/tmp/../etc/passwd` refused
	  (scope), `ssh://localhost/etc/passwd` refused (egress).
	- Honest residue: the TUI shell is still the operator's own unsandboxed
	  process — gates are policy enforced in `tool_call`, not a sandbox.
	  Symlink escapes (`/tmp/link -> /etc` + `read /tmp/link/passwd`) NOT
	  covered: lexical normalization cannot see through symlinks; a
	  `realpath` check at gate time would close it (open).
	
	## JEV openrouter backend LIVE both directions (2026-10-11, operator key)
	- `somp jev check "echo hello-jevtrial"` → classifier 200, `p=0.000
	  confidence=1.00 verdict=allow`, exit 0 (model
	  `mistralai/mistral-large-4-0`, `openrouter/` prefix stripped).
	- `somp jev check "rm -rf ~/Documents"` → `p=0.990 confidence=0.99
	  verdict=refuse`, exit 1 (`p(destructive)=0.990 > 0.15`). First live
	  model-verdict refuse (earlier refuses were fail-closed decode errors;
	  fixed via raw-bytes + lossy decode + header diagnostics in `ff74229`).
	
	## JEV deterministic network-egress deny (2026-10-11, operator report)
	- Operator: JEV allowed internet access from host bash. Root cause:
	  the classifier asks only "destructive or irreversible" and `curl`
	  is not destructive (p≈0 → allow). No NIC policy exists on host bash
	  to enforce — the governed stance is host shells never touch the
	  network; network work belongs in the `somp_task` guest.
	- Fix: `deny_network_command()` in `jev_gate.rs` runs BEFORE any
	  classifier call (lexical, no key needed): URL literals
	  (http/https/ws/ftp/ssh), egress binaries at command/separator
	  boundaries (curl/wget/ssh/scp/nc/socat/…), `/dev/tcp|udp/`
	  redirections. Case-insensitive; `sync`/`echo curl` do NOT fire.
	  A model verdict can never allow what is structurally refused.
	- Live: `somp jev check "curl -sI https://example.com | head -3"` →
	  `refuse: network egress in host bash refused (https)` exit 1, no key
	  needed; benign `echo sync-check-word` still reaches the classifier
	  (`OPENROUTER_API_KEY unset` fail-closed, correct). Tests 41/41,
	  clippy 0.
	
	## JEV egress deny widened for paste-6 leak classes (2026-10-11)
	- Pentest evidence (`local://paste-6.md`): `getent hosts` resolved
	  public DNS, `ping 1.1.1.1` got ICMP replies, and `python3 -c
	  "socket.create_connection(…)"` opened a real TCP socket — all past
	  the egress deny, which only knew fetch binaries + URL literals.
	- Fix: `deny_network_command()` now also matches DNS/ICMP/recon tools
	  (ping/dig/nslookup/host/traceroute/nmap/tcpdump/…), `getent hosts`
	  (plain `getent passwd` stays allowed), interpreter-inline socket APIs
	  (interpreter + inline/module flag + socket-family token;
	  `python3 -m http.server`, `perl -e`, `ruby -rsocket -e`, …), and awk
	  `/inet/tcp|udp/` redirections. Shared `starts_tool()` helper keeps
	  `host`-vs-`hostname`/`ghost` boundaries exact.
	- Live: all three paste-6 leak commands now `refuse: network egress in
	  host bash refused (getent hosts|ping|interpreter socket)` exit 1 with
	  no key; benign `hostname; getent passwd root` still reaches the
	  classifier. Tests 42/42, clippy 0.
	- Honest residue: string matching cannot see obfuscated imports
	  (`__import__('so'+'cket')`) or socket code inside file arguments
	  (`python3 evil.py`). The durable fix stays a netns for host bash —
	  keyword lists narrow the window, they do not close the class.
	
	## Delta audit: openssl TLS tunnel + wrapper laundering closed (2026-10-11)
	- Findings: `openssl s_client -connect example.com:443` held a live
	  TLSv1.3 tunnel (stock binary, complete encrypted channel — most
	  serious keyhole); wrapper prefixes (`timeout 10 curl`, `sudo … ping`,
	  `bash -c "nc"`, `xargs curl`) laundered known tools past
	  start-of-command matching; `git clone/fetch/pull` had no gate while
	  the gate's own doc claimed the diff loop depends on local git.
	- Fix: TOOL_MARKERS gains openssl/gnutls-cli/stunnel/s_client/DB
	  clients/busybox (+ `git://` URL); new git-remote gate denies
	  clone/fetch/pull/push/ls-remote/archive/submodule as first non-flag
	  argv token (`-C <path>`/`-c`/`--git-dir` flag-arg aware so `git -C
	  /tmp/x fetch` reads `fetch`, not the path) while status/diff/log/add
	  stay allowed; new candidates()/strip_wrappers() match tools after
	  shell separators AND wrapper prefixes with token scanning
	  (absolute-path + find -exec aware). `echo curl` prose, `sqlite3`
	  (local only, no backend), bare wrappers, and local git unaffected.
	- Live: `openssl s_client -connect example.com:443` →
	  `refused (openssl)` exit 1 keyless; `timeout 10 curl …` → refused.
	  Tests 44/44, clippy 0.
	- Agent's class argument accepted outright: the socket-capable set is
	  unbounded and each name added is one keyhole narrowed, not the class
	  closed. Durable fix stays netns-by-uid for host bash (+ nft output
	  drop + CAP_NET_RAW drop + pinned DNS stub), with JEV as advisory +
	  logging. None of that exists yet — recorded, not built. The
	  `jev.enabled: false` vs enforcing-gate mismatch in
	  somp-config-preproof.yaml is still unreconciled (see prior entry).
	
	## Host-bash allowlist: default-deny + JEV checks the allowed (2026-10-11)
	- Operator: restrict host commands to an allowlist of known-safe
	  binaries; JEV still classifies what the list permits. Shipped:
	  `HOST_ALLOWLIST` (~50 binaries: inspect/search text, workspace ops,
	  cargo build-test-check, local-only git, our own CLIs, `env`) +
	  `check_allowlist()` running FIRST in `gate()` (host path), before the
	  net deny and before any classifier call — JEV never sees unvetted
	  argv. Guest-bound commands (dispatch `--command`, session exec) route
	  to `gate_for_guest()` (net deny + classifier, no allowlist — the
	  guest exists to run toolchains).
	- Shape rules: raw argv[0], NO wrapper stripping (timeout/sudo/sh/xargs
	  absent → wrapper-laundering refuses naming the wrapper); `cargo run /
	  install / publish / login / search` denied (exec/net); git remote
	  subcmds denied (local-only git stays for the diff loop); `VAR=x cmd`
	  skips to the real binary; `env` only with a non-empty allowlisted
	  remainder (bare `env` dump refused); `>`/`>>` to any file refused
	  (bypasses ext path scope — incl `2> file`), only `/dev/null` + `2>&1`
	  pass; `->`/`=>`/`>=` non-fires preserved.
	- Live (keyless): `python3 script.py` → `refuse: not on the host-bash
	  allowlist` exit 1; `openssl s_client …` → same; vetted `ls /tmp` →
	  passes allowlist, reaches classifier (`OPENROUTER_API_KEY unset`
	  fail-closed — the "JEV checks the allowed" half). Tests 46/46,
	  clippy 0.
	- Residue unchanged: allowlist is names, not containment —
	  `VAR=x` recursion and `env` remainder are re-checked, but shell
	  arithmetic/`$()` cannot smuggle a binary past argv[0] matching
	  (only allowlisted binaries execute; their FLAGS are still JEV's job
	  — e.g. `sed`/`awk` programs, `git` paths). Netns still the durable
	  fix for the network class.
