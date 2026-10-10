#!/bin/sh
# sOMP installer: builds somp, links it onto PATH, seeds
# ~/.config/somp/config.yaml. Idempotent — safe to re-run.
#
# NON-INTERFERENCE: this installer NEVER touches your omp setup —
# no ambient extension links (~/.omp/agent/extensions is left alone),
# no omp config changes, no flags injected into your shell rc.
# Plain `omp` runs exactly as before. Governed mode is opt-in per
# invocation via the `somp-omp` wrapper (below).
#
# Usage: ./install.sh [--prefix DIR]   (default prefix: $HOME/.local)
set -eu

PREFIX="${HOME}/.local"
# while-loop (not `for a in "$@"` + shift): the old form double-shifted
# `--prefix DIR` and rejected DIR as an unknown arg — only `--prefix=DIR`
# worked.
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix=*) PREFIX="${1#--prefix=}"; shift;;
    --prefix) shift; PREFIX="${1:?--prefix needs DIR}"; shift;;
    -h|--help) echo "Usage: ./install.sh [--prefix DIR]"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

REPO="$(cd "$(dirname "$0")" && pwd)"
BIN="${PREFIX}/bin"
CFGDIR="${HOME}/.config/somp"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need cargo; need bun; need git
# --- omp itself: install if missing (pinned canonical source), never touch config.
if ! command -v omp >/dev/null 2>&1; then
  echo "== omp not found — installing (https://omp.sh/install) =="
  need curl
  curl -fsSL https://omp.sh/install | sh
  command -v omp >/dev/null 2>&1 || { echo "omp install failed" >&2; exit 1; }
else
  echo "== omp present: $(command -v omp) ($(omp --version 2>/dev/null | head -1)) =="
fi
echo "== AIec =="
# Present (CLI on PATH, or the cached checkout this repo pins) → skip, loudly.
# Missing → clone the operator repo (AIec/AIec, NOT upstream), shallow, and
# build the three binaries self-hosting needs (aiec-api, aiec-cli, aiec-mcp).
# Full self-hosting (KVM+Postgres+S3+guest image) stays manual:
# https://github.com/fedoragobrowse-design/AIec#self-hosting
if command -v aiec >/dev/null 2>&1 || [ -x "${HOME}/.cache/somp/repos/aiec/target/release/aiec" ]; then
  echo "AIec present — skipping install (found: $(command -v aiec 2>/dev/null || echo "${HOME}/.cache/somp/repos/aiec/target/release/aiec"))"
else
  echo "AIec not found — cloning + building (this takes a few minutes)…"
  need git
  mkdir -p "${HOME}/.cache/somp/repos"
  if [ ! -d "${HOME}/.cache/somp/repos/aiec/.git" ]; then
    git clone --depth 1 https://github.com/fedoragobrowse-design/AIec.git "${HOME}/.cache/somp/repos/aiec"
  fi
  (cd "${HOME}/.cache/somp/repos/aiec" && cargo build --release -p aiec-api -p aiec-cli -p aiec-mcp)
  mkdir -p "${BIN}"
  for b in aiec aiec-mcp aiec-server; do
    if [ -x "${HOME}/.cache/somp/repos/aiec/target/release/${b}" ]; then
      ln -sf "${HOME}/.cache/somp/repos/aiec/target/release/${b}" "${BIN}/${b}"
      echo "linked ${BIN}/${b}"
    fi
  done
  echo "AIec built. Next (manual): guest image + plane — see AIec#self-hosting."
  echo "Check host readiness any time: ${BIN}/aiec doctor"
fi

# --- model auth: fast local presence check only (no network, no secrets).
# sOMP passes --model/auth straight through to omp (proven: MODELPROOF via
# opencode-go/muse-spark-1.3-contributor), so any omp login works governed.
# Claude paths: `omp login anthropic` (Pro/Max OAuth) or an opencode-go key
# (OPENCODE_API_KEY) for the muse-spark subscription lanes.
echo "== model auth check =="
if [ -n "${OPENCODE_API_KEY:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "provider key in env OK (name only, never printed)"
# omp stores login credentials file-based (agent/config.yml); the sqlite
# auth_credential_blocks table is empty on file-auth setups — check the file.
elif grep -qi "api_key\|oauth\|opencode" "${HOME}/.omp/agent/config.yml" 2>/dev/null; then
  echo "stored omp credentials in agent/config.yml OK"
elif command -v sqlite3 >/dev/null 2>&1 && [ -f "${HOME}/.omp/agent/agent.db" ]; then
  NCRED=$(sqlite3 "${HOME}/.omp/agent/agent.db" "SELECT count(*) FROM auth_credential_blocks;" 2>/dev/null || echo "?")
  if [ "${NCRED}" != "?" ] && [ "${NCRED}" -gt 0 ]; then
    echo "stored omp credentials: ${NCRED} block(s) OK"
  else
    echo "NOTE: no omp credentials found — run: omp login anthropic"
    echo "      (Claude Pro/Max OAuth) or set OPENCODE_API_KEY, then re-run."
  fi
else
  echo "NOTE: cannot verify omp auth — ensure 'omp login' done."
fi
# Skills/MCP: sOMP installs none. somp-omp IS omp (+1 extension flag), so
# your skills (~/.omp/skillshare, project dirs) and MCP servers load as in
# plain omp. Allow-list only: nothing auto-enabled here.

echo "== build somp =="
(cd "${REPO}/crates/somp-cli" && cargo build --release)
mkdir -p "${BIN}"
ln -sf "${REPO}/crates/somp-cli/target/release/somp" "${BIN}/somp"
echo "linked ${BIN}/somp"

echo "== install somp-omp wrapper (opt-in governed omp) =="
cat > "${BIN}/somp-omp" <<EOF
#!/bin/sh
# Opt-in governed omp: loads the sOMP extension explicitly (-e) with
# governed mode on. Plain \`omp\` is untouched — use this only when you
# want subagents in disposable microVMs.
# AIEC_TLS_CA_CERT: local plane uses a self-signed cert; the SDK reads this
# env var for the CA (never --insecure). Falls back to ~/.config/aiec/ca.pem.
if [ -z "\${AIEC_TLS_CA_CERT:-}" ] && [ -f "\$HOME/.config/aiec/ca.pem" ]; then
  export AIEC_TLS_CA_CERT="\$HOME/.config/aiec/ca.pem"
fi
SOMP_BIN="${BIN}/somp" SOMP_GOVERNED=1 exec omp -e "${REPO}/ext/somp-ext.ts" "\$@"
EOF
chmod +x "${BIN}/somp-omp"
echo "wrote ${BIN}/somp-omp"

echo "== seed config =="
mkdir -p "${CFGDIR}"
if [ ! -f "${CFGDIR}/config.yaml" ]; then
  cp "${REPO}/docs/config-sample.yaml" "${CFGDIR}/config.yaml"
  echo "wrote ${CFGDIR}/config.yaml (edit guard.model_host!)"
else
  echo "kept existing ${CFGDIR}/config.yaml"
fi

echo "== verify =="
"${BIN}/somp" doctor
bun build "${REPO}/ext/somp-ext.ts" --external @oh-my-pi/pi-coding-agent --outfile /dev/null >/dev/null \
  && echo "ext bundles OK"
# Prove plain omp is unaffected: no ambient extensions dir may exist.
if [ -e "${HOME}/.omp/agent/extensions/somp-ext.ts" ]; then
  echo "UNINSTALLING stale ambient link (would load sOMP into plain omp):" >&2
  rm -f "${HOME}/.omp/agent/extensions/somp-ext.ts"
  rmdir "${HOME}/.omp/agent/extensions" 2>/dev/null || true
fi
case ":${PATH}:" in *":${BIN}:"*) ;; *) echo "NOTE: ${BIN} not on PATH — add: export PATH=\"${BIN}:\$PATH\"";; esac
echo "done."
echo "  plain omp (unchanged): omp ..."
echo "  governed omp:          somp-omp ...   (needs guard.model_host set + AIEC_API_KEY exported)"
