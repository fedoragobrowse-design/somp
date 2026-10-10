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
need cargo; need bun

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
