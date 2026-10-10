#!/bin/sh
# somp-bootstrap: runs at guest boot (session VM) or after TASK.md staging (subagent VM).
# Verifies the inner sandbox prerequisites, then reports readiness.
# Paths overridable for host-side simulation: SOMP_ETC, SOMP_OPT (default /etc/somp, /opt/somp).
set -eu

SOMP_ETC=${SOMP_ETC:-/etc/somp}
SOMP_OPT=${SOMP_OPT:-/opt/somp}

fail() { echo "somp-bootstrap: $1" >&2; exit 1; }

[ -f "$SOMP_ETC/srt-settings.json" ] || fail "srt settings missing at $SOMP_ETC/srt-settings.json"
command -v srt >/dev/null 2>&1 || [ -x "$SOMP_OPT/bin/srt" ] || fail "srt not on PATH"
command -v bwrap >/dev/null 2>&1 || fail "bwrap missing (srt Linux backend)"
command -v bun >/dev/null 2>&1 || [ -x "$SOMP_OPT/bin/bun" ] || fail "bun missing (omp runtime)"

# srt guest-fit probe: nested userns must work inside this microVM.
bwrap --unshare-user --dev-bind / / true 2>/dev/null || fail "bwrap --unshare-user fails in this guest (srt cannot enforce here)"

# srt config must validate (refuses invalid/missing per cli.ts refuseSettings).
SRT_BIN=$(command -v srt 2>/dev/null || echo "$SOMP_OPT/bin/srt")
"$SRT_BIN" --settings "$SOMP_ETC/srt-settings.json" true 2>/dev/null || fail "srt settings validation failed"

# No real credentials may be baked into the image: only placeholders allowed.
if grep -rEo 'sk-(ant|live|proj)-[A-Za-z0-9_-]{8,}|xox[bap]-' "$SOMP_ETC" "$SOMP_OPT" 2>/dev/null | head -1 | grep -q .; then
  fail "real credential pattern found in guest image overlay"
fi

SOMP_WORKSPACE=${SOMP_WORKSPACE:-/workspace}
mkdir -p "$SOMP_WORKSPACE" || fail "cannot create workspace at $SOMP_WORKSPACE"
echo "somp-bootstrap: ok (srt enforced, no baked secrets)"
