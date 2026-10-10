#!/bin/bash
# Build the somp guest rootfs on top of AIec's guest builder.
#
# Usage: ./build-guest.sh [out-dir]   (default /var/lib/somp/images)
# Requires: AIec checkout at $AIEC_REPO (default ~/.cache/somp/repos/aiec),
#   AIEC_KERNEL (uncompressed guest kernel), root privileges for mkfs/mount steps
#   inside build-firecracker-guest.sh.
#
# What it does:
#   1. Runs AIec scripts/build-firecracker-guest.sh (coding profile) to produce
#      aiec-rootfs.ext4 + guest-capabilities.json.
#   2. Overlays somp additions into a COPY of the rootfs (never mutates AIec's):
#      /etc/somp/srt-settings.json, /usr/local/bin/somp-bootstrap,
#      /opt/somp/bin/{srt(node wrapper),node,bun}, /opt/somp/srt/{dist,package.json}.
#      bwrap/socat/rg are NOT baked: they must come from the AIec base image
#      (coding profile); bootstrap.sh probes bwrap at boot and fails closed if
#      absent. Verify with guest-capabilities.json before publishing.
#
# Fail-closed: any missing prerequisite aborts; no partial image is published.
set -euo pipefail

OUT=${1:-/var/lib/somp/images}
AIEC_REPO=${AIEC_REPO:-$HOME/.cache/somp/repos/aiec}
HERE=$(cd "$(dirname "$0")" && pwd)

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need mke2fs; need e2fsck; need resize2fs
need node; need bun
[ -f "$AIEC_REPO/scripts/build-firecracker-guest.sh" ] || { echo "AIec repo not at $AIEC_REPO (set AIEC_REPO)" >&2; exit 1; }
[ -n "${AIEC_KERNEL:-}" ] || { echo "set AIEC_KERNEL to an uncompressed guest kernel" >&2; exit 1; }
# srt must be a BUILT checkout: dist/cli.js from `npm run build`, not the npm
# tarball name (package renamed @anthropic-ai/sandbox-runtime; the srt bin on
# PATH may be a stale shim). SRT_REPO overridable, defaults beside AIEC_REPO.
SRT_REPO=${SRT_REPO:-$HOME/.cache/somp/repos/srt}
[ -f "$SRT_REPO/dist/cli.js" ] || { echo "srt dist missing: run (cd $SRT_REPO && npm install && npm run build)" >&2; exit 1; }
# The settings file baked into the image must validate against the SAME
# srt revision's schema — refuse to build an image whose sandbox Carly refuses.
# bun transpiles the TS source directly (proven 2026-10-09: VALID).
SOMP_VALIDATE_TMP=$(mktemp)
cat > "$SOMP_VALIDATE_TMP.ts" <<EOF
import { readFile } from 'node:fs/promises';
import { SandboxRuntimeConfigSchema } from '$SRT_REPO/src/sandbox/sandbox-config.ts';
const raw = await readFile('$HERE/srt-settings.json', 'utf8');
const r = SandboxRuntimeConfigSchema.safeParse(JSON.parse(raw));
if (!r.success) { console.error(JSON.stringify(r.error.issues.slice(0, 5))); process.exit(1); }
console.log('srt-settings.json: VALID');
EOF
bun "$SOMP_VALIDATE_TMP.ts" || { echo "srt-settings.json fails srt schema validation; refusing image build" >&2; exit 1; }
rm -f "$SOMP_VALIDATE_TMP" "$SOMP_VALIDATE_TMP.ts"

mkdir -p "$OUT"
export AIEC_GUEST_SECRET="${AIEC_GUEST_SECRET:-$(openssl rand -hex 32)}"
export AIEC_KERNEL
"$AIEC_REPO/scripts/build-firecracker-guest.sh" "$OUT"

BASE="$OUT/aiec-rootfs.ext4"
SOMP_ROOTFS="$OUT/somp-guest.ext4"
[ -f "$BASE" ] || { echo "expected $BASE from AIec builder" >&2; exit 1; }
cp --reflink=auto "$BASE" "$SOMP_ROOTFS"

MNT=$(mktemp -d)
trap 'umount "$MNT" 2>/dev/null; rmdir "$MNT"' EXIT
mount -o loop "$SOMP_ROOTFS" "$MNT"

# Overlay somp files.
mkdir -p "$MNT/etc/somp" "$MNT/workspace" "$MNT/usr/local/bin"
cp "$HERE/srt-settings.json" "$MNT/etc/somp/srt-settings.json"
chmod 644 "$MNT/etc/somp/srt-settings.json"
cp "$HERE/bootstrap.sh" "$MNT/usr/local/bin/somp-bootstrap"
chmod 755 "$MNT/usr/local/bin/somp-bootstrap"
# Runtimes baked from host (fail-closed if absent). srt ships as COMPILED
# dist/ + node (proven: dist/cli.js exit-propagation + net-deny verified);
# copying a `srt` bin would bake a node-shebang shim without its modules.
for bin in bwrap socat rg; do
  command -v "$bin" >/dev/null 2>&1 || { echo "guest prerequisite missing on build host: $bin" >&2; exit 1; }
done
mkdir -p "$MNT/opt/somp/bin" "$MNT/opt/somp/srt"
cp -r "$SRT_REPO/dist" "$SRT_REPO/package.json" "$MNT/opt/somp/srt/"
cp "$(command -v node)" "$MNT/opt/somp/bin/node"
cp "$(command -v bun)" "$MNT/opt/somp/bin/bun"
cat > "$MNT/opt/somp/bin/srt" <<EOF
#!/bin/sh
exec /opt/somp/bin/node /opt/somp/srt/dist/cli.js "\$@"
EOF
chmod 755 "$MNT/opt/somp/bin/srt"

umount "$MNT"
trap - EXIT
rmdir "$MNT"
e2fsck -p -f "$SOMP_ROOTFS" || { echo "rootfs fsck failed" >&2; exit 1; }

sha256sum "$SOMP_ROOTFS" | awk '{print $1}' > "$OUT/somp-guest.sha256"
cat > "$OUT/somp-guest.json" <<EOF
{
  "name": "somp-guest",
  "base": "aiec-rootfs.ext4 (AIec coding profile)",
  "overlay": ["etc/somp/srt-settings.json", "usr/local/bin/somp-bootstrap", "opt/somp/bin/{srt,node,bun}", "opt/somp/srt/{dist,package.json}"],
  "built_at": "$(date -u +%FT%TZ)",
  "aiec_rev": "$(cd "$AIEC_REPO" && git rev-parse HEAD)"
}
EOF
echo "guest image: $SOMP_ROOTFS"
cat "$OUT/somp-guest.json"
