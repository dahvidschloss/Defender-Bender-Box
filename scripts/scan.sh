#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: scan <path-to-file>" >&2
    exit 2
fi

target="$1"
if [[ ! -e "$target" ]]; then
    echo "file not found: $target" >&2
    exit 1
fi

# Find the platform dir
plat_dir=$(ls -d "$WINEPREFIX/drive_c/defender/Platform"/*/ 2>/dev/null | head -n1)
if [[ -z "$plat_dir" ]]; then
    echo "no Defender platform dir under /defender — did you populate binaries/?" >&2
    exit 3
fi

# Map the Linux path into the Wine drive_z view.
win_target="z:${target//\//\\}"

cd "$plat_dir"

# Windows-side path to the platform dir, so mpscan finds mpengine.dll and the .vdm set.
win_plat=$(winepath -w "$plat_dir" 2>/dev/null | sed 's/\\*$//')

echo "[scan] platform: $plat_dir ($win_plat)"
echo "[scan] target  : $target ($win_target)"
echo "[scan] wine    : $(wine --version 2>&1)"
sha256sum "$plat_dir/mpengine.dll" "$WINEPREFIX/drive_c/shims/mpscan.exe" 2>/dev/null || true
for vdm in "$plat_dir"/*.vdm; do
    [[ -e "$vdm" ]] || continue
    stat -c '[scan] definitions: %n %s bytes' "$vdm"
done
echo "[scan] launching mpscan via injection loader..."

# Wine hands unhandled faults to winedbg, which blocks forever with no tty. Cap the run and SIGKILL the stragglers so a crash prints and exits instead of hanging.
set +e
timeout --kill-after=5 "${MPSCAN_TIMEOUT:-120}" \
    wine 'C:\shims\loader.exe' 'C:\shims\wdfilter_shim.dll;C:\shims\etw_stub.dll' -- 'C:\shims\mpscan.exe' "$win_target" "$win_plat"
rc=$?
pkill -9 -f winedbg 2>/dev/null
pkill -9 -f mpscan.exe 2>/dev/null
wineserver -k 2>/dev/null
[[ $rc -eq 124 || $rc -eq 137 ]] && echo "[scan] TIMEOUT after ${MPSCAN_TIMEOUT:-120}s" >&2
echo "[scan] exit_code: $rc"
exit $rc
