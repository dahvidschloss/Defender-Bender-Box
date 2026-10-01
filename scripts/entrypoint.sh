#!/bin/bash
# Container entrypoint. Dispatches to scan / shell / engine.
set -euo pipefail

# Local env setup. Basically tell Wine where the "C" drive is and force it to use 64B mode.
export WINEPREFIX=/wine
export WINEARCH=win64
export WINEDEBUG=${WINEDEBUG:--all}
export DISPLAY=:99

# Start a fake monitor so wine doesn't crash when it tries to draw a window.
Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 &
XVFB_PID=$!

#If this script crashes, kill the monitor and the Wine server
trap 'kill $XVFB_PID 2>/dev/null || true; wineserver -k 2>/dev/null || true' EXIT

# Stop! Wait a minute. Here's my cup, put some liquor in it. Cause we gotta wait for the monitor to start
for i in $(seq 1 30); do
    if xdpyinfo -display :99 >/dev/null 2>&1; then break; fi
    sleep 0.1
done

# This be arg handling.
cmd="${1:-help}"

# Slide to the left.
shift || true

# Ok the good stuff.
case "$cmd" in
    scan|engine)
        # Forawrd everything to scan.sh.
        exec /scripts/scan.sh "$@"
        ;;
    selftest)
        # EICAR is the litmus. Engine detects it => the whole direct-engine path works.
        eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        printf '%s' "$eicar" > /tmp/eicar.com
        if [[ $(wc -c < /tmp/eicar.com) -ne 68 ]]; then
            echo '[selftest] invalid EICAR sample length' >&2
            exit 1
        fi
        set +e
        MPSCAN_EXPECT_EICAR=1 /scripts/scan.sh /tmp/eicar.com
        rc=$?
        set -e
        if [[ $rc -eq 1 ]]; then
            echo "[selftest] PASS — EICAR name and detection flag observed"
            exit 0
        fi
        echo "[selftest] FAIL — mpscan exit $rc (expected 1 = detection)" >&2
        exit 1
        ;;
    shell)
        # Drop to a bash prompt and run the command if provided
        if [[ $# -gt 0 ]]; then exec bash -c "$*"; else exec /bin/bash; fi
        ;;
    wine)
    # Let us run raw Wine commands so I can debug.
        exec wine "$@"
        ;;
    mpcmdrun)
        # Ladies and Gentlemen this is the MAIN EVENT!
        # First we jump into the Defender Platform
        cd "$WINEPREFIX/drive_c/defender/Platform"/* 2>/dev/null || true

        # Defender's design: MpCmdRun is a CLI client that talks to MsMpEng via LRPC pipe IMpService<GUID>.
        # Without MsMpEng running, MpCmdRun gets a NULL RPC handle and crashes. Start MsMpEng in the background, give it a moment to register its LRPC interface, then run MpCmdRun.
        SHIMS='C:\shims\wdfilter_shim.dll;C:\shims\etw_stub.dll'
        echo "[entry] starting MsMpEng.exe in background..."
        WINEDEBUG="${WINEDEBUG:--all},+rpcrt4" wine 'C:\shims\loader.exe' "$SHIMS" -- MsMpEng.exe >/tmp/msmpeng.stdout 2>/tmp/msmpeng.stderr & MSMPENG_PID=$!

        # Wait for our shim to log "invoking ServiceMain" proves MsMpEng survived driver init and the SCM bypass fired. Then give RPC endpoint registration time to settle.
        for i in $(seq 1 40); do
            kill -0 $MSMPENG_PID 2>/dev/null || { echo "[entry] MsMpEng died during startup" >&2; break; }
            grep -q 'invoking ServiceMain' /tmp/msmpeng.stderr 2>/dev/null && break
            sleep 0.5
        done
        sleep 3

        # Disable -e for the launch + teardown so a MpCmdRun crash doesn't prevent us from dumping MsMpEng's output.
        set +e
        echo "[entry] launching MpCmdRun.exe (with 30s timeout)..."

        # Timeout because Wine's winedbg hangs on crash, and we don't want the container to lock up. SIGKILL after 5s if SIGTERM doesn't take.
        timeout --kill-after=5 30 wine 'C:\shims\loader.exe' "$SHIMS" -- MpCmdRun.exe "$@"
        EXIT_CODE=$?

        # Nuke everything wine-related. Don't "wait" on children, winedbg and various wine workers don't respect signals reliably and we block forever otherwise. 
        # Just SIGKILL widely, sleep briefly, and proceed to the diagnostic dump regardless.
        pkill -9 -f winedbg 2>/dev/null || true
        pkill -9 -f MsMpEng 2>/dev/null || true
        pkill -9 -f MpCmdRun 2>/dev/null || true
        pkill -9 -f loader.exe 2>/dev/null || true
        kill -9 $MSMPENG_PID 2>/dev/null || true
        wineserver -k 2>/dev/null || true
        sleep 1

        # ALWAYS surface MsMpEng output. Dump first AND last chunks so we see init phase (StartServiceCtrlDispatcher, ServiceMain, mpengineload, RPC registration) AND steady-state.
        echo >&2
        echo "=== MsMpEng stdout (size=$(stat -c %s /tmp/msmpeng.stdout 2>/dev/null || echo 0)) ===" >&2
        head -n 30 /tmp/msmpeng.stdout >&2 2>/dev/null
        echo >&2
        SIZE=$(stat -c %s /tmp/msmpeng.stderr 2>/dev/null || echo 0)
        echo "=== MsMpEng stderr (size=$SIZE, first 200 non-cert) ===" >&2
        grep -v 'HKEY..[0-9A-F]\{40\}' /tmp/msmpeng.stderr 2>/dev/null | head -n 200 >&2
        echo >&2
        echo "=== MsMpEng stderr (last 60 non-cert) ===" >&2
        grep -v 'HKEY..[0-9A-F]\{40\}' /tmp/msmpeng.stderr 2>/dev/null | tail -n 60 >&2
        echo >&2
        echo "=== Service/RPC/mpengine/WdDevice related lines ===" >&2
        grep -iE 'ServiceMain|StartService|dispatch|mpengine|RpcServer|RpcUserQuota|WdDevice|WdFilter|fake handle|FAILED.*pipe' /tmp/msmpeng.stderr 2>/dev/null | head -n 50 >&2
        echo "=== end MsMpEng diagnostic ===" >&2

        exit $EXIT_CODE
        ;;
    --help|help|-h)
        cat <<EOF
defender-wine — Defender static scan in Wine

Usage:
  scan <path>             Scan <path> by driving mpengine.dll directly
  selftest                Scan an EICAR sample; exits 0 only if detected
  mpcmdrun <args...>      Legacy MsMpEng+MpCmdRun path (blocked on Wine ALPC)
  wine <cmd...>           Raw wine invocation (debugging)
  shell                   Bash shell inside the container

Env:
  WINEDEBUG=fixme+all     verbose Wine logs
  WDSHIM_LOG=1            log every shim hit to stderr
EOF
        ;;
    *)
        echo "unknown command: $cmd" >&2
        exit 2
        ;;
esac
