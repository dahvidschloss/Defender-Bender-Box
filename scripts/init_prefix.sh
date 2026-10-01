#!/bin/bash

# Building and init Wine prefix  for all those registries
set -euo pipefail

# Env esetup
export WINEPREFIX=/wine
export WINEARCH=win64
export WINEDEBUG=-all
export DISPLAY=:99

# Build the headless display so we don't crash Wine
Xvfb :99 -screen 0 1024x768x24 &
XVFB_PID=$!
trap 'kill $XVFB_PID 2>/dev/null || true' EXIT

# Slow down there cowboy, we gotta wait for the fake display to start
for i in $(seq 1 30); do
    if xdpyinfo -display :99 >/dev/null 2>&1; then break; fi
    sleep 0.1
done

# This is the bootstrap, we are creating the skeleton of a C drive and Reg Hives
wineboot --init
wineserver -w || true

# Copy all our WinDef files into our fake C drive
mkdir -p "$WINEPREFIX/drive_c/defender"
cp -r /defender/* "$WINEPREFIX/drive_c/defender/" 2>/dev/null || true

# Now we need to mirror System32 as some Win apps are little pricks and look for program strictly in Program Files or System32. 
# You know why they do this, but its still a pain

PF_DEF="$WINEPREFIX/drive_c/Program Files/Windows Defender"
SYS32="$WINEPREFIX/drive_c/windows/system32"
if [[ -d /defender/ProgramFiles ]]; then
    mkdir -p "$PF_DEF"
    cp -r /defender/ProgramFiles/* "$PF_DEF/"
    # Grab all the DLLs and copy them into our fake Win32 folder
    find /defender/ProgramFiles -maxdepth 2 -name '*.dll' -exec cp -n {} "$SYS32/" \;
fi

# Since this is an AV with virus defs aka VDMs we need to create the ProgramData folders and fake some GUIDs
DEF_GUID="{6956D4E6-F3F2-4977-B859-F60BC5731E6A}"
DEF_ROOT="$WINEPREFIX/drive_c/ProgramData/Microsoft/Windows Defender"
mkdir -p "$DEF_ROOT/Definition Updates/$DEF_GUID"
mkdir -p "$DEF_ROOT/Definition Updates/Default"
mkdir -p "$DEF_ROOT/Definition Updates/Backup"
mkdir -p "$DEF_ROOT/Platform"

# Now we find all our VDMs and seed them into the location that WinDef engine will check
plat_dir=$(ls -d "$WINEPREFIX/drive_c/defender/Platform"/*/ 2>/dev/null | head -n1)
if [[ -n "$plat_dir" ]]; then
    for vdm in "$plat_dir"/*.vdm; do
        [[ -e "$vdm" ]] || continue
        cp "$vdm" "$DEF_ROOT/Definition Updates/$DEF_GUID/"
        cp "$vdm" "$DEF_ROOT/Definition Updates/Default/"
        cp "$vdm" "$DEF_ROOT/Definition Updates/Backup/"
    done
    # Also mirror the Platform layout under ProgramData.
    cp -r "$plat_dir" "$DEF_ROOT/Platform/"
fi


# So this one is a fucked nightmare. No way around it and if we don't have it we are fucked. On 64-bit Windows there are two registries.
# If you didn't know that its 64-bit and Wow6432Node aka Windows on Windows 64 bit, 32bit Node. Since WinDef is 64-Bit like everyother things fucking modern we have to force the registry into the 64-bit Hive.
import_reg() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    echo "[init] importing $file (64-bit view)..."
    WINEARCH=win64 wine 'C:\windows\regedit.exe' /S "$file"
    wineserver -w || true
}

# Now we gonna verify that they landed in the 64b section and not redirected to the 32B node.
import_reg /init/registry/windef_full.reg
import_reg /init/registry/defender_offline.reg

# Wine 9.x's regedit is 32-bit only, imports always land in Wow6432Node regardless of WINEARCH=win64. 
# Fix it after the fact: stop wineserver, mirror Wow6432Node sections to the 64-bit view, restart.

echo "[init] mirroring Wow6432Node sections to 64-bit view..."
wineserver -k || true
sleep 1

python3 /scripts/mirror_wow64.py /wine/system.reg 'Software\\Wow6432Node\\Microsoft\\Windows Defender' 'Software\\Wow6432Node\\Microsoft\\Windows Advanced Threat Protection' 'Software\\Wow6432Node\\Microsoft\\Cryptography' 'Software\\Wow6432Node\\Microsoft\\AMSI'

echo "[init] verifying registry layout..."
SIXTY_FOUR=$(grep -cE '^\[Software\\\\Microsoft\\\\Windows Defender' /wine/system.reg 2>/dev/null || echo 0)
WOW=$(grep -cE '^\[Software\\\\Wow6432Node\\\\Microsoft\\\\Windows Defender' /wine/system.reg 2>/dev/null || echo 0)
echo "[init]   64-bit view sections: $SIXTY_FOUR"
echo "[init]   Wow6432Node sections: $WOW"

if [[ "$SIXTY_FOUR" -lt 5 ]]; then
    echo "[init] WARNING: 64-bit view still empty after mirror"
fi


# Now lets put the custom loader and shims inside the C drive and finalize the staging. 
mkdir -p "$WINEPREFIX/drive_c/shims"
cp /shims/*.dll /shims/loader.exe "$WINEPREFIX/drive_c/shims/"

# Create Defender support/log directory (MsMpEng writes MPLog, MPDetection, MPScanSkip here)
mkdir -p "$WINEPREFIX/drive_c/defender/Support"

# Placeholder driver files so MsMpEng's driver-presence checks don't return NOT_FOUND
mkdir -p "$WINEPREFIX/drive_c/windows/system32/drivers"
touch "$WINEPREFIX/drive_c/windows/system32/drivers/WdFilter.sys"
touch "$WINEPREFIX/drive_c/windows/system32/drivers/WdNisDrv.sys"

echo "[init] Wine prefix ready at $WINEPREFIX"
