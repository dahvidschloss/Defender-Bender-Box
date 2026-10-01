# Defender Bender Box

Defender Bender Box is a local research tool for red teamers, penetration testers, students, and security researchers who want to see whether a file produces an **offline Microsoft Defender detection** and, when it does, what threat name the engine reports. It runs the x64 Defender scan engine inside a Linux Docker container through Wine. The submitted file is mounted read-only and **read, not launched**.

This is a prototype for studying static file-scan alerts, not a replacement for Microsoft Defender. A scan with no reported detection is currently **unverified**, not a clean bill of health.

This project will be part of a larger project to be release later.

## What works today

- Boots the pinned `mpengine.dll` with its VDM definition files and requests a file scan through `__rsignal`.
- Reports scan counts, callback flags, and a candidate threat name when the engine raises a detection callback.
- Runs each scan in a disposable Docker container with a read-only sample mount and `--network none`.
- Saves the full smoke log and a shorter console report on Linux or Windows.
- Passes the EICAR selftest with the reduced five-file platform bundle. An earlier Kali test also returned a named detection for a separate sample.

## Requirements

- An x64 host capable of running Linux Docker containers. On Windows, use Docker Desktop in Linux-container mode; on Linux, use Docker Engine.
- Bash and Python 3 for the Linux host runner, or PowerShell for the Windows host runner.
- A matching x64 Defender engine and definition set in `binaries/Platform/4.18.25010.11-0/`:

| File | Purpose |
|---|---|
| `mpengine.dll` | Scan engine |
| `mpasbase.vdm`, `mpasdlta.vdm` | Antispyware definitions |
| `mpavbase.vdm`, `mpavdlta.vdm` | Antivirus definitions |

The current registry and harness are pinned to this platform version. Keep the engine and definitions together; compatibility with newer releases has not been established.

## Scan a file

! BEFORE ANYTHING !!! GitHub does not include `mpasbase.vdm` or `mpavbase.vdm` because the file exceeds its size limit. Copy your `mpasbase.vdm` and `mpavbase.vdm` from `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{RANDOM-UUID}\` into `binaries/Platform/4.18.25010.11-0/` before building the Docker image. Use the definition set that matches the other VDM files and `mpengine.dll` in that folder.

Start Docker, then run one command from the project directory. If the `defender-wine` image is missing, the runner asks whether to build it. Answering yes streams the Docker build output to the console, saves a build log, and scans only after the build succeeds. An existing image is used immediately.

**Linux**

```bash
bash scripts/run_scan_linux.sh /absolute/path/to/sample.exe
```

**Windows PowerShell**

```powershell
.\scripts\run_scan_win.ps1 -SamplePath 'C:\path\to\sample.exe'
```

The Linux runner uses your Docker access or falls back to `sudo docker`. The Windows runner makes a temporary local copy before mounting the file, which also supports samples on mapped drives. It removes that copy after the scan.

Full output is saved as `smoke-linux-N.log` or `smoke-win-N.log`. The console report is also saved as `report-linux-N.log` or `report-win-N.log`. If a build was needed, its output is saved as `build-linux-N.log` or `build-win-N.log`.

### Interpreting the result

| Scan exit code | Meaning |
|---|---|
| `1` | The engine raised a detection callback. The report includes the candidate name and flag when available. |
| `7` | `UNVERIFIED`: no detection was reported through the callback path currently understood. This is **not** a clean verdict. |
| Other nonzero code | Setup, engine, file-read, scan, or Docker error. Check the full smoke log. |

Callback flags are internal scan state, not outbound connections. The report prints the observed hex value, but the complete flag layout has not been validated. `SCANSTRUCT` is a raw diagnostic dump; fields beyond the threat name are still under investigation.

## Run the selftest

The selftest creates an EICAR test file **inside** the container and succeeds only when the engine reads it and reports the EICAR detection. On Windows, this command rebuilds the image and writes `buildNN.log` and `smokeNN.log`:

```powershell
.\scripts\run_smoke.ps1
```

To use the existing image on Windows, run `.\scripts\run_smoke.ps1 -SkipBuild` in PowerShell. On Linux:

```bash
docker build -t defender-wine .
docker run --rm --network none defender-wine selftest
```

For the selftest, Docker exit code `0` means the expected EICAR detection was observed. For a normal file scan, exit code `1` means a detection was reported.

## How it works

```text
Host file -> read-only Docker mount -> Wine -> mpscan.exe -> mpengine.dll + VDMs
                                                  |
                                                  +-> read and scan callbacks -> report
```

The first approach tried to start `MsMpEng.exe` and scan through `MpCmdRun.exe`. In our Wine traces, that service path could not establish the ALPC-backed local RPC endpoint it needed. The current harness instead loads `mpengine.dll` directly, calls its `__rsignal` boot operation, supplies the file through read callbacks, and requests a stream scan. The file is never executed by the harness.

A small loader starts the harness suspended, loads targeted WdFilter and ETW compatibility shims, then resumes it. The Docker build prepares the Wine prefix and registry entries before scanning. This x64 Wine implementation draws on the direct-engine research and structure definitions in [Tavis Ormandy's loadlibrary project](https://github.com/taviso/loadlibrary), which uses a different Linux loading approach.

## Limitations

- **Offline file scanning only.** There is no Defender cloud lookup, real-time monitoring, behavioral detonation, OS protection, or automatic remediation.
- **No validated clean verdict.** A missing detection callback produces `UNVERIFIED`; do not use it to declare a file safe.
- **Pinned engine and definitions.** Definition updates and compatibility with other platform versions are not automated or validated.
- **One file at a time.** The harness loads the whole target into memory, so large-file handling needs more work.
- **Research isolation, not an execution sandbox.** Docker and Wine are used to run the scanner; submitted files are not executed. Treat untrusted files and scan logs as untrusted input.

The next steps are to validate the no-detection path, test matched engine and definition updates, and expose structured results to a local front end.
