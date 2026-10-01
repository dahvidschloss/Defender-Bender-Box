#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: scan_report.py <smoke-log> [docker-exit-code]", file=sys.stderr)
        return 2

    lines = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines()
    logged_codes = [match.group(1) for line in lines if (match := re.search(r"\[smoke\] docker exit_code: (\d+)", line))]
    docker_code = sys.argv[2] if len(sys.argv) == 3 else (logged_codes[-1] if logged_codes else "unknown")

    platform = next((match.group(1) for line in lines if (match := re.search(r"\[scan\] platform: .*?/Platform/([^/]+)/", line))),"unknown",)
    print(f"[mpscan] WinDef Platform: {platform}")

    summaries = [
        match
        for line in lines
        if (match := re.search(r"\[mpscan\] scan summary: reads=(\d+) bytes=(\d+) callbacks=(\d+) candidates=(\d+)", line,))
    ]
    if summaries:
        reads, size, callbacks, candidates = summaries[-1].groups()
        print(f"[mpscan] scan summary: reads={reads} bytes={size} callbacks={callbacks} candidates={candidates}")
    else:
        print("[mpscan] scan summary: unavailable; see full smoke log")

    status = next(
        (
            line for line in reversed(lines)
            if line.startswith("[mpscan] DETECTION_REPORTED:")
            or line.startswith("[mpscan] EICAR_CONFIRMED:")
            or line.startswith("[mpscan] UNVERIFIED:")
        ),
        None,
    )
    if status:
        print(status)
    else:
        print("[mpscan] detection status unavailable; see full smoke log")

    for line in lines:
        match = re.search(r'\[mpscan\] detection candidate: name="([^"]*)" flags=(0x[0-9a-fA-F]+)', line)
        if match:
            print(f"[Detection] Candidate Name: {json.dumps(match.group(1), ensure_ascii=False)}")
            print(f"[Detection] Flag: {match.group(2)}")

    for index, line in enumerate(lines):
        if line.startswith("[mpscan] SCANSTRUCT"):
            print("[Detection] SCANSTRUCT")
            for dump_line in lines[index + 1:]:
                if not re.match(r"^\s+[0-9a-fA-F]{4}\s{2}", dump_line):
                    break
                print(dump_line)
            break

    scan_codes = [match.group(1) for line in lines if (match := re.search(r"\[scan\] exit_code: (\d+)", line))]
    if scan_codes:
        print(f"[scan] Scan completed, returned {scan_codes[-1]}")
    else:
        print("[scan] Scan did not complete; see full smoke log")
    print(f"[smoke] Docker run completed, returned {docker_code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
