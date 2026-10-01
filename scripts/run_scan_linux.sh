#!/usr/bin/env bash
# Scan one host file, building the image on request if it is missing.
set -uo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
    echo "usage: $0 <file-to-scan>" >&2
    exit 2
fi

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sample=$(realpath -- "$1") || exit 2

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required on the host" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to print the scan report" >&2
    exit 2
fi

docker_cmd=(docker)
if ! docker info >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    docker_cmd=(sudo docker)
fi
if ! "${docker_cmd[@]}" info >/dev/null 2>&1; then
    echo "cannot connect to Docker; start the daemon or check permissions" >&2
    exit 2
fi
sample_name=${sample##*/}
extension=${sample_name##*.}
if [[ "$extension" == "$sample_name" ]]; then
    extension=""
else
    extension=".$extension"
fi

number=1
while [[ -e "$project_root/smoke-linux-$number.log" || -e "$project_root/report-linux-$number.log" || -e "$project_root/build-linux-$number.log" ]]; do
    number=$((number + 1))
done
smoke_log="$project_root/smoke-linux-$number.log"
report_log="$project_root/report-linux-$number.log"
build_log="$project_root/build-linux-$number.log"
container_sample="/sample/input$extension"

if ! "${docker_cmd[@]}" image inspect defender-wine:latest >/dev/null 2>&1; then
    printf 'Image defender-wine is not built. Build it now? [y/N] '
    IFS= read -r answer || answer=''
    case "$answer" in
        y|Y|yes|YES|Yes) ;;
        *) echo 'Build declined; scan not started.'; exit 2 ;;
    esac
    printf 'Building image (details: %s)...\n' "$build_log"
    "${docker_cmd[@]}" build --progress plain -t defender-wine "$project_root" 2>&1 | tee "$build_log"
    build_code=${PIPESTATUS[0]}
    if [[ $build_code -ne 0 ]]; then
        printf 'Build failed (exit %s). Full build log: %s\n' "$build_code" "$build_log" >&2
        exit "$build_code"
    fi
fi

printf '[smoke] sample_sha256: %s\n' "$(sha256sum -- "$sample" | cut -d ' ' -f 1)" > "$smoke_log"
printf '[smoke] image: defender-wine\n' >> "$smoke_log"
printf 'Running scan inside Docker (details: %s)...\n' "$smoke_log"
docker_code=0
"${docker_cmd[@]}" run --rm --network none --pids-limit 256 --security-opt no-new-privileges --mount "type=bind,source=$sample,target=$container_sample,readonly" defender-wine scan "$container_sample" >> "$smoke_log" 2>&1 || docker_code=$?
printf '[smoke] docker exit_code: %s\n' "$docker_code" >> "$smoke_log"

if ! python3 "$project_root/scripts/scan_report.py" "$smoke_log" "$docker_code" | tee "$report_log"; then
    echo "Report generation failed; full smoke log remains at $smoke_log" >&2
    exit 8
fi
printf 'Full smoke log: %s\nReport: %s\n' "$smoke_log" "$report_log"
exit "$docker_code"
