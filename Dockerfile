# Defender static-scan in Wine
# Base: Debian bookworm slim, Wine stable, mingw toolchain to build the shims.
FROM debian:bookworm-slim AS shim-builde

RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 make ca-certificates git && rm -rf /var/lib/apt/lists/*

# Build the WdFilter shim, ETW stub, and the generic loader
WORKDIR /build
COPY stubs/  /build/stubs/
COPY loader/ /build/loader/
COPY mpscan/ /build/mpscan/
RUN make -C /build/stubs/wdfilter_shim && make -C /build/stubs/etw_stub && make -C /build/loader && make -C /build/mpscan

# -------- Runtime stage --------
FROM debian:bookworm-sli

ENV DEBIAN_FRONTEND=noninteractive WINEDEBUG=-all WINEPREFIX=/wine WINEARCH=win64

# Wine stable + 32-bit helper + minimal X stack
RUN dpkg --add-architecture i386  && apt-get update && apt-get install -y --no-install-recommends  wine wine64 wine32:i386 libwine:i386 winbind cabextract xvfb xauth x11-utils ca-certificates procps less python3 && rm -rf /var/lib/apt/lists/*

# Bring shims and loader over from builder
COPY --from=shim-builder /build/stubs/wdfilter_shim/wdfilter_shim.dll /shims/wdfilter_shim.dll
COPY --from=shim-builder /build/stubs/etw_stub/etw_stub.dll /shims/etw_stub.dll
COPY --from=shim-builder /build/loader/loader.exe /shims/loader.exe

# Direct-scan engine and definitions baked into the image.
# /defender/Platform/<ver>/ contains mpengine.dll and four VDM files.
COPY binaries/ /defender/

# Registry tweaks for offline-only operation
COPY registry/ /init/registry/

COPY scripts/init_prefix.sh scripts/mirror_wow64.py /scripts/
RUN chmod +x /scripts/init_prefix.sh

# Initialize Wine prefix and import registry at build time so first run is fast
RUN /scripts/init_prefix.sh

# Keep runtime script and harness edits from repeating Wine prefix initialization.
COPY scripts/entrypoint.sh scripts/scan.sh /scripts/
RUN chmod +x /scripts/entrypoint.sh /scripts/scan.sh
COPY --from=shim-builder /build/mpscan/mpscan.exe /shims/mpscan.exe
COPY --from=shim-builder /build/mpscan/mpscan.exe /wine/drive_c/shims/mpscan.exe

ENTRYPOINT ["/scripts/entrypoint.sh"]
CMD ["--help"]
