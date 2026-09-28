#!/bin/sh
set -eu

RUNS=${1:-3}
case "$RUNS" in
    ''|*[!0-9]*) echo "usage: $0 [positive-run-count]" >&2; exit 2 ;;
esac
case "$RUNS" in
    *[1-9]*) ;;
    *) echo "usage: $0 [positive-run-count]" >&2; exit 2 ;;
esac

echo "=== Benchmark environment ==="
sw_vers
echo "Architecture: $(uname -m)"
echo "Model: $(sysctl -n hw.model)"
if sysctl -n machdep.cpu.brand_string 2>/dev/null; then :; else
    echo "SoC string: unavailable via machdep.cpu.brand_string"
fi
echo "Swift compiler:"
swift --version
echo "macOS SDK: $(xcrun --sdk macosx --show-sdk-version)"
echo "=== Release build and benchmark ==="
swift run -c release HardwareAESBenchmarkCLI --runs "$RUNS"
