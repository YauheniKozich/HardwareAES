#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GENERATED_PROJECT=$(mktemp -d "${TMPDIR:-/tmp}/hardwareaes-simulator-tests.XXXXXX")
trap 'rm -rf "$GENERATED_PROJECT"' EXIT HUP INT TERM

HAES_PACKAGE_PATH="$REPO_ROOT" xcodegen generate \
    --spec "$REPO_ROOT/SimulatorTests/project.yml" \
    --project "$GENERATED_PROJECT"
xcodebuild \
    -project "$GENERATED_PROJECT/HardwareAESSimulatorTests.xcodeproj" \
    -scheme HardwareAESSimulatorTests \
    -destination "${SIMULATOR_DESTINATION:-platform=iOS Simulator,name=iPhone 17,OS=latest}" \
    test
