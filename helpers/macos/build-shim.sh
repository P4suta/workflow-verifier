#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$script_directory/../../target/release/workflow-verifier-vm-shim"}
identity=${WORKFLOW_VERIFIER_CODESIGN_IDENTITY:--}

mkdir -p "$(dirname -- "$output")"
swiftc \
  -O \
  -swift-version 5 \
  -framework CryptoKit \
  -framework Virtualization \
  "$script_directory/shim/WorkflowVerifierVm.swift" \
  -o "$output"
codesign \
  --force \
  --sign "$identity" \
  --options runtime \
  --entitlements "$script_directory/shim/WorkflowVerifierVm.entitlements" \
  "$output"
codesign --verify --strict --verbose=2 "$output"
