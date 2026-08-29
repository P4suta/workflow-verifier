#!/usr/bin/env bash
set -euo pipefail

: "${CANDIDATE_COMMIT:?CANDIDATE_COMMIT is required}"
: "${CANDIDATE_PLATFORM:?CANDIDATE_PLATFORM is required}"
: "${CANDIDATE_VERSION:?CANDIDATE_VERSION is required}"
: "${CANDIDATE_OUTPUT:?CANDIDATE_OUTPUT is required}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

if [[ ! $CANDIDATE_COMMIT =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'candidate commit must be exact lowercase 40-hex' >&2
  exit 2
fi

case "$CANDIDATE_PLATFORM" in
  linux-x86_64 | linux-arm64)
    archive_suffix=.tar.gz
    cargo_packages=(
      -p workflow-verifier-linux-helper
      -p workflow-verifier-oci-helper
      -p workflow-verifier-vm-agent
    )
    helper_names=(
      workflow-verifier-linux-helper
      workflow-verifier-oci-helper
      workflow-verifier-vm-agent
    )
    ;;
  windows-x86_64)
    archive_suffix=.zip
    cargo_packages=(
      -p workflow-verifier-windows-helper
      -p workflow-verifier-vm-agent
    )
    helper_names=(
      workflow-verifier-windows-helper.exe
      workflow-verifier-vm-agent.exe
    )
    ;;
  macos-arm64 | macos-x86_64)
    archive_suffix=.tar.gz
    cargo_packages=(
      -p workflow-verifier-macos-helper
      -p workflow-verifier-vm-agent
    )
    helper_names=(
      workflow-verifier-macos-helper
      workflow-verifier-vm-agent
      workflow-verifier-vm-shim
    )
    ;;
  *)
    printf 'unsupported candidate platform: %s\n' "$CANDIDATE_PLATFORM" >&2
    exit 2
    ;;
esac
cargo_packages=(-p workflow-verifier "${cargo_packages[@]}")
analyzer_name=workflow-verifier
if [[ $CANDIDATE_PLATFORM == windows-x86_64 ]]; then
  analyzer_name=workflow-verifier.exe
fi

task_temp=$RUNNER_TEMP
if command -v cygpath >/dev/null 2>&1; then
  task_temp=$(cygpath -u "$RUNNER_TEMP")
fi
candidate_root=$(mktemp -d "$task_temp/workflow-verifier-candidate.XXXXXX")
first_root="$candidate_root/first"
second_root="$candidate_root/second"
mkdir -p "$first_root" "$second_root" "$CANDIDATE_OUTPUT"

repository=$(pwd -P)
git_command=(git -c "safe.directory=$repository")
actual_commit=$("${git_command[@]}" rev-parse HEAD)
if [[ $actual_commit != "$CANDIDATE_COMMIT" ]]; then
  printf 'checked-out commit %s does not equal candidate %s\n' \
    "$actual_commit" "$CANDIDATE_COMMIT" >&2
  exit 2
fi
"${git_command[@]}" archive \
  --format=tar \
  --output="$candidate_root/source.tar" \
  "$CANDIDATE_COMMIT"
tar -xf "$candidate_root/source.tar" -C "$first_root"
tar -xf "$candidate_root/source.tar" -C "$second_root"

product_name="workflow-verifier-$CANDIDATE_VERSION-$CANDIDATE_PLATFORM$archive_suffix"
helpers_name="workflow-verifier-helpers-$CANDIDATE_VERSION-$CANDIDATE_PLATFORM$archive_suffix"
if [[ $CANDIDATE_PLATFORM == windows-x86_64 ]]; then
  product_name=windows-unsigned-payload.zip
  helpers_name=windows-unsigned-helpers.zip
fi

build_one() {
  local source_root=$1
  local output_root=$2
  local native_root prefix_map rust_flags

  native_root=$(python -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$source_root")
  prefix_map=$(python -B scripts/candidate_artifacts.py prefix-map "$native_root")
  rust_flags="--remap-path-prefix=$native_root=."
  if [[ $CANDIDATE_PLATFORM == windows-x86_64 ]]; then
    rust_flags+=$'\x1f-Clink-arg=/Brepro'
  fi

  (
    cd "$source_root"
    export BUILD_PATH_PREFIX_MAP=$prefix_map
    export CARGO_ENCODED_RUSTFLAGS=$rust_flags
    export DUNE_CACHE=disabled
    export SOURCE_DATE_EPOCH
    export TZ=UTC
    export WORKFLOW_VERIFIER_SOURCE_COMMIT=$CANDIDATE_COMMIT
    opam exec -- dune build --profile release @install
    cargo build \
      --locked \
      --release \
      --target-dir _candidate-target \
      "${cargo_packages[@]}"
  )

  if [[ $CANDIDATE_PLATFORM == macos-* ]]; then
    WORKFLOW_VERIFIER_CODESIGN_IDENTITY=- \
      sh "$source_root/helpers/macos/build-shim.sh" \
      "$source_root/_candidate-target/release/workflow-verifier-vm-shim"
    codesign --force --sign - --timestamp=none \
      --identifier dev.workflow-verifier.cli --options runtime \
      "$source_root/_candidate-target/release/$analyzer_name"
    codesign --force --sign - --timestamp=none \
      --identifier dev.workflow-verifier.macos-helper --options runtime \
      "$source_root/_candidate-target/release/workflow-verifier-macos-helper"
    codesign --force --sign - --timestamp=none \
      --identifier dev.workflow-verifier.vm-agent --options runtime \
      "$source_root/_candidate-target/release/workflow-verifier-vm-agent"
    codesign --verify --strict --verbose=2 \
      "$source_root/_candidate-target/release/$analyzer_name"
    codesign --verify --strict --verbose=2 \
      "$source_root/_candidate-target/release/workflow-verifier-macos-helper"
    codesign --verify --strict --verbose=2 \
      "$source_root/_candidate-target/release/workflow-verifier-vm-agent"
  fi

  local helper_arguments=()
  local helper
  for helper in "${helper_names[@]}"; do
    helper_arguments+=(
      --helper "bin/$helper=$source_root/_candidate-target/release/$helper"
    )
  done
  python -B scripts/candidate_artifacts.py package-install \
    --workspace-root "$source_root" \
    --install-root "$source_root/_build/install/default" \
    --analyzer "$source_root/_candidate-target/release/$analyzer_name" \
    --platform "$CANDIDATE_PLATFORM" \
    --version "$CANDIDATE_VERSION" \
    "${helper_arguments[@]}" \
    --output "$output_root/$product_name" \
    --helpers-output "$output_root/$helpers_name"

  if [[ $CANDIDATE_PLATFORM == linux-* ]]; then
    python -B scripts/verify_linux_compat.py \
      "$source_root/_candidate-target/release/$analyzer_name" \
      "$source_root/_candidate-target/release/workflow-verifier-linux-helper" \
      "$source_root/_candidate-target/release/workflow-verifier-oci-helper" \
      "$source_root/_candidate-target/release/workflow-verifier-vm-agent"
  fi
}

mkdir -p "$candidate_root/first-output" "$candidate_root/second-output"
build_one "$first_root" "$candidate_root/first-output"
build_one "$second_root" "$candidate_root/second-output"

fragment="$CANDIDATE_OUTPUT/reproducibility-$CANDIDATE_PLATFORM.json"
python -B scripts/candidate_artifacts.py record \
  --platform "$CANDIDATE_PLATFORM" \
  --subject-commit "$CANDIDATE_COMMIT" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --artifact "product=$candidate_root/first-output/$product_name=$candidate_root/second-output/$product_name" \
  --artifact "helper=$candidate_root/first-output/$helpers_name=$candidate_root/second-output/$helpers_name" \
  --output "$fragment"
cp "$candidate_root/first-output/$product_name" "$CANDIDATE_OUTPUT/$product_name"
cp "$candidate_root/first-output/$helpers_name" "$CANDIDATE_OUTPUT/$helpers_name"

printf 'candidate platform: %s; two clean builds are byte-identical\n' "$CANDIDATE_PLATFORM"
