#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

set -e
shopt -s extglob

cd "$(dirname "${BASH_SOURCE[0]}")"
readonly BIN=$(pwd)/target/release

# Check for required commands
check_prereq() {
  local cmd="$1"
  if ! command -v "$cmd" &> /dev/null; then
    echo -e "\033[0;31m❌ Error: '$cmd' is required but not installed or not in PATH.\033[0m" >&2
    missing=true
  fi
}

check_pip_pkg() {
  local pkg="$1"
  if ! python -c "import $pkg" &>/dev/null; then
    echo -e "\033[0;31m❌ Error: Python package '$pkg' is not installed.\033[0m" >&2
    missing=true
  fi
}

echo "🔍 Checking prerequisites..."
check_prereq node
check_prereq npm
check_prereq python
check_prereq circom
check_prereq rustc
check_prereq cargo
check_prereq ssh
check_pip_pkg jwcrypto
check_pip_pkg cbor2

# halt if any prerequisites are missing
if [ "${missing:-false}" = true ]; then
  echo -e "\033[0;31m❌ Some prerequisites are missing. See circuit_setup\README.md for help with dependencies.\033[0m" >&2
  exit 1
fi


RELEASE_FLAG="--release"
SECONDS=0

# Check for "trim" argument to have script clean extraneous artifacts
do_trim=false; for arg in "$@"; do [[ "$arg" == "trim" ]] && do_trim=true && break; done


git submodule update --init --recursive

# Build all subproject to ./target/release
cargo build $RELEASE_FLAG --features print-trace

# Circuit setup
# Generates circom circuits and artifacts in circuit_setup/generated_files/
# Final output is copied to creds/test-vectors/[mdl1, rs256, rs256-sd, rs256-db]
# The setup scripts are run in parallel for each circuit type to take advantage of multiple CPU cores
#   as circuit generation is CPU intensive but single-threaded.
# rm -rf circuit_setup/generated_files/!(README.md) creds/test-vectors/!(README.md)
pushd circuit_setup/scripts > /dev/null
./run_setup.sh mdl1 &
./run_setup.sh rs256 &
./run_setup.sh rs256-sd &
./run_setup.sh rs256-db &
wait
popd > /dev/null

# Ensure the output directories exist
pushd creds > /dev/null
for d in test-vectors/rs256 test-vectors/rs256-sd test-vectors/rs256-db test-vectors/mdl1; do
  if [ ! -d "$d" ]; then
    echo "❌ Error: Missing directory creds/$d" >&2
    exit 1
  fi
done

if [ "$do_trim" = true ]; then
  echo "Cleaning up intermediate artifacts..."
  rm -rf ../circuit_setup/generated_files/!(README.md)
fi


crescent="${BIN}/crescent-cli"

if [ "$do_trim" = true ]; then
  echo "Cleaning up build artifacts..."
  cargo clean
fi

declare -A LABEL_COLORS=(
  [rs256]=$'\033[0;35m'
  [rs256-sd]=$'\033[0;36m'
  [rs256-db]=$'\033[1;33m'
  [mdl1]=$'\033[1;34m'
)

RESET=$'\033[0m'

for name in "${!LABEL_COLORS[@]}"; do
  color="${LABEL_COLORS[$name]}"
  {
    $crescent zksetup --name "$name"
    $crescent prove   --name "$name"
    $crescent show    --name "$name"
    $crescent verify  --name "$name"
  } 2>&1 | sed "s/^/\\${color}[${name}]\\${RESET} /" &
done

wait

#
# Sample setup
#
../sample/setup-sample.sh

echo -e "\033[0;32mBuild-all completed in $SECONDS seconds\033[0m"
