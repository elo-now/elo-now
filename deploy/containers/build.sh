#!/bin/sh
# Build local images from an allowlisted source context. No images are published.
set -eu
umask 077
if [ "$#" -ne 2 ]; then
  printf '%s\n' 'Usage: sh deploy/containers/build.sh VERSION api|witness|all' >&2
  exit 2
fi
version=$1
role=$2
case "$version" in ''|*[!A-Za-z0-9_.-]*) printf '%s\n' 'Invalid version tag.' >&2; exit 2;; esac
case "$role" in api) targets='api wake calls';; witness) targets='witness storage storage-mega';; all) targets='api witness storage wake calls storage-mega';; *) exit 2;; esac
case "${ELO_BUILD_NETWORK:-default}" in default|host|none) ;; *) printf '%s\n' 'Invalid build network.' >&2; exit 2;; esac
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
python3 "$script_dir/bundle.py" --output "$scratch/source"
for target in $targets; do
  docker build --file "$scratch/source/deploy/containers/Dockerfile" --target "$target" \
    --network "${ELO_BUILD_NETWORK:-default}" \
    --build-arg "ELO_VERSION=$version" \
    --build-arg "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}" \
    --build-arg "RUST_IMAGE=${RUST_IMAGE:-rust:1.98.1-trixie}" \
    --build-arg "RUNTIME_IMAGE=${RUNTIME_IMAGE:-debian:13-slim}" \
    --tag "elo-$target:$version" "$scratch/source"
done
