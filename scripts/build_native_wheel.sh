#!/usr/bin/env bash
# Build one repaired native Linux wheel from prebuilt Core assets.
set -euo pipefail

case "$(uname -m)" in
  x86_64|aarch64)
    arch="$(uname -m)"
    ;;
  *)
    echo "unsupported native-wheel architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset_dir="${BLOCKSNOOP_NATIVE_ASSET_DIR:-$root/build/native-wheel/$arch/assets}"
raw_dir="$root/build/native-wheel/$arch/raw"
wheel_dir="${WHEEL_OUTPUT_DIR:-$root/dist}"

rm -rf "$asset_dir" "$raw_dir"
mkdir -p "$asset_dir" "$raw_dir" "$wheel_dir"

make -C "$root/native" OUT_DIR="$asset_dir"

export BLOCKSNOOP_NATIVE_WHEEL=1
export BLOCKSNOOP_NATIVE_ASSET_DIR="$asset_dir"
python -m pip wheel --no-deps --no-cache-dir --wheel-dir "$raw_dir" "$root"

raw_wheel="$(find "$raw_dir" -maxdepth 1 -name '*.whl' -print -quit)"
test -n "$raw_wheel"
case "$(basename "$raw_wheel")" in
  *-py3-none-linux_"$arch".whl) ;;
  *)
    echo "native build produced an unexpected wheel tag: $raw_wheel" >&2
    exit 1
    ;;
esac

auditwheel repair \
  --plat "manylinux_2_28_$arch" \
  --wheel-dir "$wheel_dir" \
  "$raw_wheel"
