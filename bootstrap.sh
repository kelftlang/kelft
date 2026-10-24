#!/bin/sh
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -s)" in Linux) platform=linux;; Darwin) platform=macos;; *) echo 'Unsupported native platform.' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) architecture=x86_64;; aarch64|arm64) architecture=arm64;; *) echo 'Unsupported native architecture.' >&2; exit 1;; esac
seed="$repository/bootstrap/$platform-$architecture"
if [ "$#" -eq 0 ]; then set -- help; fi
if [ ! -f "$seed/READY" ]; then
  echo "The $platform-$architecture seed is not ready for this workflow. See bootstrap/README.md." >&2
  exit 1
fi
starter=$(mktemp -d "${TMPDIR:-/tmp}/kelft-launch.XXXXXXXX")
trap 'rm -f "$starter/kelft"; rmdir "$starter"' EXIT
cp "$seed/bin/kelft" "$starter/kelft"
chmod 700 "$starter/kelft"
"$starter/kelft" bootstrap --package "$seed" -- "$@"
