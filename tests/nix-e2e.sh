#!/usr/bin/env bash
# End-to-end test against real Nix, inside a privileged nixos/nix container:
# builds the flake's package, evaluates agentSandboxes with the Nix library, and runs
# sandboxes as root and as a dedicated agent user. Needs docker and network access.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# The volume keeps the store between runs; the first run downloads a toolchain.
exec docker run --rm --privileged \
  -v "$ROOT":/src \
  -v agentbox-nix-test:/nix \
  -e HOST_OWNER="$(id -u):$(id -g)" \
  nixos/nix sh /src/tests/nix-e2e-inner.sh
