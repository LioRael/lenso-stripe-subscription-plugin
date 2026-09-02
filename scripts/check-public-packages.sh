#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
package_flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
fi

for package in \
  lenso-capability-stripe-subscription \
  lenso-capability-stripe-subscription-admin \
  lenso-stripe-subscription-plugin; do
  "$cargo_bin" package "${package_flags[@]}" -p "$package"
done
