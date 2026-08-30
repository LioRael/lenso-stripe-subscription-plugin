#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
package_flags=(--locked)
plugin_package_flags=()
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-stripe-packages.XXXXXX")"

cleanup() {
  if [[ "${LENSO_KEEP_PACKAGE_TMP:-0}" == "1" ]]; then
    printf 'kept package verification root: %s\n' "$verification_root" >&2
  else
    rm -r "$verification_root"
  fi
}
trap cleanup EXIT

if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
  plugin_package_flags+=(--allow-dirty)
fi

for capability in \
  lenso-capability-stripe-subscription \
  lenso-capability-stripe-subscription-admin; do
  "$cargo_bin" package --quiet "${package_flags[@]}" -p "$capability"
done

metadata="$("$cargo_bin" metadata --no-deps --format-version=1)"
target_directory="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$metadata")"
subscription_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-stripe-subscription <<<"$metadata")"
admin_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-stripe-subscription-admin <<<"$metadata")"
plugin_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-stripe-subscription-plugin <<<"$metadata")"

subscription_source="$repository_root/crates/lenso-capability-stripe-subscription"
admin_source="$repository_root/crates/lenso-capability-stripe-subscription-admin"
entitlements_source="${LENSO_ENTITLEMENTS_SOURCE:-}"
if [[ -z "$entitlements_source" ]]; then
  entitlements_checkout="$verification_root/entitlements"
  git clone --quiet --filter=blob:none --no-checkout \
    https://github.com/LioRael/lenso-entitlements-plugin "$entitlements_checkout"
  git -C "$entitlements_checkout" checkout --quiet --detach \
    bc953a0c6de9aefe5489f7c7e3ef2d215cc25c13
  entitlements_source="$entitlements_checkout/crates/lenso-capability-entitlements-admin"
fi
entitlements_root="$(git -C "$entitlements_source" rev-parse --show-toplevel)"
entitlements_metadata="$("$cargo_bin" metadata --manifest-path "$entitlements_root/Cargo.toml" --no-deps --format-version=1)"
entitlements_target="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$entitlements_metadata")"
entitlements_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-entitlements-admin <<<"$entitlements_metadata")"
"$cargo_bin" package --quiet --locked \
  --manifest-path "$entitlements_root/Cargo.toml" \
  -p lenso-capability-entitlements-admin

subscription_source_patch="patch.crates-io.lenso-capability-stripe-subscription.path=\"$subscription_source\""
admin_source_patch="patch.crates-io.lenso-capability-stripe-subscription-admin.path=\"$admin_source\""
entitlements_source_patch="patch.crates-io.lenso-capability-entitlements-admin.path=\"$entitlements_source\""

# Build the archive with every not-yet-published Capability supplied explicitly.
# Verification happens below against only the normalized archive contents.
"$cargo_bin" \
  --config "$subscription_source_patch" \
  --config "$admin_source_patch" \
  --config "$entitlements_source_patch" \
  package --quiet --offline "${plugin_package_flags[@]}" --no-verify \
  -p lenso-stripe-subscription-plugin

subscription_archive="$target_directory/package/lenso-capability-stripe-subscription-$subscription_version.crate"
admin_archive="$target_directory/package/lenso-capability-stripe-subscription-admin-$admin_version.crate"
entitlements_archive="$entitlements_target/package/lenso-capability-entitlements-admin-$entitlements_version.crate"
plugin_archive="$target_directory/package/lenso-stripe-subscription-plugin-$plugin_version.crate"

tar -xzf "$subscription_archive" -C "$verification_root"
tar -xzf "$admin_archive" -C "$verification_root"
tar -xzf "$entitlements_archive" -C "$verification_root"
tar -xzf "$plugin_archive" -C "$verification_root"

subscription_package="$verification_root/lenso-capability-stripe-subscription-$subscription_version"
admin_package="$verification_root/lenso-capability-stripe-subscription-admin-$admin_version"
entitlements_package="$verification_root/lenso-capability-entitlements-admin-$entitlements_version"
plugin_package="$verification_root/lenso-stripe-subscription-plugin-$plugin_version"

[[ -f "$subscription_package/Cargo.toml" ]]
[[ -f "$admin_package/Cargo.toml" ]]
[[ -f "$entitlements_package/Cargo.toml" ]]
[[ -f "$plugin_package/Cargo.toml" ]]

subscription_package_patch="patch.crates-io.lenso-capability-stripe-subscription.path=\"$subscription_package\""
admin_package_patch="patch.crates-io.lenso-capability-stripe-subscription-admin.path=\"$admin_package\""
entitlements_package_patch="patch.crates-io.lenso-capability-entitlements-admin.path=\"$entitlements_package\""
plugin_manifest="$plugin_package/Cargo.toml"

"$cargo_bin" \
  --config "$subscription_package_patch" \
  --config "$admin_package_patch" \
  --config "$entitlements_package_patch" \
  generate-lockfile --manifest-path "$plugin_manifest"
"$cargo_bin" \
  --config "$subscription_package_patch" \
  --config "$admin_package_patch" \
  --config "$entitlements_package_patch" \
  check --quiet --locked --all-targets --manifest-path "$plugin_manifest"
"$cargo_bin" \
  --config "$subscription_package_patch" \
  --config "$admin_package_patch" \
  --config "$entitlements_package_patch" \
  test --quiet --locked --manifest-path "$plugin_manifest"
"$cargo_bin" clippy \
  --config "$subscription_package_patch" \
  --config "$admin_package_patch" \
  --config "$entitlements_package_patch" \
  --quiet --locked --all-targets --manifest-path "$plugin_manifest" -- -D warnings
