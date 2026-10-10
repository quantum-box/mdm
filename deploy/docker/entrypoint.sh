#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

# Do not enable shell tracing here. This process handles bearer tokens and
# private keys, and values must never be written to logs or command arguments.
umask 077

die() {
    echo "mdmd-entrypoint: $*" >&2
    exit 1
}

secret_dir=${MDM_SECRET_DIR:-/run/mdmsecrets}
if [ -L "$secret_dir" ] || { [ -e "$secret_dir" ] && [ ! -d "$secret_dir" ]; }; then
    die "secret directory is not a directory: $secret_dir"
fi
mkdir -p "$secret_dir" || die "cannot create secret directory"
chmod 700 "$secret_dir" || die "cannot protect secret directory"

# Copy a mounted secret to a private, process-local path. Docker/Kubernetes
# secret mounts are commonly 0444; the origin itself reads only this copy.
# Reject symlinks so a provider cannot silently redirect a configured secret.
copy_secret() {
    source=$1
    name=$2
    max_bytes=$3
    description=$4

    [ -n "$source" ] || die "$description path is empty"
    [ -e "$source" ] || die "$description does not exist"
    [ -f "$source" ] || die "$description is not a regular file"
    [ ! -L "$source" ] || die "$description must not be a symlink"

    size=$(wc -c < "$source") || die "cannot read $description size"
    case "$size" in
        ''|*[!0-9]*) die "invalid $description size" ;;
    esac
    [ "$size" -le "$max_bytes" ] || die "$description exceeds its size limit"

    temporary=$(mktemp "$secret_dir/.${name}.XXXXXX") || die "cannot create private $description copy"
    chmod 600 "$temporary" || { rm -f "$temporary"; die "cannot protect $description copy"; }
    if ! cat "$source" > "$temporary"; then
        rm -f "$temporary"
        die "cannot copy $description"
    fi
    chmod 600 "$temporary" || { rm -f "$temporary"; die "cannot protect $description copy"; }
    destination="$secret_dir/$name"
    mv -f "$temporary" "$destination" || { rm -f "$temporary"; die "cannot install $description copy"; }
    printf '%s\n' "$destination"
}

copy_optional_file() {
    source=$1
    name=$2
    max_bytes=$3
    description=$4
    if [ -n "$source" ]; then
        copy_secret "$source" "$name" "$max_bytes" "$description"
    fi
}

# Explicit subcommands such as `init-ca`, `backup`, and `restore` are kept
# available without requiring server-only settings. They do not auto-create a
# CA or start the server.
if [ "${1:-serve}" != "serve" ]; then
    exec /usr/local/bin/mdmd "$@"
fi
if [ "$#" -gt 0 ]; then
    shift
fi

# These names are provider-neutral. The MDM_* aliases match the existing
# binary's environment conventions; the short names are convenient for
# Compose, Kubernetes, and other runtimes.
database=${MDM_DATABASE:-${DATABASE:-/data/mdm.sqlite}}
bind=${MDM_BIND:-${BIND:-127.0.0.1:8080}}
public_url=${MDM_PUBLIC_URL:?MDM_PUBLIC_URL is required}
bootstrap_url=${MDM_BOOTSTRAP_URL:-${BOOTSTRAP_URL:-}}
topic=${MDM_TOPIC:-${TOPIC:?MDM_TOPIC or TOPIC is required}}
organization=${MDM_ORGANIZATION:-${ORGANIZATION:-MDM}}
trust_proxy=${MDM_TRUST_PROXY:-${TRUST_PROXY:-false}}

ca_cert_source=${MDM_CA_CERT:-${CA_CERT:-/run/secrets/ca.pem}}
ca_key_source=${MDM_CA_KEY:-${CA_KEY:-/run/secrets/ca-key.pem}}
ca_cert=$(copy_secret "$ca_cert_source" ca-cert.pem 1048576 "SCEP CA certificate")
ca_key=$(copy_secret "$ca_key_source" ca-key.pem 1048576 "SCEP CA private key")

tls_cert_source=${MDM_TLS_CERT:-${TLS_CERT:-}}
tls_key_source=${MDM_TLS_KEY:-${TLS_KEY:-}}
tls_cert=$(copy_optional_file "$tls_cert_source" tls-cert.pem 1048576 "HTTPS certificate")
tls_key=$(copy_optional_file "$tls_key_source" tls-key.pem 1048576 "HTTPS private key")
if [ -n "$tls_cert_source" ] && [ -z "$tls_key_source" ]; then
    die "TLS certificate and key must be configured together"
fi
if [ -z "$tls_cert_source" ] && [ -n "$tls_key_source" ]; then
    die "TLS certificate and key must be configured together"
fi

apns_source=${MDM_APNS_IDENTITY:-${APNS_IDENTITY:-}}
apns_identity=$(copy_optional_file "$apns_source" apns.pem 2097152 "APNs identity")

# The two token file aliases are intentionally file based. If a deployment
# injects a token directly as an environment secret, the existing MDM_* value
# is passed through without ever appearing in this script's arguments.
admin_token_file=${MDM_ADMIN_TOKEN_FILE:-${ADMIN_TOKEN_FILE:-}}
read_token_file=${MDM_READ_TOKEN_FILE:-${READ_TOKEN_FILE:-}}
if [ -n "$admin_token_file" ]; then
    admin_token_copy=$(copy_secret "$admin_token_file" admin-token 4096 "admin token")
    MDM_ADMIN_TOKEN=$(cat "$admin_token_copy") || die "cannot read admin token"
    export MDM_ADMIN_TOKEN
fi
if [ -n "$read_token_file" ]; then
    read_token_copy=$(copy_secret "$read_token_file" read-token 4096 "read token")
    MDM_READ_TOKEN=$(cat "$read_token_copy") || die "cannot read read-only token"
    export MDM_READ_TOKEN
fi

# The Rust gateway-HMAC adapter consumes this path when enabled. Older mdmd
# binaries ignore the variable, so deployments must not mistake copying the
# key for enabling gateway authentication.
gateway_key_file=${MDM_GATEWAY_KEY_FILE:-${GATEWAY_KEY_FILE:-}}
if [ -n "$gateway_key_file" ]; then
    gateway_key_copy=$(copy_secret "$gateway_key_file" gateway-key 4096 "gateway signing key")
    export MDM_GATEWAY_KEY_FILE="$gateway_key_copy"
fi

# ADE and Apps & Books files are optional but follow the same private-copy
# policy. They retain the environment names consumed by mdmd.
ade_token_file=$(copy_optional_file "${MDM_ADE_TOKEN_FILE:-}" ade-token 2097152 "ADE server token")
ade_provider_cert_file=$(copy_optional_file "${MDM_ADE_PROVIDER_CERT_FILE:-}" ade-provider-cert.pem 1048576 "ADE provider certificate")
ade_provider_key_file=$(copy_optional_file "${MDM_ADE_PROVIDER_KEY_FILE:-}" ade-provider-key.pem 1048576 "ADE provider private key")
ade_device_ca_file=$(copy_optional_file "${MDM_ADE_DEVICE_CA_FILE:-}" ade-device-ca.pem 262144 "Apple device CA bundle")
vpp_token_file=$(copy_optional_file "${MDM_VPP_TOKEN_FILE:-}" vpp-token 2097152 "Apps & Books token")
[ -z "$ade_token_file" ] || export MDM_ADE_TOKEN_FILE="$ade_token_file"
[ -z "$ade_provider_cert_file" ] || export MDM_ADE_PROVIDER_CERT_FILE="$ade_provider_cert_file"
[ -z "$ade_provider_key_file" ] || export MDM_ADE_PROVIDER_KEY_FILE="$ade_provider_key_file"
[ -z "$ade_device_ca_file" ] || export MDM_ADE_DEVICE_CA_FILE="$ade_device_ca_file"
[ -z "$vpp_token_file" ] || export MDM_VPP_TOKEN_FILE="$vpp_token_file"

# `"$@"` is expanded before `set --` replaces the positional parameters, so
# caller-supplied mdmd flags remain available after the provider-neutral flags.
set -- serve \
    --database "$database" \
    --bind "$bind" \
    --public-url "$public_url" \
    --topic "$topic" \
    --organization "$organization" \
    --ca-cert "$ca_cert" \
    --ca-key "$ca_key" \
    "$@"

if [ -n "$bootstrap_url" ]; then
    set -- "$@" --bootstrap-url "$bootstrap_url"
fi

if [ -n "$apns_identity" ]; then
    set -- "$@" --apns-identity "$apns_identity"
fi
if [ -n "$tls_cert" ]; then
    set -- "$@" --tls-cert "$tls_cert" --tls-key "$tls_key"
fi
case "$trust_proxy" in
    1|true|TRUE|yes|YES) set -- "$@" --trust-proxy ;;
    0|false|FALSE|no|NO|'') ;;
    *) die "MDM_TRUST_PROXY must be true or false" ;;
esac

# Extra server flags are appended only after all provider-neutral settings.
exec /usr/local/bin/mdmd "$@"
