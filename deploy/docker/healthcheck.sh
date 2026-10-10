#!/bin/sh
# SPDX-License-Identifier: MIT

# Keep the image health probe strict. Native TLS deployments can use a private
# CA and resolve the certificate hostname to the loopback listener without
# weakening certificate or hostname verification.
set -eu

url=${MDM_HEALTHCHECK_URL:-http://127.0.0.1:8080/health}
ca=${MDM_HEALTHCHECK_CA:-}
resolve=${MDM_HEALTHCHECK_RESOLVE:-}

case "$url" in
    http://*|https://*) ;;
    *) exit 2 ;;
esac

set -- curl --fail --silent --show-error --max-time 3
if [ -n "$ca" ]; then
    set -- "$@" --cacert "$ca"
fi
if [ -n "$resolve" ]; then
    set -- "$@" --resolve "$resolve"
fi
exec "$@" "$url"
