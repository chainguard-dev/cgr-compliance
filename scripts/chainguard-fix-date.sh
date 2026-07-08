#!/bin/bash
#
# chainguard-fix-date.sh - print the build date of a Chainguard apk package
#
# Usage:   chainguard-fix-date.sh <pkg_name> <pkg_version>
# Example: 
# ./chainguard-fix-date.sh libexpat1 2.8.2-r0
# 2026-06-25
#
# Requires chainctl (logged in via 'chainctl auth login') for auth to apk.cgr.dev.

cgr_repo="https://apk.cgr.dev/chainguard"
wolfi_repo="https://packages.wolfi.dev/os"
pkg_arch="x86_64"

if [[ $# -ne 2 ]]; then
    echo "Usage: $(basename "$0") <pkg_name> <pkg_version>" >&2
    exit 2
fi

pkg_name="$1"
pkg_version="$2"

if ! command -v chainctl >/dev/null; then
    echo "ERROR: chainctl is required but not found in PATH" >&2
    exit 1
fi

# 1) Chainguard repo (authenticated via chainctl)
url="${cgr_repo%/}/${pkg_arch}/${pkg_name}-${pkg_version}.apk"
apk_token=$(chainctl auth token --audience apk.cgr.dev)

builddateraw=$(curl -sL --user "user:$apk_token" "$url" | tar -Oxz .PKGINFO 2>/dev/null | awk -F' = ' '/^builddate/ {print $2}')

# 2) Check Wolfi repo (public) if the Chainguard repo returned a 404
if [[ -z "$builddateraw" ]]; then
    http_code=$(curl -o /dev/null -sL --user "user:$apk_token" -w '%{http_code}' "$url")
    if [[ "$http_code" == "404" ]]; then
        url="${wolfi_repo%/}/${pkg_arch}/${pkg_name}-${pkg_version}.apk"
        builddateraw=$(curl -sL "$url" | tar -Oxz .PKGINFO 2>/dev/null | awk -F' = ' '/^builddate/ {print $2}')
    fi
fi

if [[ -z "$builddateraw" ]]; then
    echo "ERROR: could not get builddate for ${pkg_name}-${pkg_version} from $url" >&2
    exit 1
fi

date -u -d @"$builddateraw" +%Y-%m-%d
