#!/bin/sh
set -eu

repository=https://github.com/Mondrethos/vyx
work=
temporary=
cleanup() {
    [ -z "$temporary" ] || rm -f "$temporary"
    [ -z "$work" ] || rm -rf "$work"
}
trap cleanup 0
trap 'exit 1' 1 2 15
fail() { printf 'vyx: %s\n' "$*" >&2; exit 1; }
fetch() {
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 180 --max-filesize "$3" \
        "$1" --output "$2"
}

case "${1-}" in
    -h|--help)
        printf '%s\n' \
            'Usage: install.sh [NATIVE_BINARY]' \
            'Installs the latest verified Linux/macOS release into ${PREFIX:-$HOME/.local}/bin.' \
            'VYX_VERSION=vX.Y.Z selects a specific release. An explicit binary installs a local build.' \
            'If needed, the installer adds the bin directory to your shell startup configuration.'
        exit 0
        ;;
esac
[ "$#" -le 1 ] || fail 'Usage: install.sh [NATIVE_BINARY]'

if [ "$#" -eq 1 ]; then
    binary=$1
else
    command -v curl >/dev/null 2>&1 || fail 'curl is required'
    case "$(uname -s):$(uname -m)" in
        Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-musl ;;
        Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl ;;
        Darwin:x86_64) target=x86_64-apple-darwin ;;
        Darwin:arm64) target=aarch64-apple-darwin ;;
        *) fail 'Supported platforms: Linux and macOS on x86_64 or ARM64' ;;
    esac
    tag=${VYX_VERSION:-latest}
    if [ "$tag" = latest ]; then
        latest_url=$(curl --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 10 --max-time 30 --output /dev/null \
            --write-out '%{url_effective}' "$repository/releases/latest")
        case "$latest_url" in
            "$repository/releases/tag/"*) tag=${latest_url##*/} ;;
            *) fail 'Cannot resolve the latest release' ;;
        esac
    fi
    printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        || fail 'VYX_VERSION must be a stable release tag such as v0.1.0'
    asset=vyx-$target
    work=$(mktemp -d "${TMPDIR:-/tmp}/vyx-install.XXXXXX")
    release=$repository/releases/download/$tag
    printf 'Downloading vyx %s for %s...\n' "$tag" "$target"
    fetch "$release/SHA256SUMS" "$work/SHA256SUMS" 65536
    expected=$(LC_ALL=C awk -v asset="$asset" '
        $2 == asset { count++; hash = $1; if (NF != 2) bad = 1 }
        END {
            if (bad || count != 1 || length(hash) != 64 || hash ~ /[^0-9a-f]/) exit 1
            print hash
        }
    ' "$work/SHA256SUMS") || fail 'Missing or invalid release checksum'
    binary=$work/$asset
    fetch "$release/$asset" "$binary" 134217728
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$binary")
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$binary")
    else
        fail 'sha256sum or shasum is required to verify the download'
    fi
    actual=${actual%% *}
    [ "$actual" = "$expected" ] || fail 'Checksum mismatch; the existing installation was not changed'
    chmod 755 "$binary"
fi

[ -f "$binary" ] && [ -x "$binary" ] || fail "Not an executable file: $binary"
version=$("$binary" --version) || fail 'The binary cannot run on this operating system'
case "$version" in 'vyx '*) ;; *) fail 'The supplied binary is not vyx' ;; esac
if [ "$#" -eq 0 ]; then
    [ "$version" = "vyx ${tag#v}" ] || fail 'The downloaded binary does not match the release version'
fi

bin_dir=${PREFIX:-"$HOME/.local"}/bin
case "$bin_dir" in
    /*) ;;
    *) bin_dir=$(pwd)/$bin_dir ;;
esac
case "$bin_dir" in *'
'*) fail 'The installation path must not contain a newline' ;; esac
mkdir -p "$bin_dir"
destination=$bin_dir/vyx
[ ! -d "$destination" ] || fail "Cannot replace a directory: $destination"
temporary=$(mktemp "$bin_dir/.vyx-install.XXXXXX")
install -m 755 "$binary" "$temporary"
mv -f "$temporary" "$destination"
temporary=
printf 'Installed %s at %s\n' "$version" "$destination"

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *)
        escaped=$(printf '%s' "$bin_dir" | sed 's/[\\$"`]/\\&/g')
        login_shell=${SHELL:-sh}
        login_shell=${login_shell##*/}
        login_rc=
        case "$login_shell" in
            fish)
                rc=${XDG_CONFIG_HOME:-"$HOME/.config"}/fish/conf.d/vyx.fish
                mkdir -p "$(dirname "$rc")"
                line="fish_add_path \"$escaped\""
                ;;
            zsh) rc=${ZDOTDIR:-"$HOME"}/.zshrc; line="export PATH=\"$escaped:\$PATH\"" ;;
            bash)
                rc=$HOME/.bashrc
                line="export PATH=\"$escaped:\$PATH\""
                if [ -f "$HOME/.bash_profile" ]; then
                    login_rc=$HOME/.bash_profile
                elif [ -f "$HOME/.bash_login" ]; then
                    login_rc=$HOME/.bash_login
                else
                    login_rc=$HOME/.profile
                fi
                ;;
            *) rc=$HOME/.profile; line="export PATH=\"$escaped:\$PATH\"" ;;
        esac
        for startup in "$rc" "$login_rc"; do
            [ -n "$startup" ] || continue
            mkdir -p "$(dirname "$startup")"
            if ! { [ -f "$startup" ] && grep -Fqx "$line" "$startup"; }; then
                printf '\n# vyx\n%s\n' "$line" >> "$startup"
            fi
            printf 'Added vyx to %s. Open a new terminal to use the vyx command.\n' "$startup"
        done
        ;;
esac
printf '%s\n' 'Run vyx to start or reattach. Ctrl+B then d detaches; Ctrl+B then q quits.' 'Run vyx update to install future releases.'
