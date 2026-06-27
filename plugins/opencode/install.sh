#!/usr/bin/env bash
set -euo pipefail

REPO="Daviey/sondera-coding-agent-hooks"
REPO_URL="https://github.com/${REPO}"
BIN_NAME="sondera-opencode-adapter"
PLUGIN_NAME="sondera-bundled.ts"

DEFAULT_BIN_DIR="${HOME}/.local/bin"
DEFAULT_PLUGIN_DIR="${HOME}/.config/opencode/plugins"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[info]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${NC}  %s\n" "$*"; }
error() { printf "${RED}[error]${NC} %s\n" "$*" >&2; }

need() {
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "'$cmd' is required but not found in PATH."
            exit 1
        fi
    done
}

detect_target() {
    local arch os target
    arch="$(uname -m)"
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "${arch}-${os}" in
        x86_64-linux)  target="x86_64-unknown-linux-gnu" ;;
        aarch64-linux) target="aarch64-unknown-linux-gnu" ;;
        x86_64-darwin) target="x86_64-apple-darwin" ;;
        arm64-darwin)  target="aarch64-apple-darwin" ;;
        *)
            error "Unsupported platform: ${arch}-${os}"
            error "Supported: x86_64-linux, aarch64-linux, x86_64-darwin, arm64-darwin"
            exit 1
            ;;
    esac
    echo "${target}"
}

latest_tag() {
    local tag
    tag="$(curl -sL -o /dev/null -w '%{url_effective}' "${REPO_URL}/releases/latest" | sed 's|.*/tag/||')"
    if [ "${tag}" = "${REPO_URL}/releases/latest" ] || [ -z "${tag}" ]; then
        error "Could not determine latest release tag."
        error "Check ${REPO_URL}/releases"
        exit 1
    fi
    echo "${tag}"
}

download_with_fallback() {
    local url="$1" dest="$2" description="$3"
    local tmp

    tmp="$(mktemp)"

    info "Downloading ${description}..."
    info "  URL: ${url}"

    if curl -fSL --retry 3 --retry-delay 2 -o "${tmp}" "${url}" 2>/dev/null; then
        : # success
    elif curl -fSL -o "${tmp}" "${url}" 2>/dev/null; then
        : # success without retries
    else
        rm -f "${tmp}"
        error "Failed to download ${description}."
        return 1
    fi

    if [ ! -s "${tmp}" ]; then
        rm -f "${tmp}"
        error "Downloaded file is empty (${description})."
        return 1
    fi

    if grep -q "Not Found" "${tmp}" 2>/dev/null; then
        rm -f "${tmp}"
        error "Download returned 'Not Found' - the release asset does not exist (${description})."
        return 1
    fi

    cp "${tmp}" "${dest}"
    rm -f "${tmp}"
    info "  Saved to ${dest}"
    return 0
}

validate_binary() {
    local file="$1"
    local mime
    mime="$(file -b --mime-type "${file}" 2>/dev/null || echo "unknown")"

    case "${mime}" in
        application/x-executable|application/x-pie-executable|application/x-sharedlib|application/x-mach-binary)
            info "Binary validated (${mime})."
            return 0
            ;;
        application/octet-stream)
            info "Binary downloaded (octet-stream - assuming valid)."
            return 0
            ;;
        text/*|inode/x-empty)
            error "Downloaded file is text, not a binary. Got: ${mime}"
            head -c 200 "${file}" >&2
            echo "" >&2
            return 1
            ;;
        *)
            warn "Unexpected file type: ${mime}. Proceeding anyway."
            return 0
            ;;
    esac
}

validate_plugin() {
    local file="$1"
    if head -c 1 "${file}" | grep -q '<'; then
        error "Plugin file looks like HTML, not TypeScript."
        head -c 200 "${file}" >&2
        echo "" >&2
        return 1
    fi
    info "Plugin file validated."
    return 0
}

main() {
    need curl

    local target tag bin_dir plugin_dir
    bin_dir="${1:-${DEFAULT_BIN_DIR}}"
    plugin_dir="${2:-${DEFAULT_PLUGIN_DIR}}"

    target="$(detect_target)"
    info "Detected platform: ${target}"

    tag="$(latest_tag)"
    info "Latest release: ${tag}"

    local download_url="${REPO_URL}/releases/download/${tag}/${BIN_NAME}-${target}"

    mkdir -p "${bin_dir}" "${plugin_dir}"

    local adapter="${bin_dir}/${BIN_NAME}"

    if download_with_fallback "${download_url}" "${adapter}" "adapter binary for ${target}"; then
        if validate_binary "${adapter}"; then
            chmod +x "${adapter}"
            info "Adapter installed: ${adapter}"
        else
            warn "Binary validation failed. Cleaning up."
            rm -f "${adapter}"
            error "The release binary for ${target} may not exist in ${tag}."
            error "Check ${REPO_URL}/releases/tag/${tag} for available assets."
            error "You may need to build from source - see the README."
            exit 1
        fi
    else
        error "Could not download adapter binary."
        error "Check ${REPO_URL}/releases/tag/${tag} for available assets."
        error "You may need to build from source - see the README."
        exit 1
    fi

    local plugin="${plugin_dir}/sondera.ts"
    local plugin_url="${REPO_URL}/releases/download/${tag}/${PLUGIN_NAME}"

    if download_with_fallback "${plugin_url}" "${plugin}" "plugin file"; then
        if validate_plugin "${plugin}"; then
            info "Plugin installed: ${plugin}"
        else
            rm -f "${plugin}"
            warn "Plugin download failed. You can manually download ${PLUGIN_NAME} from the release."
        fi
    else
        warn "Could not download plugin file. You can manually download ${PLUGIN_NAME} from the release."
    fi

    echo ""
    info "Install complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Ensure '${bin_dir}' is on your PATH."
    echo "  2. Start the Sondera harness server."
    echo "  3. Verify: ${adapter} health"
    echo "  4. Run: opencode"
    echo ""
    echo "To configure Cedar policies, see: ${REPO_URL}#custom-policies"
}

main "$@"
