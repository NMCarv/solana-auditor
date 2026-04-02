#!/usr/bin/env bash
# install.sh — Install the Solana Auditor skill for Claude Code, Opencode, or other compatible tools
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

REPO_URL="https://github.com/NMCarv/solana-auditor"
SKILL_NAME="solana-auditor"

# ── Detect source ──────────────────────────────────────────────────────────────
# If running from a cloned repo, use local files. Otherwise, clone from GitHub.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/SKILL.md" ]]; then
    SOURCE_DIR="$SCRIPT_DIR"
    info "Installing from local directory: $SOURCE_DIR"
else
    SOURCE_DIR=$(mktemp -d)
    trap 'rm -rf "$SOURCE_DIR"' EXIT
    log "Cloning $REPO_URL..."
    if ! git clone --depth 1 "$REPO_URL" "$SOURCE_DIR" 2>/dev/null; then
        err "Failed to clone repository. Check your network connection."
        exit 1
    fi
fi

# ── Detect target tool ────────────────────────────────────────────────────────

detect_tool() {
    if command -v claude &> /dev/null; then
        echo "claude-code"
    elif command -v opencode &> /dev/null; then
        echo "opencode"
    else
        echo "unknown"
    fi
}

TOOL="${1:-$(detect_tool)}"

echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Solana Auditor — Skill Installer${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""

# ── Install for Claude Code ───────────────────────────────────────────────────

install_claude_code() {
    local SKILLS_DIR="$HOME/.claude/skills"
    local DEST="$SKILLS_DIR/$SKILL_NAME"

    log "Installing for Claude Code..."

    mkdir -p "$DEST"

    # Copy skill files
    cp "$SOURCE_DIR/SKILL.md" "$DEST/SKILL.md"
    cp -r "$SOURCE_DIR/references" "$DEST/references"
    cp -r "$SOURCE_DIR/assets" "$DEST/assets"
    cp -r "$SOURCE_DIR/scripts" "$DEST/scripts"
    chmod +x "$DEST/scripts/"*.sh 2>/dev/null || true

    log "Installed to $DEST"
    echo ""
    info "Usage: open Claude Code and ask it to audit a Solana program."
    info "The skill triggers automatically on Solana security-related prompts."
    echo ""
    info "Examples:"
    echo "  - \"Audit this Anchor program for vulnerabilities\""
    echo "  - \"Is this Solana program safe?\" (paste code)"
    echo "  - \"Review the security of program <ADDRESS>\""
}

# ── Install for Opencode ──────────────────────────────────────────────────────

install_opencode() {
    local SKILLS_DIR="$HOME/.opencode/skills"
    local DEST="$SKILLS_DIR/$SKILL_NAME"

    log "Installing for Opencode..."

    mkdir -p "$DEST"

    cp "$SOURCE_DIR/SKILL.md" "$DEST/SKILL.md"
    cp -r "$SOURCE_DIR/references" "$DEST/references"
    cp -r "$SOURCE_DIR/assets" "$DEST/assets"
    cp -r "$SOURCE_DIR/scripts" "$DEST/scripts"
    chmod +x "$DEST/scripts/"*.sh 2>/dev/null || true

    log "Installed to $DEST"
    echo ""
    info "Usage: open Opencode and ask it to audit a Solana program."
}

# ── Generic / manual install ──────────────────────────────────────────────────

install_generic() {
    local DEST="${2:-$HOME/.claude/skills/$SKILL_NAME}"

    warn "Could not auto-detect Claude Code or Opencode."
    echo ""
    echo "Options:"
    echo "  1) Install to Claude Code default path (~/.claude/skills/)"
    echo "  2) Install to Opencode default path (~/.opencode/skills/)"
    echo "  3) Install to a custom path"
    echo "  4) Cancel"
    echo ""
    read -rp "Choice [1-4]: " choice

    case "$choice" in
        1) install_claude_code ;;
        2) install_opencode ;;
        3)
            read -rp "Enter destination path: " custom_path
            mkdir -p "$custom_path"
            cp "$SOURCE_DIR/SKILL.md" "$custom_path/SKILL.md"
            cp -r "$SOURCE_DIR/references" "$custom_path/references"
            cp -r "$SOURCE_DIR/assets" "$custom_path/assets"
            cp -r "$SOURCE_DIR/scripts" "$custom_path/scripts"
            chmod +x "$custom_path/scripts/"*.sh 2>/dev/null || true
            log "Installed to $custom_path"
            ;;
        4) echo "Cancelled."; exit 0 ;;
        *) err "Invalid choice."; exit 1 ;;
    esac
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

case "$TOOL" in
    claude-code|claude) install_claude_code ;;
    opencode)           install_opencode ;;
    *)                  install_generic ;;
esac

echo ""
echo -e "${GREEN}Done.${NC} Run ${CYAN}scripts/setup-audit-env.sh${NC} inside a Solana project to set up the audit toolchain."
echo ""
