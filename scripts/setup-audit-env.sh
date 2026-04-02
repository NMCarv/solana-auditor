#!/usr/bin/env bash
# setup-audit-env.sh — Bootstrap the Solana audit toolchain
# Run from the project directory or any workspace

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[x]${NC} $1"; }

check_tool() {
    if command -v "$1" &> /dev/null; then
        local version=$($1 --version 2>&1 | head -1)
        log "$1 found: $version"
        return 0
    else
        warn "$1 not found"
        return 1
    fi
}

echo "========================================="
echo "  Solana Audit Environment Setup"
echo "========================================="
echo ""

# 1. Core tools
log "Checking core tools..."

check_tool "rustc" || {
    err "Rust not installed. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
}

check_tool "solana" || {
    warn "Solana CLI not installed. See https://docs.solanalabs.com/cli/install for installation instructions."
}

check_tool "anchor" || {
    warn "Anchor not installed. Install via: cargo install --git https://github.com/coral-xyz/anchor avm --force && avm install latest && avm use latest"
}

# 2. Audit-specific tools
log "Checking audit tools..."

check_tool "cargo-audit" || {
    log "Installing cargo-audit..."
    cargo install cargo-audit 2>/dev/null || warn "Failed to install cargo-audit"
}

# 3. Fuzzing tools
log "Checking fuzzing tools..."

if cargo install --list 2>/dev/null | grep -q "trident-cli"; then
    log "trident-cli found"
else
    warn "trident-cli not found. Install via: cargo install trident-cli"
fi

if cargo install --list 2>/dev/null | grep -q "cargo-fuzz"; then
    log "cargo-fuzz found"
else
    warn "cargo-fuzz not found. Install via: cargo install cargo-fuzz"
fi

# 4. Check Solana configuration
log "Checking Solana config..."
if command -v solana &> /dev/null; then
    CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $3}')
    log "Current cluster: $CLUSTER"

    if [[ "$CLUSTER" == *"mainnet"* ]]; then
        warn "Connected to MAINNET. Switch to devnet for testing:"
        warn "  solana config set --url devnet"
    fi
fi

# 5. Create workspace structure
WORKSPACE="audit-workspace"
if [[ ! -d "$WORKSPACE" ]]; then
    log "Creating audit workspace..."
    mkdir -p "$WORKSPACE"/{source,findings,tests,reports,poc}
    log "Workspace created at ./$WORKSPACE/"
else
    log "Workspace already exists at ./$WORKSPACE/"
fi

# 6. Check if we're in an Anchor project
if [[ -f "Anchor.toml" ]]; then
    log "Anchor project detected"

    # Try to build
    log "Attempting anchor build..."
    if anchor build 2>&1 | tee "$WORKSPACE/build-log.txt"; then
        log "Build succeeded"

        # Check for warnings
        WARNINGS=$(grep -c "warning" "$WORKSPACE/build-log.txt" 2>/dev/null || echo 0)
        if [[ "$WARNINGS" -gt 0 ]]; then
            warn "$WARNINGS build warnings detected — review $WORKSPACE/build-log.txt"
        fi
    else
        err "Build failed — review $WORKSPACE/build-log.txt"
    fi

    # Run cargo audit
    if command -v cargo-audit &> /dev/null; then
        log "Running cargo audit..."
        cargo audit 2>&1 | tee "$WORKSPACE/cargo-audit.txt" || true
    fi
fi

echo ""
echo "========================================="
echo "  Setup complete"
echo "========================================="
echo ""
echo "Workspace: ./$WORKSPACE/"
echo ""
echo "Next steps:"
echo "  1. Review build warnings:  cat $WORKSPACE/build-log.txt | grep warning"
echo "  2. Review dependency audit: cat $WORKSPACE/cargo-audit.txt"
echo "  3. Begin reconnaissance:    grep -rn '#[derive(Accounts)]' programs/*/src/"
echo ""
