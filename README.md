# Solana Auditor

A Claude Code skill that turns your AI assistant into a Solana smart contract security auditor. It systematically reviews Anchor and native Solana programs for vulnerabilities, generates proof-of-concept exploits, and produces structured audit reports.

## What it does

When you ask Claude Code to audit a Solana program, this skill activates and provides:

- **Structured audit workflow** — five phases from reconnaissance to report generation
- **Vulnerability taxonomy** — 25 vulnerability classes covering account validation, CPI safety, PDA security, Token-2022, integer math, oracle manipulation, and more
- **SVM runtime model** — deep reference on Solana's account model, CPI mechanics, and runtime constraints
- **Exploit case studies** — real-world exploits mapped to vulnerability classes
- **Testing and fuzzing** — harness templates for Trident, LiteSVM, Mollusk, and proptest
- **Report template** — standardized format with severity ratings, PoCs, and recommendations

## Installation

### Claude Code plugin (recommended)

```
/plugin install NMCarv/solana-auditor
```

### Quick install (script)

```bash
git clone https://github.com/NMCarv/solana-auditor.git
cd solana-auditor
./install.sh
```

The installer auto-detects Claude Code or Opencode and copies the skill to the right location.

### Manual install (Claude Code)

```bash
git clone https://github.com/NMCarv/solana-auditor.git
cp -r solana-auditor ~/.claude/skills/solana-auditor
```

### Manual install (Opencode)

```bash
git clone https://github.com/NMCarv/solana-auditor.git
cp -r solana-auditor ~/.opencode/skills/solana-auditor
```

### Other tools

Copy the skill folder to wherever your tool reads skill definitions from, or run `./install.sh` and choose a custom path.

## Usage

Once installed, the skill triggers automatically when you ask Claude Code about Solana security. Examples:

```
> Audit this Anchor program for vulnerabilities
> Is this Solana program safe? [paste code]
> Review the security of program <PROGRAM_ADDRESS>
> What are the common Solana exploit patterns?
> Fuzz this program's deposit instruction
```

### Audit environment setup

Inside a Solana project, you can bootstrap the audit toolchain:

```bash
~/.claude/skills/solana-auditor/scripts/setup-audit-env.sh
```

This checks for required tools (Rust, Solana CLI, Anchor, cargo-audit, Trident), verifies your Solana cluster config, and creates a workspace directory for findings.

## Skill contents

```
solana-auditor/
├── .claude-plugin/
│   └── plugin.json                   # Plugin metadata (name, version, author)
├── SKILL.md                          # Skill definition and workflow
├── references/
│   ├── cheatsheet.md                 # Condensed lookup table — read first
│   ├── audit-workflow.md             # Step-by-step audit procedure
│   ├── vulnerability-taxonomy.md     # 25 vulnerability classes with detection patterns
│   ├── svm-runtime-model.md          # SVM internals, accounts, CPI mechanics
│   ├── rust-solana-pitfalls.md       # Rust-specific edge cases in Solana
│   ├── crypto-primitives.md          # Ed25519, SHA-256, PDAs, ZK proofs
│   ├── exploit-case-studies.md       # Real exploits mapped to vuln classes
│   └── testing-fuzzing.md            # Trident, LiteSVM, Mollusk, proptest
├── assets/
│   └── audit-report-template.md      # Standardized report format
├── scripts/
│   ├── setup-audit-env.sh            # Toolchain bootstrapper
│   └── fuzz-harness-template.rs      # Trident fuzz harness template
└── install.sh                        # Installer script
```

## Vulnerability classes covered

| Priority | Class |
|----------|-------|
| CRITICAL | Missing signer/authority checks |
| CRITICAL | Account type confusion / discriminator bypass |
| CRITICAL | Arbitrary CPI target |
| CRITICAL | PDA seed manipulation |
| CRITICAL | Private key / infrastructure compromise |
| HIGH | Missing owner checks |
| HIGH | Token account validation gaps |
| HIGH | Stale state after CPI |
| HIGH | Duplicate mutable accounts |
| HIGH | Unchecked remaining_accounts |
| HIGH | Timelock / governance design failures |
| MEDIUM | Integer overflow/underflow |
| MEDIUM | Unsafe type casting |
| MEDIUM | Uninitialized / zero-copy alignment |
| MEDIUM | Close account revival (rent) |
| LOW-MED | Panic paths / DoS |
| LOW-MED | Floating point / precision loss |
| VARIES | Economic / oracle manipulation |
| VARIES | Upgradeability risks |
| VARIES | Cross-program trust assumptions |
| VARIES | Social engineering / supply chain |
| HIGH-CRIT | Token-2022 extension incompatibility |
| MEDIUM-HIGH | Compute budget exhaustion |
| CRITICAL | Instruction introspection spoofing |
| LOW-MED | Clock/slot reliance |

## Security & Trust

This skill runs on your machine and injects a system prompt into your AI assistant. You should know exactly what it does before installing. See [SECURITY.md](SECURITY.md) for the full trust model.

The short version:

- **No network calls at runtime** — all references are local Markdown files, nothing phones home
- **No `curl | sh`, `eval`, or encoded payloads** — every script is plain, readable Bash
- **No data exfiltration** — your code never leaves your machine through this skill
- **No file deletion** — the skill only creates workspace directories and logs
- **Fully auditable** — read every file before installing; they're short and plain-text

Verify it yourself before installing:

```bash
# Check scripts for hidden network calls or eval
grep -r "curl\|wget\|eval\|base64\|exec" scripts/ install.sh
# Read the full prompt the skill injects
cat SKILL.md
```

## Requirements

The skill itself has no dependencies — it's a set of reference documents that Claude Code reads during audits.

For running PoCs and fuzzing (optional), you'll need:

- [Rust](https://rustup.rs/)
- [Solana CLI](https://docs.solanalabs.com/cli/install)
- [Anchor](https://www.anchor-lang.com/docs/installation)
- [Trident](https://ackee.xyz/trident/docs/latest/) (for fuzz testing)

## License

[MIT](LICENSE)
