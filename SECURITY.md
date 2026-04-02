# Security & Trust

This skill injects a system prompt and ships shell scripts that run on your machine.
You should understand exactly what it does before installing it.

## What this skill does

- **SKILL.md** tells the AI how to perform a Solana security audit. It is a text prompt — it does not execute code.
- **references/** are static Markdown documents the AI reads for context. They contain no executable code.
- **assets/** contains a report template (Markdown). No executable code.
- **scripts/setup-audit-env.sh** checks for installed tools (`rustc`, `solana`, `anchor`, `cargo-audit`, `trident-cli`, `cargo-fuzz`), prints warnings for missing ones, and creates a workspace directory. It runs `anchor build` and `cargo audit` only if it detects an Anchor project.
- **scripts/fuzz-harness-template.rs** is a Rust source template. It is not compiled or executed by the skill.
- **install.sh** copies files to your skill directory. If run outside a cloned repo, it does a `git clone` from the hardcoded GitHub URL.

## What this skill does NOT do

- **No network calls at runtime.** The skill never phones home, fetches remote code, or downloads anything during normal use. The only network operation is the optional `git clone` in `install.sh` when installing without a local copy.
- **No `curl | sh` or `eval`.** No piped remote execution, no dynamic code evaluation.
- **No data exfiltration.** The skill does not read, collect, or transmit your source code, keys, or any other data outside your machine.
- **No file deletion.** The skill only creates files (workspace directory, build logs). It never deletes or overwrites your project files.
- **No background processes.** Nothing is daemonized, scheduled, or persisted beyond the skill files themselves.
- **No obfuscated code.** Every script is plain Bash. Every reference is plain Markdown. Read them yourself.

## How to verify

Before installing, audit the skill yourself:

```bash
# Read every script — they're short
cat install.sh
cat scripts/setup-audit-env.sh

# Confirm no network calls in the skill prompt
grep -r "curl\|wget\|fetch\|http" SKILL.md references/ assets/

# Confirm no eval or encoded payloads
grep -r "eval\|base64\|exec\|source " scripts/

# Check that install.sh only copies files
grep -n "cp\|mkdir\|chmod" install.sh
```

## Reporting vulnerabilities

If you find a security issue in this skill, please open an issue at
https://github.com/NMCarv/solana-auditor/issues or contact the maintainer directly.

Do **not** open a public issue if the vulnerability could be exploited before a fix is available — reach out privately first.
