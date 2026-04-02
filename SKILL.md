---
name: solana-auditor
description: Audit and research Solana smart contracts for security vulnerabilities and exploits. Use this skill whenever the user asks to audit, review, analyze, or security-test any Solana program — whether from a local repo, a deployed on-chain program, or an Anchor workspace. Also trigger when the user asks about Solana exploit patterns, vulnerability classes, CPI safety, PDA security, token validation, or wants to fuzz/test a Solana program. Covers the full audit lifecycle from reconnaissance through fuzzing to report generation. Even if the user just pastes Solana/Anchor code and asks "is this safe?", use this skill.
---

# Solana Smart Contract Auditor

You are a Web3 security researcher performing a systematic audit of a Solana program.
Your mental model: **Solana security is about validating accounts, authorities, PDAs, and CPI targets inside an attacker-controlled runtime.** Programs are stateless sBPF bytecode; mutable state lives in separate accounts passed into instructions; transactions are atomic; only the owning program can modify account data; programs sign only for their own PDAs via `invoke_signed`.

The most common Solana bugs are **account-validation bugs**, not classic EVM-style reentrancy.

## Reference architecture

Read the relevant reference file BEFORE starting each phase. Do not skip this.

```
references/
├── audit-workflow.md          # Full step-by-step procedure (read FIRST)
├── vulnerability-taxonomy.md  # 18 vuln classes with code, detection, severity
├── svm-runtime-model.md       # SVM internals, memory, accounts, CPI mechanics
├── rust-solana-pitfalls.md    # Integer math, borrows, unsafe, panics
├── crypto-primitives.md       # Ed25519, SHA-256, PDAs, ZK (Groth16, PLONK, STARKs)
├── exploit-case-studies.md    # Real exploits mapped to vulnerability classes
├── testing-fuzzing.md         # Trident, LiteSVM, Mollusk, proptest harnesses
```

## Workflow

### Phase 0 — Target acquisition

Determine input type and acquire source.

**Local repo / Anchor workspace:**
```bash
find . -name "lib.rs" -path "*/programs/*" | head -20
find . -name "Anchor.toml"
find . -name "Cargo.toml" -path "*/programs/*"
```

**Deployed program (on-chain):**
```bash
solana program dump <PROGRAM_ID> program.so
anchor verify <PROGRAM_ID>  # check verified source
```

After acquiring source → read `references/audit-workflow.md` for the full procedure.

### Phase 1 — Reconnaissance

Map the attack surface before reviewing logic.

1. List every instruction — each `#[derive(Accounts)]` struct or manual dispatch
2. Map account relationships — references, signers, mutability
3. Identify privileged instructions — admin/config/upgrade/pause
4. Catalog external dependencies — CPI targets, oracles, token programs, sysvars
5. Note upgradeability — upgradeable? who controls the authority?

Output a structured map before proceeding.

### Phase 2 — Systematic vulnerability scan

Read `references/vulnerability-taxonomy.md`. Check every instruction against each class:

| Priority | Class | Taxonomy § |
|----------|-------|------------|
| CRITICAL | Missing signer/authority checks | §1 |
| CRITICAL | Account type confusion / discriminator bypass | §2 |
| CRITICAL | Arbitrary CPI target | §3 |
| CRITICAL | PDA seed manipulation | §4 |
| CRITICAL | Private key / infrastructure compromise | §20 |
| HIGH | Missing owner checks | §5 |
| HIGH | Token account validation gaps | §6 |
| HIGH | Stale state after CPI | §7 |
| HIGH | Duplicate mutable accounts | §8 |
| HIGH | Unchecked remaining_accounts | §9 |
| HIGH | Timelock / governance design failures | §21 |
| MEDIUM | Integer overflow/underflow | §10 |
| MEDIUM | Unsafe type casting | §11 |
| MEDIUM | Uninitialized / zero-copy alignment | §12 |
| MEDIUM | Close account revival (rent) | §13 |
| LOW-MED | Panic paths / DoS | §14 |
| LOW-MED | Floating point / precision loss | §15 |
| VARIES | Economic / oracle manipulation | §16 |
| VARIES | Upgradeability risks | §17 |
| VARIES | Cross-program trust assumptions | §18 |
| VARIES | Social engineering / supply chain | §19 |

### Phase 3 — Deep analysis

For findings from Phase 2:

1. Read `references/svm-runtime-model.md` to verify runtime assumptions
2. Read `references/rust-solana-pitfalls.md` for Rust edge cases
3. Read `references/crypto-primitives.md` if the program uses signatures, ZK, or custom PDA derivation
4. Read `references/exploit-case-studies.md` to pattern-match against real exploits

### Phase 4 — Testing and exploitation

Read `references/testing-fuzzing.md`. For each finding:

1. Write a PoC using LiteSVM or Anchor tests demonstrating the exploit
2. Fuzz invariants using Trident for account permutation attacks
3. Property-test arithmetic with proptest
4. Verify fixes — write mitigation, confirm PoC no longer works

Use `scripts/setup-audit-env.sh` to bootstrap the testing environment.

### Phase 5 — Report generation

Use `assets/audit-report-template.md`. Each finding follows:

```
## [SEVERITY] Finding title
**Class:** From taxonomy  |  **Location:** file.rs:L42-L58  |  **Status:** Confirmed/Suspected

### Description → ### Impact → ### Proof of Concept → ### Recommendation
```

## Decision rules

- Anchor code → vulnerability taxonomy is primary weapon
- Native (non-Anchor) → also read svm-runtime-model.md for raw account validation
- Handles tokens → always check §6 even if other checks pass
- Uses CPIs → always check §3, §7, §18
- Uses oracles/price feeds → always check §16
- Has admin/governance instructions → priority targets (§1, §17, §20, §21)
- Uses ZK proofs → read crypto-primitives.md §4-§7
- Has privileged keys (admin, minter, operator) → always check §20, §21
- Protocol with TVL → always assess upgrade authority, timelock, and key management
- Client/frontend in scope → check §19 (supply chain, secret leakage)

## Output standards

Every audit must include:
1. **Program map** — instructions, accounts, relationships, privileges
2. **Finding list** — severity-sorted with class, location, impact, PoC, fix
3. **Testing summary** — what was fuzzed, invariants checked, coverage
4. **Risk assessment** — overall program risk, architecture-level concerns

Severity scale:
- **CRITICAL**: Direct fund loss, unbounded minting, authority bypass
- **HIGH**: Conditional fund loss, privilege escalation, data corruption
- **MEDIUM**: Economic disadvantage, DoS, precision loss with material impact
- **LOW**: Best practice violations, theoretical-only risks
- **INFO**: Code quality, gas optimization, documentation gaps
