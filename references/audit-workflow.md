# Audit Workflow — Step-by-Step Procedure

This document is the operational playbook. Follow it sequentially.

## Table of Contents
1. [Environment setup](#1-environment-setup)
2. [Source acquisition](#2-source-acquisition)
3. [Structural reconnaissance](#3-structural-reconnaissance)
4. [Instruction-by-instruction review](#4-instruction-by-instruction-review)
5. [Cross-cutting concerns](#5-cross-cutting-concerns)
6. [Testing phase](#6-testing-phase)
7. [Report assembly](#7-report-assembly)

---

## 1. Environment setup

Run `scripts/setup-audit-env.sh` or manually verify:

```bash
# Required tools
solana --version          # >= 1.18
anchor --version          # >= 0.30
rustc --version           # stable, >= 1.75
cargo install cargo-fuzz  # for libfuzzer harnesses
```

For deployed program analysis:
```bash
# Solana CLI configured to the right cluster
solana config get
solana config set --url mainnet-beta  # or devnet
```

Create a workspace:
```bash
mkdir -p audit-workspace/{source,findings,tests,reports}
```

## 2. Source acquisition

### Local source
```bash
# Verify it builds cleanly
cd <project-root>
anchor build 2>&1 | tee audit-workspace/build-log.txt

# Check for build warnings — they often hint at issues
grep -E "warning|unused|deprecated" audit-workspace/build-log.txt
```

### Deployed program
```bash
# Dump the binary
solana program dump <PROGRAM_ID> audit-workspace/source/program.so

# Check program metadata
solana program show <PROGRAM_ID>

# Attempt to find verified source:
# 1. Anchor registry
anchor verify <PROGRAM_ID> --provider.cluster mainnet

# 2. Check if the project publishes verified builds
# Look for verifiable-build CI artifacts or Solana Verify entries

# 3. Search GitHub for the program ID
# Many projects include their deployed address in README or Anchor.toml
```

If no source is available, you're limited to:
- Reading the IDL if published (anchor idl fetch <PROGRAM_ID>)
- sBPF binary analysis (limited but can reveal instruction structure)
- Black-box testing via transaction simulation

### Dependency audit
```bash
# Check Cargo.lock for known vulnerable crates
cargo audit 2>&1 | tee audit-workspace/cargo-audit.txt

# List all dependencies
cargo tree --prefix depth | head -100

# Check Anchor version — older versions have known issues
grep "anchor-lang" Cargo.toml
```

## 3. Structural reconnaissance

This is the most important pre-analysis step. Build a complete map before reviewing logic.

### 3.1 Instruction inventory

For Anchor programs, extract from `lib.rs`:
```bash
# Find all instruction handlers
grep -n "pub fn " programs/*/src/lib.rs

# Find all Account structs
grep -rn "#\[derive(Accounts)\]" programs/*/src/

# Find all account types (state)
grep -rn "#\[account\]" programs/*/src/
```

For each instruction, document:
- **Name and purpose** — what does this do?
- **Who can call it** — what signer is required?
- **What state changes** — which accounts are mutated?
- **External calls** — any CPIs?
- **Access control** — is this admin-only, user-only, permissionless?

### 3.2 Account relationship graph

Build a mental (or written) graph:
```
[Authority (signer)] --has_one--> [Config (PDA)]
[Config] --has_one--> [Vault (token account)]
[Vault] --token::mint--> [Mint]
[Mint] --mint_authority--> [PDA derived from Config]
```

Specifically track:
- Which accounts reference which other accounts via `has_one`, stored pubkeys, or PDA derivation
- Which accounts are writable and why
- Which accounts are PDAs and what seeds derive them
- Which accounts are expected to be specific programs (Token Program, System Program, etc.)

### 3.3 Privilege mapping

Classify every instruction into one of:
- **Permissionless** — anyone can call (e.g., crank, liquidate)
- **User-gated** — requires user to be a specific account holder
- **Admin-gated** — requires protocol authority
- **Governance-gated** — requires multisig or DAO vote

Admin and governance instructions are your highest-priority targets. They control protocol parameters and are often the least tested because "only admins call them."

### 3.4 External trust boundary catalog

List every external dependency:
- Token Program (which one — SPL Token or Token-2022?)
- System Program
- Associated Token Account Program
- Any oracle program (Pyth, Switchboard, Chainlink)
- Any other program the code CPIs into
- Any sysvar accessed (Clock, Rent, SlotHashes, Instructions)

For each: is the program ID hardcoded or user-supplied? If user-supplied, this is a critical review target.

## 4. Instruction-by-instruction review

For every instruction, ask these questions in order:

### The seven questions

1. **Who signs?** Is the signer checked? Does the signer match the stored authority? Could an attacker substitute a different signer?

2. **Are all accounts validated?** Owner check, address check, discriminator check, PDA derivation check, `has_one` constraints. For every account: what happens if the attacker passes a completely different account?

3. **Can accounts be swapped?** Could two accounts that should be distinct be the same account (duplicate mutable)? Could a token account for the wrong mint be passed?

4. **What about the CPI?** If the instruction CPIs: is the target program pinned? After CPI, is any previously-read state re-used without reload? Are signer seeds correct?

5. **Does the math hold?** Any arithmetic overflow/underflow? Any precision loss from division before multiplication? Any `as` casts that truncate?

6. **What about the close?** If accounts are closed: is there revival protection? Is the rent reclaimed correctly? Does the discriminator get zeroed?

7. **What's the economic model?** Could flash loans break assumptions? Could oracle manipulation profit an attacker? Are there sandwich attack vectors?

### Review checklist per instruction

```
Instruction: _______________________
- [ ] Signer verified and matches stored authority
- [ ] All account owners checked (program ownership)
- [ ] All account types checked (discriminator)
- [ ] PDA seeds verified (canonical bump, correct derivation)
- [ ] Token accounts: mint, authority, program validated
- [ ] No duplicate mutable account vulnerability
- [ ] CPI target program ID pinned
- [ ] Post-CPI state refreshed before reuse
- [ ] remaining_accounts validated if used
- [ ] Integer math checked/saturating
- [ ] No unsafe casts
- [ ] Close accounts zeroed and lamport-drained
- [ ] Economic invariants hold under adversarial conditions
```

## 5. Cross-cutting concerns

After individual instruction review, look for systemic issues:

### 5.1 Upgrade authority
```bash
solana program show <PROGRAM_ID>
# Check: is the upgrade authority set? Is it a multisig? Is it revoked?
```

A single-key upgrade authority on a DeFi protocol with TVL is a critical finding.

### 5.2 Initialization atomicity
Can the program be initialized in a bad state? Are there race conditions between init instructions? Can an attacker front-run initialization?

### 5.3 State machine consistency
For programs with phases/states: can an instruction be called in a state where it shouldn't be? Are state transitions validated?

### 5.4 Cross-instruction composability
Can calling instruction A then B produce a different (exploitable) outcome than intended? Look for assumptions about ordering.

### 5.5 Token-2022 compatibility
If the program interacts with tokens: does it handle Token-2022 extensions (transfer fees, permanent delegate, non-transferable, confidential transfers)? Ignoring these is increasingly a real bug class.

## 6. Testing phase

Read `references/testing-fuzzing.md` for detailed harness construction.

Priority order for testing:
1. **PoC for confirmed findings** — prove the exploit works
2. **Invariant fuzzing** — Trident for account permutation attacks
3. **Property testing** — proptest for arithmetic edge cases
4. **Negative tests** — verify that invalid operations correctly fail

## 7. Report assembly

Use `assets/audit-report-template.md`. Structure:

1. Executive summary (1 paragraph, risk rating, key stats)
2. Program overview (what it does, architecture)
3. Findings (severity-sorted, each with description → impact → PoC → fix)
4. Testing methodology and coverage
5. Recommendations (prioritized action items)
6. Appendix (full test output, account maps, dependency list)
