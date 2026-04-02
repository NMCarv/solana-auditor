# Security Audit Report

## Program: [PROGRAM NAME]
## Program ID: [PUBKEY or N/A for pre-deployment]
## Audit Date: [DATE]
## Auditor: [NAME]

---

## Executive Summary

**Overall Risk Rating:** [CRITICAL / HIGH / MEDIUM / LOW]

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |

[1-2 paragraph summary of the program, its purpose, the audit scope, and the key findings. Include the most impactful finding if any.]

---

## Program Overview

### Purpose
[What the program does]

### Architecture
[Key components, account relationships, external dependencies]

### Instruction Map

| Instruction | Access | Mutates | CPIs | Priority |
|-------------|--------|---------|------|----------|
| initialize | Admin | Config, Vault | System, Token | HIGH |
| deposit | User | UserState, Vault | Token | HIGH |
| ... | ... | ... | ... | ... |

### Account Relationship Diagram
```
[Authority] --has_one--> [Config]
[Config] --has_one--> [Vault]
[Vault] --token::mint--> [Mint]
...
```

### External Dependencies
- Token Program: [SPL Token / Token-2022 / Both]
- Oracle: [Pyth / Switchboard / None]
- Other CPIs: [list]
- Upgrade authority: [address, type (EOA/multisig/governance)]

---

## Findings

### [CRITICAL-01] Finding Title

**Class:** [Taxonomy reference, e.g., §1 Missing signer/authority]
**Location:** `programs/my_program/src/instructions/admin.rs:L42-L58`
**Status:** Confirmed

#### Description
[Clear explanation of the vulnerability — what it is and why it exists]

#### Impact
[What an attacker can do. Quantify: drain X tokens, mint Y unbacked, modify Z]

#### Proof of Concept
```rust
// or TypeScript — the test that demonstrates the exploit
```

#### Recommendation
```rust
// Before (vulnerable)

// After (fixed)
```

---

### [HIGH-01] Finding Title

**Class:** [Taxonomy reference]
**Location:** `file:line`
**Status:** Confirmed / Suspected

#### Description
#### Impact
#### Proof of Concept
#### Recommendation

---

[Repeat for each finding, severity-sorted]

---

## Testing Methodology

### Tools Used
- [x] Manual code review (instruction-by-instruction)
- [ ] Anchor test framework (TypeScript PoCs)
- [ ] LiteSVM (Rust PoCs)
- [ ] Mollusk (instruction-level tests)
- [ ] Trident (fuzz testing)
- [ ] proptest (property-based testing)
- [ ] cargo-audit (dependency scanning)

### Fuzzing Coverage

| Instruction | Fuzzed | Iterations | Invariants Checked |
|-------------|--------|------------|-------------------|
| deposit | Yes | 100,000 | Conservation, no-overflow |
| withdraw | Yes | 100,000 | Conservation, no-value-creation |
| ... | ... | ... | ... |

### Invariants Tested

| Invariant | Result |
|-----------|--------|
| Total value conservation | PASS / VIOLATED |
| Authority-only config access | PASS / VIOLATED |
| No value creation on roundtrip | PASS / VIOLATED |
| ... | ... |

---

## Recommendations (Prioritized)

### Immediate (before deployment / before next operation)
1. [Fix CRITICAL findings]
2. [Fix HIGH findings with fund-loss risk]

### Short-term (within 1-2 weeks)
1. [Fix remaining HIGH findings]
2. [Fix MEDIUM findings]

### Long-term (within 1-3 months)
1. [Address architectural concerns]
2. [Implement monitoring / alerting]
3. [Consider re-audit after significant changes]

---

## Scope and Limitations

### In Scope
- [List files/programs reviewed]
- [Commit hash or version]

### Out of Scope
- [Frontend / client code]
- [Off-chain infrastructure]
- [Economic modeling beyond basic oracle checks]

### Limitations
- [Any areas not fully covered]
- [Time constraints]
- [Missing verified source for deployed programs]

---

## Appendix

### A. Account Map (Full)
[Complete account relationship diagram]

### B. Dependency List
[Output of `cargo tree` or relevant subset]

### C. Build Verification
[Build warnings, cargo audit output]

### D. Test Output
[Relevant test logs, fuzz crash details]
