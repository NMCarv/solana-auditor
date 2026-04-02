# Critical: Key Management & Governance (§20, §21)

Private key compromise, infrastructure security, timelocks, and governance design.
The #1 attack vector by dollar loss in 2024-2026.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §20 — Private key management and infrastructure compromise

**What:** The protocol's security depends on one or more private keys that control privileged operations (admin, upgrade, minting, treasury). If these keys are compromised, the attacker gains full control regardless of how secure the smart contract code is.

**Why critical:** Resolv ($25M) lost funds because ONE AWS KMS key controlled unlimited minting with zero on-chain safeguards. Drift ($285M) was drained after the attacker gained admin access and rotated keys to lock out the team. Both had been audited multiple times.

**Sub-classes:**
- **Single-key admin:** one EOA controls upgrade authority, minting, treasury, or config changes
- **Cloud KMS dependency:** privileged keys stored in AWS KMS, GCP Cloud HSM, etc. — cloud infrastructure compromise = key compromise
- **No on-chain safety rails:** the smart contract trusts the key holder unconditionally with no caps, rate limits, or sanity checks
- **Key rotation without timelock:** admin keys can be changed instantly, allowing an attacker to lock out the legitimate team
- **Hot wallet over-authorization:** operational keys held in hot wallets with more privileges than necessary
- **Withdrawal limit manipulation (NEW — Drift 2026):** admin raises withdrawal limits to absurd values ($500T in Drift's case) before draining. On-chain withdrawal caps that can be overridden by admin provide no real protection. Caps must be hardcoded or require multi-party + timelocked changes.
- **Plaintext key exposure (NEW — DEXX 2024):** platforms that custody user keys store/transmit them insecurely. DEXX's `export_wallet` endpoint displayed private keys in plaintext. Server breach = mass wallet drain. 8,620+ wallets compromised.

**Detection:**
```bash
# Identify all privileged roles and their powers
grep -rn "authority\|admin\|owner\|operator\|service_role\|minter" programs/*/src/
# For each: what can this role do? Is there an upper bound?

# Check for on-chain safety rails
grep -rn "max_\|cap\|limit\|ceiling\|rate_limit\|cooldown" programs/*/src/
# Check: can the admin mint unlimited tokens?
# Check: can the admin withdraw unlimited funds?
# Check: can the admin change their own key instantly?

# Check upgrade authority
solana program show <PROGRAM_ID>
# Is it an EOA, multisig, or governance?

# Check for emergency mechanisms
grep -rn "pause\|freeze\|emergency\|circuit_breaker" programs/*/src/
# Check: can pause be triggered independently of admin key?
# Check: can the pause mechanism itself be disabled by the admin?
```

**What an audit should flag:**
- Single EOA as upgrade authority on protocol with TVL > $1M → CRITICAL
- Minting/burning with no on-chain cap or rate limit → HIGH
- Withdrawal limits changeable by admin without timelock → HIGH
- Admin key rotation without timelock → HIGH
- No independent emergency pause mechanism → HIGH
- Cloud-hosted keys without HSM or multi-party computation → MEDIUM
- No verified builds published → MEDIUM

**Recommended architecture:**
```
Admin operations → Multisig (e.g., Squads) → Timelock (24-48h) → Execution
Emergency pause → Separate guardian key (cannot be rotated by admin) → Instant
Key rotation → Multisig → Timelock (72h+) → Execution
Minting/large withdrawals → On-chain cap per epoch + rate limit
```

**Severity:** CRITICAL when a single key can drain protocol funds. The pattern across 2025-2026 exploits is clear: key compromise is now the #1 vector by dollar loss.

---

## §21 — Timelock and governance design failures

**What:** The protocol's governance or admin operations lack time delays, allowing privileged actions to execute instantly. Without timelocks, there is no window for monitoring, community review, or emergency response.

**Why dangerous:** Timelocks are the critical safety net that converts a key compromise from "instant catastrophic loss" into "detectable incident with time to respond." Without them, the difference between a compromised key and a total protocol drain is measured in seconds.

**Sub-classes:**

### Missing timelocks
The most common issue: admin or governance operations execute instantly.
```rust
// BAD: admin can change config instantly
pub fn update_config(ctx: Context<AdminUpdate>, new_fee: u64) -> Result<()> {
    ctx.accounts.config.fee = new_fee;  // instant, no delay
    Ok(())
}

// BAD: upgrade authority can deploy new code instantly
// (Solana's default — no built-in timelock on program upgrades)
```

### Timelock bypass via key rotation
The most devastating pattern (seen in Drift): attacker compromises admin key, then uses admin privileges to rotate the admin key to one they control, locking out the legitimate team. If key rotation is not itself behind a longer timelock, the attacker effectively owns the protocol permanently.
```rust
// BAD: admin can rotate their own key instantly
pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
    ctx.accounts.config.admin = new_admin;  // attacker locks out team
    Ok(())
}
```

### Governance attacks on inactive DAOs
Low-participation DAOs are vulnerable to hostile proposals (Synthetify: $230K). If there's no quorum, no veto council, and no timelock, a single actor with enough tokens can pass any proposal.

### Emergency pause anti-pattern
If the emergency pause mechanism is behind a timelock, it defeats its purpose. If the pause mechanism can be disabled by the admin key, a compromised admin can disable it before draining. The correct pattern: emergency pause is instant and controlled by a SEPARATE key that cannot be rotated by the admin.

**Detection:**
```bash
# Find all admin/governance operations
grep -rn "admin\|governance\|authority\|set_\|update_\|transfer_authority" programs/*/src/

# Check for timelock patterns
grep -rn "timelock\|delay\|pending\|queue\|cooldown\|epoch" programs/*/src/

# Check key rotation
grep -rn "set_admin\|set_authority\|transfer_owner\|new_admin" programs/*/src/
# Is key rotation behind a LONGER timelock than other admin ops?

# Check emergency mechanisms
grep -rn "pause\|freeze\|halt\|emergency" programs/*/src/
# Is pause instant? Is it on a separate key? Can admin disable it?

# Check governance parameters
grep -rn "quorum\|threshold\|voting_period\|veto" programs/*/src/
```

**Audit checklist for timelock/governance:**
- [ ] All admin operations behind a timelock (minimum 24h for config, 72h+ for key rotation)
- [ ] Key rotation has a LONGER timelock than other operations
- [ ] Emergency pause is instant and on a separate, non-rotatable key
- [ ] Emergency pause cannot be disabled by the admin
- [ ] Governance has minimum quorum requirements
- [ ] Governance has a veto council or guardian for malicious proposals
- [ ] Large withdrawals/mints have per-epoch caps even with admin approval
- [ ] Timelock cannot be set to zero by the admin

**Severity:** HIGH to CRITICAL. Missing timelocks on admin operations directly enabled both Resolv ($25M) and Drift ($285M). Missing governance safeguards enabled Synthetify ($230K).
