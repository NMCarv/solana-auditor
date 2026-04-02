# Upgradeability & Cross-Program Trust (§17, §18)

Program upgradeability risks and assumptions about external program behavior.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §17 — Upgradeability risks

**What:** Solana programs are upgradeable by default. The upgrade authority can change program code at any time.

**Detection:**
```bash
solana program show <PROGRAM_ID>
# Check: ProgramData account authority field
# Check: is it a multisig? EOA? Governance?
```

**Findings:**
- Single EOA upgrade authority on protocol with TVL → HIGH
- Upgrade authority not behind timelock → MEDIUM
- Upgrade authority not behind multisig → HIGH
- No verified build published → MEDIUM (users can't verify what's deployed)

**Fix:**
- Use multisig (e.g., Squads) for upgrade authority
- Implement timelock for upgrades
- Publish verified builds
- Consider revoking upgrade authority for stable, audited programs

**Severity:** HIGH for DeFi protocols. Lower for utility programs.

---

## §18 — Cross-program trust assumptions

**What:** The program makes assumptions about how other programs behave during CPI, or trusts return values from external programs without validation.

**Sub-classes:**
- **Rebase/fee-on-transfer tokens:** Token-2022 transfer hooks, transfer fees change actual amounts received
- **Callback trust:** assuming CPI return means success without checking state
- **Reentrancy via CPI:** while direct self-recursion is allowed, indirect cycles through multiple programs can create unexpected state
- **Extension behavior:** Token-2022 extensions (permanent delegate, freezing) change token semantics

**Detection:**
```bash
grep -rn "invoke\|invoke_signed" programs/*/src/
# For each CPI: what does the program assume about the callee's behavior?
# Is the actual transferred amount verified after CPI?
grep -rn "token_2022\|transfer_hook\|transfer_fee" programs/*/src/
```

**Fix:**
- After token transfers via CPI, verify actual balance changes (post - pre)
- Handle fee-on-transfer tokens explicitly
- Document and test assumptions about external program behavior
- Check for Token-2022 extension compatibility

**Severity:** VARIES — can be CRITICAL if transfer amounts differ from expected.
