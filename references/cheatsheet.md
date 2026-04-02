# Vulnerability Cheatsheet

Condensed lookup table. Read this FIRST before diving into full references.
For details on any class, see `vulnerability-taxonomy.md` at the corresponding section.

## Quick-scan grep commands

Run these against the program source to surface candidates before manual review:

```bash
# §1 Missing signer — AccountInfo where Signer expected
grep -rn "AccountInfo" programs/*/src/ | grep -v "//\|///"
# §1 Missing has_one on authority fields
grep -rn "pub authority" programs/*/src/ | grep -v "has_one"
# §2 Discriminator — raw deserialization without type checks
grep -rn "try_from_slice\|from_account_info\|deserialize" programs/*/src/
# §3 Arbitrary CPI — program ID passed as account, not hardcoded
grep -rn "invoke\|invoke_signed" programs/*/src/
# §4 PDA seeds — user-controlled seeds
grep -rn "find_program_address\|create_program_address" programs/*/src/
# §5 Missing owner check
grep -rn "owner\|AccountInfo" programs/*/src/ | grep -v "constraint\|has_one"
# §6 Token validation — unchecked mint/authority on token accounts
grep -rn "TokenAccount\|token::mint\|token::authority" programs/*/src/
# §7 Stale state — reading account data after CPI
grep -rn "invoke\|invoke_signed" programs/*/src/
# §8 Duplicate accounts — same account passed twice
grep -rn "#\[account(mut" programs/*/src/
# §9 remaining_accounts
grep -rn "remaining_accounts" programs/*/src/
# §10 Integer math — unchecked arithmetic
grep -rn "checked_add\|checked_sub\|checked_mul\|checked_div\|overflow" programs/*/src/
# §13 Close account revival
grep -rn "close\|lamports.*= 0\|close = " programs/*/src/
# §14 Panic paths — unwrap, expect, array index, division
grep -rn "unwrap()\|expect(\|\[.*\]\|/ " programs/*/src/
# §16 Oracle — price feeds
grep -rn "pyth\|switchboard\|oracle\|price" programs/*/src/
# §17 Upgradeability
grep -rn "upgrade\|set_authority\|BpfLoaderUpgradeable" programs/*/src/
# §22 Token-2022 extensions — transfer hooks, fees, permanent delegate
grep -rn "token_2022\|Token2022\|spl_token_2022\|TokenInterface\|transfer_hook\|transfer_fee\|permanent_delegate" programs/*/src/
# §23 Compute exhaustion — unbounded loops, Vec in on-chain state
grep -rn "remaining_accounts\|Vec<" programs/*/src/ | grep -v "test\|//"
# §23 CPI inside loops
grep -rn "invoke\|invoke_signed" programs/*/src/ -B5 | grep "for\|while\|loop"
# §24 Instruction introspection — sysvar validation
grep -rn "load_instruction_at\|sysvar::instructions\|Instructions" programs/*/src/
# §25 Clock/slot reliance — time-sensitive logic
grep -rn "Clock::get\|unix_timestamp\|clock\.slot\|deadline\|end_time\|cooldown\|expir" programs/*/src/
```

## Vulnerability classes at a glance

| § | Class | Severity | Key question | Anchor mitigates? |
|---|-------|----------|-------------|-------------------|
| 1 | Missing signer/authority | CRITICAL | Does every privileged ix verify the signer matches stored authority? | Partially — only if `Signer` + `has_one` used correctly |
| 2 | Account type confusion | CRITICAL | Can an attacker pass a wrong account type that deserializes successfully? | Yes — 8-byte discriminator, but bypassable with `UncheckedAccount` |
| 3 | Arbitrary CPI target | CRITICAL | Is the CPI target program ID hardcoded or caller-controlled? | No — must manually verify program ID |
| 4 | PDA seed manipulation | CRITICAL | Can an attacker control seeds to derive a different PDA? | Partially — only if `seeds` + `bump` constraints are correct |
| 5 | Missing owner check | HIGH | Does the program verify account.owner == expected_program? | Yes — `Account<>` checks owner, but `AccountInfo` / `UncheckedAccount` don't |
| 6 | Token validation gaps | HIGH | Are mint, authority, and token program verified on every token account? | Partially — needs explicit `token::mint`, `token::authority` constraints |
| 7 | Stale state after CPI | HIGH | Does the program read account data after a CPI without reloading? | No — must manually reload |
| 8 | Duplicate mutable accounts | HIGH | Can the same account be passed for two different parameters? | Partially — Anchor checks some, but not all combinations |
| 9 | Unchecked remaining_accounts | HIGH | Does the program validate accounts from `ctx.remaining_accounts`? | No — remaining_accounts bypass all Anchor constraints |
| 10 | Integer overflow/underflow | MEDIUM | Is all arithmetic checked? Are casts safe? | No — Rust release builds wrap by default |
| 11 | Unsafe type casting | MEDIUM | Are there `as` casts that truncate or change sign? | No |
| 12 | Uninitialized / zero-copy | MEDIUM | Is `zero_copy` used with correct alignment? Any uninitialized reads? | Partially — `init` zeroes, but `zero_copy` has alignment requirements |
| 13 | Close account revival | MEDIUM | Can a closed account be revived by sending it lamports in the same tx? | Partially — `close` zeroes data + transfers lamports, but same-tx revival possible |
| 14 | Panic paths / DoS | LOW-MED | Can an attacker trigger unwrap/expect/divide-by-zero/index OOB? | No |
| 15 | Floating point / precision | LOW-MED | Is floating point used for financial math? Rounding direction? | No |
| 16 | Economic / oracle manipulation | VARIES | Are price feeds validated for staleness, confidence, and source? | No |
| 17 | Upgradeability risks | VARIES | Who holds upgrade authority? Is it a multisig? Timelock? | No |
| 18 | Cross-program trust | VARIES | Does the program assume CPI targets behave correctly? | No |
| 19 | Supply chain / social eng. | VARIES | Are dependencies audited? Secrets in client code? | No |
| 20 | Private key compromise | CRITICAL | Are privileged keys on hot wallets? Single points of failure? | No |
| 21 | Timelock / governance | HIGH | Can admin actions execute instantly without delay? | No |
| 22 | Token-2022 extensions | HIGH-CRIT | Does the program handle transfer hooks, fees, permanent delegate, CPI guard? | No |
| 23 | Compute budget exhaustion | MED-HIGH | Can an attacker make a critical ix exceed the CU limit? | No |
| 24 | Instruction introspection spoofing | CRITICAL | Is the Instructions sysvar validated? Is program ID + data fully checked? | No |
| 25 | Clock/slot reliance | LOW-MED | Does time-sensitive logic trust validator-reported timestamps? | No |

## Priority order by program type

**DeFi / handles tokens:** §1 → §6 → §22 → §3 → §10 → §16 → §4 → §7 → §8 → §20 → §21

**DeFi accepting arbitrary mints:** §22 → §6 → §1 → §3 → §10 → §16 → §23

**Governance / DAO:** §1 → §20 → §21 → §4 → §17 → §8 → §3

**NFT / metaplex:** §1 → §2 → §4 → §6 → §5 → §3

**Native (non-Anchor):** §1 → §2 → §5 → §3 → §4 → §24 → §12 → §10 → §7

**Uses instruction introspection:** §24 → §1 → §3 → §5

**Auctions / vesting / time-locked:** §25 → §1 → §23 → §20 → §10

**Any program with admin keys:** §20 → §21 → §1 → §17
