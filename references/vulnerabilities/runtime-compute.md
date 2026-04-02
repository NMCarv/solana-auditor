# Runtime & Compute (§23-§25)

Compute budget exhaustion, instruction introspection spoofing, and clock/slot reliance.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §23 — Compute budget exhaustion

**What:** An attacker crafts inputs that cause the program to consume all available compute units (default 200K per instruction, max 1.4M per transaction), causing the transaction to fail. This is distinct from §14 (panic paths) — the program doesn't crash, it simply runs out of gas.

**Why dangerous:** If an attacker can make a critical instruction (liquidation, settlement, oracle update, withdrawal) exceed the CU limit, they can block that operation indefinitely. This is especially severe when the blocked operation is time-sensitive or when the attacker profits from the delay.

**Sub-classes:**

- **Unbounded iteration:** Loops over user-controlled collections (`remaining_accounts`, vectors stored on-chain, nested account structures) with no size cap.
- **Expensive deserialization:** Large accounts or many accounts deserialized in a single instruction. Zero-copy helps but has its own issues (§12).
- **Recursive CPI chains:** Deeply nested CPI calls that consume the shared CU budget. Caller and callee share the same budget — a callee can consume all remaining CUs.
- **Log spam:** Excessive `msg!()` or `emit!()` calls in loops consume CUs. Not a direct attack vector but can push legitimate logic over the limit.
- **Algorithmic complexity:** On-chain sorting, searching, or mathematical operations with O(n^2) or worse complexity on user-controlled n.

**Vulnerable pattern:**
```rust
// BAD: iterates over all remaining_accounts with no cap
for account in ctx.remaining_accounts.iter() {
    let data = Account::<UserPosition>::try_from(account)?;
    total += data.value;  // attacker passes 100 accounts → OOM on CU
}

// BAD: unbounded vector stored on-chain
#[account]
pub struct Pool {
    pub participants: Vec<Pubkey>,  // grows without bound
}
pub fn distribute(ctx: Context<Distribute>) -> Result<()> {
    for p in ctx.accounts.pool.participants.iter() {
        // transfer to each → exceeds CU at ~50-100 participants
    }
}
```

**Detection:**
```bash
# Find loops over remaining_accounts
grep -rn "remaining_accounts" programs/*/src/ | grep -v "//"

# Find unbounded vectors in account structs
grep -rn "Vec<" programs/*/src/ | grep -v "test\|//\|mod test"

# Find nested loops (O(n^2) risk)
grep -rn "for.*\{" programs/*/src/ -A5 | grep "for.*\{"

# Find CPI calls inside loops
grep -rn "invoke\|invoke_signed" programs/*/src/ -B5 | grep "for\|while\|loop"

# Check if compute budget is explicitly requested
grep -rn "ComputeBudgetInstruction\|request_units\|compute_budget" programs/*/src/
```

**Fix:**
```rust
// 1. Cap iteration with a constant
const MAX_ACCOUNTS: usize = 10;
require!(
    ctx.remaining_accounts.len() <= MAX_ACCOUNTS,
    MyError::TooManyAccounts
);

// 2. Use pagination for large collections
pub fn distribute(ctx: Context<Distribute>, offset: u32, limit: u32) -> Result<()> {
    let end = (offset + limit).min(pool.participants.len() as u32);
    for i in offset..end {
        // process batch
    }
}

// 3. Prefer fixed-size arrays over Vec in on-chain state
#[account]
pub struct Pool {
    pub participants: [Pubkey; 32],  // bounded
    pub count: u8,
}
```

**Severity:** MEDIUM to HIGH — blocks liquidations (potential bad debt), freezes withdrawals (temporary fund lock), or prevents oracle updates (stale price exploitation).

---

## §24 — Instruction introspection spoofing

**What:** Programs that read other instructions in the current transaction via the `sysvar::instructions` account (instruction introspection) but fail to fully validate what they read. This is commonly used for Ed25519/Secp256k1 signature verification and flash loan guards.

**Why dangerous:** Instruction introspection lets a program say "check that instruction N in this transaction was a call to program X with data Y." If the program only checks the data format but not the program ID, or only checks program ID but not the instruction index, an attacker can craft a transaction that satisfies the check with a spoofed instruction.

**Sub-classes:**

- **Missing program ID validation:** The program reads instruction data at a given index but doesn't verify the instruction was executed by the expected program. The Wormhole exploit ($320M) used exactly this — a fake account was accepted in place of the Instructions sysvar, and the "Ed25519 verification" instruction was entirely attacker-controlled.
- **Wrong instruction index:** The program assumes the verification instruction is at index 0, but the attacker can reorder instructions or insert padding instructions to shift indices.
- **Partial data validation:** The program checks that a signature verification instruction exists but doesn't verify it checked the right message, pubkey, or signature.
- **Flash loan guard bypass:** Programs that check "did a deposit instruction happen earlier in this tx?" can be tricked if they don't verify the deposit was to THIS program with THESE parameters.

**Vulnerable pattern:**
```rust
// BAD: reads instruction sysvar without validating account address
let ix_sysvar = &ctx.accounts.instructions;  // could be a fake account!
let ix = load_instruction_at_checked(0, ix_sysvar)?;

// BAD: checks program ID but not message content
let ix = load_instruction_at_checked(0, &ix_sysvar)?;
if ix.program_id != ed25519_program::ID {
    return Err(MyError::InvalidSignature.into());
}
// proceeds without verifying the signature was over the expected message

// BAD: hardcodes instruction index
let ix = load_instruction_at_checked(0, &ix_sysvar)?;
// attacker puts a dummy instruction at index 0, real exploit at index 1
```

**Detection:**
```bash
# Find instruction introspection usage
grep -rn "load_instruction_at\|sysvar::instructions\|Instructions" programs/*/src/

# Check if sysvar account is validated
grep -rn "sysvar::instructions::ID\|sysvar::instructions::check_id" programs/*/src/

# Find Ed25519 / Secp256k1 verification patterns
grep -rn "ed25519\|secp256k1\|verify_signature" programs/*/src/

# Check if the program iterates instructions rather than hardcoding index
grep -rn "load_instruction_at_checked\|get_instruction_relative" programs/*/src/
```

**Fix:**
```rust
// 1. ALWAYS validate the Instructions sysvar address
use solana_program::sysvar::instructions;
if *ix_sysvar_account.key != instructions::ID {
    return Err(ProgramError::InvalidAccountData);
}
// Or use Anchor's Sysvar type:
pub instructions: Sysvar<'info, Instructions>,

// 2. Validate program ID AND instruction data
let ix = load_instruction_at_checked(index, &ix_sysvar)?;
require!(ix.program_id == ed25519_program::ID, MyError::WrongProgram);
// Deserialize and verify: correct pubkey, correct message, correct signature

// 3. Don't hardcode instruction index — search for the expected instruction
let mut found = false;
for i in 0..num_instructions {
    let ix = load_instruction_at_checked(i, &ix_sysvar)?;
    if ix.program_id == ed25519_program::ID {
        // validate data...
        found = true;
        break;
    }
}
require!(found, MyError::MissingVerification);
```

**Severity:** CRITICAL — the Wormhole exploit ($320M) was exactly this bug. Any program using instruction introspection for security-critical checks (signature verification, flash loan guards, multi-instruction protocols) is at risk.

---

## §25 — Clock/slot reliance

**What:** Programs that use `Clock::get().unix_timestamp` or `Clock::get().slot` for time-sensitive logic (vesting schedules, auction deadlines, cooldowns, rate limiting) are trusting validator-reported values that have inherent drift and manipulation potential.

**Why dangerous:** `unix_timestamp` is set by the validator producing the block. The Solana runtime allows a drift tolerance — validators can report timestamps that differ from real wall-clock time. `slot` is more reliable for ordering but maps to wall-clock time unpredictably due to variable slot times and skipped slots.

**Sub-classes:**

- **Timestamp manipulation:** Validators have tolerance to set `unix_timestamp` slightly ahead or behind. For short time windows (seconds to minutes), this can be exploited to trigger or delay time-dependent operations.
- **Skipped slot assumptions:** Programs that calculate elapsed time as `(current_slot - start_slot) * 400ms` are wrong when slots are skipped. Skipped slots don't advance the clock but do advance slot numbers.
- **Epoch boundary sensitivity:** Programs relying on epoch boundaries for transitions (staking, fee calculations) can behave unexpectedly if they don't account for variable epoch lengths.
- **Front-running time-dependent operations:** If an auction ends at timestamp T, a validator producing the block at T can see all submitted bids and choose to include/exclude transactions.

**Vulnerable pattern:**
```rust
// BAD: using timestamp for short-window logic (minutes)
let clock = Clock::get()?;
if clock.unix_timestamp < auction.end_time {
    // still accepting bids — but validator can manipulate this by ~seconds
}

// BAD: assuming slot duration is constant
let elapsed_seconds = (clock.slot - start_slot) * 400 / 1000;  // wrong

// BAD: exact timestamp comparison
if clock.unix_timestamp == scheduled_time {
    // may never trigger — slots don't land on exact timestamps
}
```

**Detection:**
```bash
# Find all clock usage
grep -rn "Clock::get\|clock\.unix_timestamp\|clock\.slot\|clock\.epoch" programs/*/src/

# Find time comparisons
grep -rn "timestamp.*<\|timestamp.*>\|timestamp.*==\|slot.*<\|slot.*>" programs/*/src/

# Find slot-to-time conversions
grep -rn "slot.*400\|slot.*0\.4\|slot_duration\|ms_per_slot" programs/*/src/

# Find vesting / auction / deadline logic
grep -rn "deadline\|end_time\|start_time\|vesting\|unlock\|cooldown\|expir" programs/*/src/
```

**Fix:**
```rust
// 1. Use slot-based deadlines for ordering, not second-precision timing
// Slots are monotonic even if time isn't

// 2. For timestamp logic, use generous windows (hours, not seconds)
require!(
    clock.unix_timestamp >= auction.end_time + GRACE_PERIOD,
    MyError::AuctionNotEnded
);

// 3. Never use exact timestamp comparisons — use >= or <=
if clock.unix_timestamp >= scheduled_time {
    // trigger
}

// 4. Never convert slots to wall-clock time with a fixed ratio
// Instead, read Clock::get().unix_timestamp directly if you need time

// 5. For high-value time-sensitive operations, consider requiring
// multiple confirmations or using a commit-reveal pattern
```

**Severity:** LOW to MEDIUM — exploitable range is narrow (seconds), but can be HIGH for auctions, liquidation deadlines, or rate-limited minting where even small timing advantages create extractable value.
