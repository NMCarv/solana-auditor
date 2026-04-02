# Critical: Account Validation (§1-§5)

The most common Solana code-level bug class. Every instruction must validate every account.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §1 — Missing signer/authority checks

**What:** An instruction that modifies privileged state does not verify that the caller is authorized. On Solana, the runtime marks accounts as `is_signer`, but the program must check that the signer matches the expected authority stored on-chain.

**Why critical:** An attacker can call any instruction with any accounts. If the program does not verify that the signer is the stored authority, the attacker IS the authority.

**Vulnerable pattern (Anchor):**
```rust
// BAD: authority is not checked as Signer, or no has_one constraint
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: AccountInfo<'info>,  // NOT Signer<'info>!
}
```

**Vulnerable pattern (native):**
```rust
// BAD: no check that authority.is_signer == true
let config = Config::unpack(&config_account.data.borrow())?;
// proceeds to modify config without verifying who called this
```

**Detection:**
```bash
# Find AccountInfo used where Signer should be
grep -rn "AccountInfo" programs/*/src/ | grep -v "/// "
# Find instructions missing has_one constraints on authority fields
grep -rn "pub authority" programs/*/src/
# Verify every mut account has a corresponding signer check
```

**Fix (Anchor):**
```rust
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut, has_one = authority)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,  // Signer enforced
}
```

**Fix (native):**
```rust
if !authority_account.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
if config.authority != *authority_account.key {
    return Err(MyError::UnauthorizedAuthority.into());
}
```

**Severity:** CRITICAL when it gates fund movement, minting, or config changes. HIGH otherwise.

---

## §2 — Account type confusion / discriminator bypass

**What:** The program deserializes an account without verifying it's the expected type. Anchor adds 8-byte discriminators, but native programs and programs using `UncheckedAccount` or raw deserialization can read account A's bytes as if it were type B.

**Why critical:** An attacker creates an account with data that looks valid when deserialized as a different type. "Type cosplay" can bypass all business logic.

**Vulnerable pattern:**
```rust
// BAD: deserializes without discriminator check
let data = try_from_slice_unchecked::<MyState>(&account.data.borrow())?;

// BAD in Anchor: using UncheckedAccount where Account<T> should be used
/// CHECK: "we'll validate later" (famous last words)
pub suspicious_account: UncheckedAccount<'info>,
```

**Detection:**
```bash
grep -rn "UncheckedAccount" programs/*/src/
grep -rn "AccountInfo" programs/*/src/ | grep -v "Signer\|Program\|SystemAccount"
grep -rn "try_from_slice" programs/*/src/
grep -rn "/// CHECK" programs/*/src/  # Review every CHECK comment
```

**Fix:** Always use Anchor's `Account<'info, T>` which validates discriminator + owner. If using native, manually check the 8-byte discriminator before deserialization. Never trust raw AccountInfo for state accounts.

**Severity:** CRITICAL — enables complete state forgery.

---

## §3 — Arbitrary CPI target

**What:** The program makes a CPI where the target program ID comes from user-supplied accounts rather than being hardcoded or validated.

**Why critical:** If an attacker controls which program gets called, they control what code executes. The attacker deploys a malicious program that returns success for any input, and the caller trusts the result.

**Vulnerable pattern:**
```rust
// BAD: program ID comes from an unchecked account
let cpi_program = ctx.accounts.some_program.to_account_info();
invoke(&instruction, &[...], cpi_program)?;  // attacker controls this
```

**Detection:**
```bash
grep -rn "invoke\|invoke_signed" programs/*/src/
# For each invocation: trace where the program AccountInfo comes from
# Is it typed as Program<'info, SpecificProgram>? Or raw AccountInfo?
grep -rn "to_account_info" programs/*/src/ | grep -i "program"
```

**Fix (Anchor):**
```rust
// Program<'info, T> validates the program ID matches T::id()
pub token_program: Program<'info, Token>,
pub system_program: Program<'info, System>,
```

**Fix (native):**
```rust
if *program_account.key != expected_program::ID {
    return Err(ProgramError::IncorrectProgramId);
}
```

**Severity:** CRITICAL — attacker executes arbitrary code in your trust context.

---

## §4 — PDA seed manipulation

**What:** PDA derivation uses seeds that an attacker can control or collide, allowing them to produce a PDA that passes validation but represents wrong authority.

**Sub-classes:**
- **Non-canonical bump:** accepting a user-supplied bump instead of deriving with `find_program_address`
- **Seed collision:** using insufficiently unique seeds so different logical entities share a PDA
- **Missing seeds:** not including enough context in seeds (e.g., missing user pubkey, missing mint)
- **PDA authority sharing:** one PDA used as authority across unrelated domains

**Vulnerable pattern:**
```rust
// BAD: user supplies the bump, could use a non-canonical bump
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump = user_supplied_bump,  // WRONG: should be stored or derived
)]
pub vault: Account<'info, Vault>,

// BAD: seed collision — two different vaults could share seeds
#[account(seeds = [b"vault"], bump)]  // no user-specific seed!
```

**Detection:**
```bash
grep -rn "bump\s*=" programs/*/src/ | grep -v "bump\s*=\s*\w*\.bump"
# Look for seeds that don't include enough entropy
grep -rn "seeds\s*=" programs/*/src/
```

**Fix:**
```rust
// Store the canonical bump at init, reuse it
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump = vault.bump,  // stored canonical bump
)]

// Or let Anchor derive it
#[account(seeds = [b"vault", user.key().as_ref()], bump)]
```

**Severity:** CRITICAL for authority PDAs. HIGH for data PDAs.

---

## §5 — Missing owner checks

**What:** The program reads data from an account without verifying that the account is owned by the expected program. An attacker can create an account with arbitrary data owned by the System Program.

**Why dangerous:** Anchor's `Account<'info, T>` checks owner automatically. But `AccountInfo`, `UncheckedAccount`, or custom deserialization does not.

**Vulnerable pattern (native):**
```rust
// BAD: reads data but never checks account.owner
let state = MyState::try_from_slice(&account.data.borrow())?;
// attacker created this account with crafted data, owned by System Program
```

**Detection:**
```bash
grep -rn "\.owner" programs/*/src/  # see if owner is ever checked
# In native programs, every AccountInfo used for state must have owner check
```

**Fix (native):**
```rust
if account.owner != &my_program::ID {
    return Err(ProgramError::IllegalOwner);
}
```

**Severity:** HIGH — allows arbitrary state injection for native programs. Low for pure Anchor (auto-checked).
