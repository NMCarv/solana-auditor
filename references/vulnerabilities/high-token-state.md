# High: Token & State Validation (§6-§9, §22)

Token account validation, stale state after CPI, duplicate accounts, remaining_accounts, and Token-2022 extensions.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §6 — Token account validation gaps

**What:** The program interacts with SPL token accounts but fails to validate one or more of: mint, token authority, token program ID, or ATA derivation.

**Sub-classes:**
- **Wrong mint:** attacker passes a token account for a worthless mint
- **Wrong authority:** attacker passes a token account they control as "the vault"
- **Wrong token program:** with Token-2022, the token program itself is an input. Swapping Token for Token-2022 (or vice versa) with different extension behavior.
- **Missing ATA check:** attacker passes a non-ATA token account

**Vulnerable pattern:**
```rust
// BAD: no mint or authority constraint
#[account(mut)]
pub user_token_account: Account<'info, TokenAccount>,
```

**Detection:**
```bash
grep -rn "TokenAccount\|token::Token" programs/*/src/
# For each: verify token::mint, token::authority constraints exist
grep -rn "token::mint\|token::authority" programs/*/src/
# Check if Token-2022 is handled
grep -rn "token_2022\|Token2022\|spl_token_2022" programs/*/src/
```

**Fix (Anchor):**
```rust
#[account(
    mut,
    token::mint = expected_mint,
    token::authority = expected_authority,
)]
pub user_token_account: Account<'info, TokenAccount>,

// And validate the token program
pub token_program: Program<'info, Token>,  // or Interface<'info, TokenInterface>
```

**Severity:** HIGH to CRITICAL — wrong mint = drain with worthless tokens.

---

## §7 — Stale state after CPI

**What:** After a CPI call, the program continues using previously-deserialized account data without reloading. The CPI may have mutated that account's on-chain state.

**Why dangerous:** Anchor deserializes accounts at instruction entry. If a CPI changes an account's data, the in-memory copy is stale. Decisions based on stale data can be exploited.

**Vulnerable pattern:**
```rust
pub fn bad_instruction(ctx: Context<MyAccounts>) -> Result<()> {
    let balance_before = ctx.accounts.vault.amount;  // read before CPI

    // CPI that modifies vault
    transfer_tokens(&ctx, amount)?;

    // BAD: still using the pre-CPI value
    let balance_after = ctx.accounts.vault.amount;  // STALE!
    require!(balance_after == balance_before - amount);
}
```

**Detection:**
```bash
grep -rn "invoke\|invoke_signed\|CpiContext" programs/*/src/
# For each CPI: trace which accounts are read AFTER the CPI
# Check if reload() or refresh() is called
grep -rn "reload\|refresh" programs/*/src/
```

**Fix:**
```rust
// After CPI, reload affected accounts
ctx.accounts.vault.reload()?;
let balance_after = ctx.accounts.vault.amount;  // now fresh
```

**Severity:** HIGH — enables double-spend or invariant violations.

---

## §8 — Duplicate mutable accounts

**What:** An attacker passes the same account twice in different parameter positions, both marked as mutable. The program logic assumes they're distinct and double-counts or double-mutates.

**Vulnerable pattern:**
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    // What if from == to?
}
```

**Detection:**
```bash
# Find instructions with multiple mutable accounts of the same type
grep -rn "#\[account(mut" programs/*/src/
# Check if key inequality constraints exist
grep -rn "constraint\s*=" programs/*/src/ | grep "key"
```

**Fix:**
```rust
#[account(mut, constraint = from.key() != to.key() @ MyError::DuplicateAccounts)]
pub from: Account<'info, TokenAccount>,
#[account(mut)]
pub to: Account<'info, TokenAccount>,
```

**Severity:** HIGH — double-counting is a classic money-creation bug.

---

## §9 — Unchecked remaining_accounts

**What:** `ctx.remaining_accounts` is an untyped, unvalidated slice of accounts. Programs that iterate over it without per-account validation are processing attacker-controlled inputs.

**Vulnerable pattern:**
```rust
for account in ctx.remaining_accounts.iter() {
    // BAD: no owner check, no type check, no relationship check
    let data = SomeType::try_deserialize(&mut &account.data.borrow()[..])?;
    total += data.amount;
}
```

**Detection:**
```bash
grep -rn "remaining_accounts" programs/*/src/
# Every use must have manual validation
```

**Fix:** Validate every account from `remaining_accounts` exactly as rigorously as typed accounts — check owner, discriminator, seeds, and business relationships.

**Severity:** HIGH — it's an untyped trust boundary.

---

## §22 — Token-2022 extension incompatibility

**What:** Programs that interact with SPL tokens but do not account for Token-2022 extensions. Token-2022 introduces transfer hooks, transfer fees, permanent delegates, confidential transfers, CPI guard, and non-transferable tokens — each changing fundamental assumptions about how token transfers behave.

**Why dangerous:** A program built for SPL Token assumes: transfer(X) means the recipient gets X, transfers always succeed if balances suffice, and nobody else can move tokens from an account. Token-2022 breaks all three assumptions.

**Sub-classes:**

- **Transfer hooks:** Token-2022 mints can attach a transfer hook — an arbitrary program that executes on every transfer. If your program CPI's a token transfer, the hook runs with your signer seeds. A malicious mint's hook can re-enter, log data, or revert transfers selectively.
- **Transfer fees:** Mints with transfer fee extensions deduct a fee on every transfer. If the program assumes `amount_sent == amount_received`, accounting breaks. Vaults, pools, and escrows are especially vulnerable — the vault receives less than expected, creating a deficit an attacker can drain.
- **Permanent delegate:** A mint authority can set a permanent delegate that can transfer or burn tokens from ANY token account of that mint, at any time, without the holder's signature. Programs that custody tokens of arbitrary mints can have their vaults drained by the mint's permanent delegate.
- **CPI guard:** Token accounts with the CPI guard extension enabled reject transfers initiated via CPI. Programs that rely on CPI transfers to/from user accounts will silently fail if the user's account has CPI guard enabled.
- **Non-transferable tokens:** Soulbound tokens that reject all transfers. Programs assuming they can move tokens into/out of escrow will fail.
- **Interest-bearing tokens:** Display amount differs from actual amount. Programs reading the raw amount without accounting for interest accrual will compute wrong values.

**Vulnerable pattern:**
```rust
// BAD: assumes transfer amount == received amount
let amount = 1_000_000;
token::transfer(cpi_ctx, amount)?;
// vault.total_deposited += amount;  // WRONG if transfer fee exists

// BAD: accepts any mint without checking extensions
#[account(mut, token::mint = deposit_mint)]
pub vault: Account<'info, TokenAccount>,
// No check: does deposit_mint have transfer hooks? permanent delegate? fees?
```

**Detection:**
```bash
# Does the program handle Token-2022 at all?
grep -rn "token_2022\|Token2022\|spl_token_2022\|TokenInterface\|token_interface" programs/*/src/

# Does it check for transfer fees?
grep -rn "transfer_fee\|TransferFee\|fee_amount\|get_epoch_fee" programs/*/src/

# Does it check for transfer hooks?
grep -rn "transfer_hook\|TransferHook\|execute_with_extra" programs/*/src/

# Does it check for permanent delegate?
grep -rn "permanent_delegate\|PermanentDelegate" programs/*/src/

# Does it use CPI transfers that could be blocked by CPI guard?
grep -rn "invoke\|invoke_signed" programs/*/src/ | grep -i "transfer"

# Does it accept arbitrary mints?
grep -rn "pub.*mint\|deposit_mint\|token_mint" programs/*/src/
```

**Fix:**
```rust
// 1. Check for transfer fees and adjust accounting
use spl_token_2022::extension::transfer_fee::TransferFeeConfig;
let mint_data = mint_account.data.borrow();
let mint = StateWithExtensions::<Mint>::unpack(&mint_data)?;
if let Ok(fee_config) = mint.get_extension::<TransferFeeConfig>() {
    let epoch = Clock::get()?.epoch;
    let fee = fee_config.calculate_epoch_fee(epoch, amount).unwrap();
    let received = amount.checked_sub(fee).unwrap();
    // Use `received` for accounting, not `amount`
}

// 2. Reject mints with dangerous extensions (allowlist approach)
// Or: explicitly handle each extension the program supports
// Reject all others

// 3. Use TokenInterface instead of Token for Token-2022 compatibility
pub token_program: Interface<'info, TokenInterface>,

// 4. For permanent delegate: only accept mints from a known allowlist
// or verify the mint has no permanent delegate extension
```

**Audit checklist:**
- [ ] Does the program accept arbitrary mints, or only a known allowlist?
- [ ] If arbitrary: does it check for and handle transfer fees?
- [ ] If arbitrary: does it check for permanent delegate (vault drain risk)?
- [ ] If CPI transfers: does it account for CPI guard on user accounts?
- [ ] If transfer hooks exist: is the hook program audited? Can it re-enter?
- [ ] Are displayed amounts corrected for interest-bearing extensions?

**Severity:** HIGH to CRITICAL — transfer fees break accounting (vault drain), permanent delegate enables direct theft, transfer hooks enable arbitrary code execution during transfers.
