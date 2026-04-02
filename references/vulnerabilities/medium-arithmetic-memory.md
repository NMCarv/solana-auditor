# Medium: Arithmetic & Memory (§10-§15)

Integer math, type casting, zero-copy alignment, account closure, panic paths, and floating point.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §10 — Integer overflow/underflow

**What:** Arithmetic operations that wrap, panic, or produce incorrect results. Rust's release builds wrap on overflow by default (in Solana's case, the BPF target uses wrapping). Anchor can enable overflow checks via features.

**Vulnerable pattern:**
```rust
// BAD: wraps silently in BPF
let total = amount_a + amount_b;

// BAD: underflow
let remaining = total_supply - burn_amount;  // what if burn > supply?
```

**Detection:**
```bash
grep -rn "[+\-*/]" programs/*/src/lib.rs  # broad, then manually inspect
# Check if checked_add/checked_sub are used
grep -rn "checked_\|saturating_\|overflowing_" programs/*/src/
# Check Cargo.toml for overflow-checks feature
grep -rn "overflow-checks" Cargo.toml
```

**Fix:**
```rust
let total = amount_a.checked_add(amount_b).ok_or(MyError::Overflow)?;
let remaining = total_supply.checked_sub(burn_amount).ok_or(MyError::Underflow)?;
```

Also enable in Cargo.toml:
```toml
[profile.release]
overflow-checks = true
```

**Severity:** MEDIUM to CRITICAL depending on what the math controls.

---

## §11 — Unsafe type casting

**What:** Using Rust's `as` keyword for numeric conversions without checking for truncation or sign issues. `as` silently truncates or reinterprets.

**Vulnerable pattern:**
```rust
// BAD: u64 to u32 truncation
let amount_u32 = large_u64_value as u32;  // silently loses upper 32 bits

// BAD: i64 to u64 reinterpretation
let unsigned = signed_value as u64;  // negative becomes huge positive
```

**Detection:**
```bash
grep -rn "\bas\b" programs/*/src/ | grep -E "u8|u16|u32|u64|i8|i16|i32|i64|usize"
```

**Fix:**
```rust
let amount_u32: u32 = large_u64_value.try_into().map_err(|_| MyError::CastOverflow)?;
```

**Severity:** MEDIUM — truncation in amount calculations = money creation/destruction.

---

## §12 — Uninitialized / zero-copy alignment

**What:** Using `zero_copy` (memory-mapped) accounts without proper initialization, or reading from accounts that haven't been fully initialized.

**Vulnerable pattern:**
```rust
// BAD: zero_copy account read before init fills all fields
#[account(zero_copy)]
pub struct BigState {
    pub authority: Pubkey,
    pub data: [u8; 10000],
}
// If 'data' isn't fully written on init, it contains old account bytes
```

**Detection:**
```bash
grep -rn "zero_copy\|AccountLoader" programs/*/src/
# Verify init instructions write ALL fields
```

**Fix:** Always fully initialize all fields on account creation. For zero_copy, use `load_init()` on first use.

**Severity:** MEDIUM — can lead to reading garbage state or leftover data from previous accounts.

---

## §13 — Close account revival (rent)

**What:** When an account is "closed" by zeroing data and transferring lamports, it can be revived in the same transaction if it still has enough lamports for rent exemption. Also: if the account is not zeroed, the next user of that address inherits old data.

**Vulnerable pattern:**
```rust
// BAD: only transfers lamports, doesn't zero discriminator
**dest.lamports.borrow_mut() += account.lamports();
**account.lamports.borrow_mut() = 0;
// attacker re-funds the account in the same tx → it's "alive" with old data
```

**Detection:**
```bash
grep -rn "close\s*=" programs/*/src/
grep -rn "lamports" programs/*/src/ | grep "borrow_mut"
# Verify closed accounts have discriminator/data zeroed
```

**Fix (Anchor):** Use `close = destination` constraint, which zeroes discriminator, transfers lamports, and assigns owner to System Program. For native: zero all data, drain lamports, reassign owner.

**Severity:** MEDIUM to HIGH — enables state resurrection and replay attacks.

---

## §14 — Panic paths / DoS

**What:** Code paths that panic (unwrap, array out-of-bounds, slice failures) abort the transaction but can be triggered by attackers to DoS the protocol if the panicking path is required for normal operation.

**Vulnerable pattern:**
```rust
// BAD: unwrap on user-controlled data
let value = some_option.unwrap();

// BAD: index without bounds check
let item = my_vec[user_supplied_index];
```

**Detection:**
```bash
grep -rn "\.unwrap()" programs/*/src/
grep -rn "\[.*\]" programs/*/src/ | grep -v "account\|seeds\|constraint"
```

**Fix:** Replace `.unwrap()` with `.ok_or(MyError::...)?`. Use `.get()` for indexing. Never panic on user-controlled inputs.

**Severity:** LOW to MEDIUM — DoS is less severe than fund loss but can block liquidations, settlements, or time-sensitive operations.

---

## §15 — Floating point / precision loss

**What:** Using f64/f32 for financial calculations, or losing precision through integer division before multiplication.

**Vulnerable pattern:**
```rust
// BAD: float math for token amounts
let rate: f64 = 1.05;
let new_amount = (amount as f64 * rate) as u64;

// BAD: division before multiplication (integer truncation)
let fee = amount / 10000 * fee_bps;  // truncates to 0 for small amounts
```

**Detection:**
```bash
grep -rn "f32\|f64\|as f" programs/*/src/
# Look for division before multiplication
grep -rn "/" programs/*/src/ | grep -v "//" | grep -v "///"
```

**Fix:**
```rust
// Multiply first, divide last
let fee = amount.checked_mul(fee_bps)?.checked_div(10000)?;

// Use fixed-point libraries (e.g., spl-math, uint, fixed)
```

**Severity:** LOW to MEDIUM — rounding errors accumulate over time and can be MEV-extracted.
