# Rust + Solana Pitfalls — Language-Level Security Concerns

Rust's safety guarantees cover memory safety, not logic safety. On Solana, the constrained sBPF environment adds its own edge cases. This reference covers the Rust-specific issues that show up in Solana audits.

## Table of Contents
1. [Integer arithmetic](#1-integer-arithmetic)
2. [Type casting with `as`](#2-type-casting-with-as)
3. [Borsh serialization edge cases](#3-borsh-serialization-edge-cases)
4. [Borrow checker and RefCell panics](#4-borrow-checker-and-refcell-panics)
5. [Unsafe code patterns](#5-unsafe-code-patterns)
6. [Zero-copy and alignment](#6-zero-copy-and-alignment)
7. [Error handling anti-patterns](#7-error-handling-anti-patterns)
8. [String and Vec allocation traps](#8-string-and-vec-allocation-traps)
9. [Feature flags and conditional compilation](#9-feature-flags-and-conditional-compilation)

---

## 1. Integer arithmetic

### The sBPF overflow problem

In standard Rust, integer overflow panics in debug and wraps in release. On Solana's sBPF target, the behavior depends on configuration:

- **Default sBPF:** wrapping arithmetic (no panic on overflow)
- **With `overflow-checks = true` in Cargo.toml:** panics on overflow

Wrapping is dangerous because `u64::MAX + 1 = 0`. Panicking is less dangerous but still causes transaction failure (DoS vector).

### What to look for

```rust
// DANGER: all basic operators can overflow
let total = a + b;           // wraps if overflow-checks disabled
let diff = a - b;            // wraps (underflow)
let product = a * b;         // wraps
let shifted = a << n;        // can lose bits

// SAFE alternatives
let total = a.checked_add(b).ok_or(MyError::Overflow)?;
let diff = a.checked_sub(b).ok_or(MyError::Underflow)?;
let product = a.checked_mul(b).ok_or(MyError::Overflow)?;

// ACCEPTABLE for non-critical paths
let total = a.saturating_add(b);  // clamps at MAX instead of wrapping
```

### Division edge cases

```rust
// Integer division truncates toward zero
let result = 7u64 / 3;  // = 2, not 2.33

// Division by zero panics (always, regardless of overflow-checks)
let result = a / b;  // if b == 0: panic!

// Precision loss: multiply BEFORE dividing
let fee_bad = amount / 10000 * fee_bps;     // truncates early
let fee_good = amount.checked_mul(fee_bps)?.checked_div(10000)?;

// Rounding direction matters for financial calculations
// Truncation always rounds toward zero — protocol should round in its own favor
let fee = (amount * fee_bps + 9999) / 10000;  // round up
```

### Audit checklist for arithmetic

```bash
# Find all arithmetic operators in program code
grep -rn "[+\-*/]" programs/*/src/ | grep -v "//\|///\|#\[" | head -50

# Check for checked/saturating usage
grep -c "checked_" programs/*/src/lib.rs
grep -c "saturating_" programs/*/src/lib.rs

# Check Cargo.toml
grep "overflow-checks" programs/*/Cargo.toml
```

## 2. Type casting with `as`

Rust's `as` keyword is a silent footgun. It never fails — it truncates, wraps, or reinterprets.

### Dangerous patterns

```rust
// u64 → u32: truncation (upper 32 bits silently dropped)
let small: u32 = big_u64 as u32;
// If big_u64 = 4_294_967_296, small = 0

// i64 → u64: reinterpretation (negative becomes huge positive)
let unsigned: u64 = negative_i64 as u64;
// If negative_i64 = -1, unsigned = 18_446_744_073_709_551_615

// u64 → i64: can flip sign
let signed: i64 = huge_u64 as i64;
// If huge_u64 > i64::MAX, signed becomes negative

// f64 → u64: undefined behavior territory for out-of-range values
let amount: u64 = float_value as u64;  // NaN, infinity, negative → undefined

// usize ↔ u64: usize is 64-bit on Solana sBPF, but this is platform-dependent
let index: usize = user_u64 as usize;  // safe on Solana, fragile assumption
```

### Safe alternatives

```rust
// Use TryFrom/TryInto for fallible conversion
let small: u32 = big_u64.try_into().map_err(|_| MyError::CastOverflow)?;

// For signed ↔ unsigned
let unsigned: u64 = i64::try_into(signed_val).map_err(|_| MyError::NegativeValue)?;

// For float → integer (rare on Solana, but if you must)
if float_value.is_nan() || float_value < 0.0 || float_value > u64::MAX as f64 {
    return Err(MyError::InvalidConversion);
}
let amount = float_value as u64;
```

### Audit checklist

```bash
# Find every `as` cast involving numeric types
grep -rn "\bas\s\+[iu]\(8\|16\|32\|64\|128\|size\)" programs/*/src/
```

Every `as` cast between numeric types in financial or state-critical code is a potential finding.

## 3. Borsh serialization edge cases

### Data size mismatches

```rust
// Account data too small for struct → deserialization fails
// Account data too large → extra bytes silently ignored
// Account data exactly right → works

// DANGER: if you realloc an account and add fields to the struct,
// old accounts (created before realloc) may have smaller data
```

### Vec/String length manipulation

Borsh encodes Vec<T> as: `[u32 length][T; length]`. If the account data is crafted:

```rust
// Borsh reads the length prefix, then tries to read that many elements
// A malicious length prefix pointing past the end of data → deserialization error
// A length prefix of 0 when business logic expects non-empty → logic bug
```

### Enum discriminant issues

```rust
// Borsh enums use a u8 discriminant
#[derive(BorshDeserialize)]
enum Action {
    Deposit { amount: u64 },  // discriminant 0
    Withdraw { amount: u64 }, // discriminant 1
}
// A crafted byte of 2 → BorshError (good, fails safely)
// But: if you add variants later, old serialized data with new discriminants = confusion
```

### Audit checklist

```bash
# Look for manual Borsh deserialization (vs Anchor auto)
grep -rn "BorshDeserialize\|try_from_slice\|deserialize" programs/*/src/
# Check for account realloc
grep -rn "realloc" programs/*/src/
```

## 4. Borrow checker and RefCell panics

Solana account data is accessed through `Rc<RefCell<&mut [u8]>>`. RefCell enforces borrow rules at RUNTIME, not compile time.

### The RefCell panic trap

```rust
// This panics at runtime:
let data1 = account.try_borrow_data()?;  // immutable borrow
let data2 = account.try_borrow_mut_data()?;  // PANIC: already borrowed

// This also panics:
let mut data1 = account.try_borrow_mut_data()?;
let mut data2 = account.try_borrow_mut_data()?;  // PANIC: already mutably borrowed
```

**Security relevance:** RefCell panics are DoS vectors. If an attacker can trigger a RefCell double-borrow through instruction ordering or CPI, they can force transaction failure.

### The lamport borrow trap

```rust
// Lamports are also behind RefCell
**account.try_borrow_mut_lamports()? += amount;
// If lamports are already borrowed elsewhere → panic
```

### Audit checklist

```bash
grep -rn "borrow_mut\|try_borrow" programs/*/src/
# Check that borrows don't overlap within the same scope
```

## 5. Unsafe code patterns

`unsafe` in Solana programs is rare but when present demands scrutiny.

### Common unsafe patterns

```rust
// Reinterpreting bytes as struct (zero-copy style)
unsafe {
    let state = &mut *(data.as_mut_ptr() as *mut MyState);
}
// DANGER: alignment must be correct, size must match, padding must be valid

// Manual memory manipulation
unsafe {
    std::ptr::copy_nonoverlapping(src, dst, len);
}
// DANGER: overlapping regions, out-of-bounds, uninitialized memory
```

### What to check in unsafe blocks

1. Is the alignment guaranteed? (sBPF accounts may not be aligned to struct requirements)
2. Is the size correct? (reading past account data = out-of-bounds)
3. Are there aliasing violations? (two &mut references to same memory)
4. Is the cast valid? (transmuting to wrong type = instant UB)

### Audit checklist

```bash
grep -rn "unsafe" programs/*/src/
# Every unsafe block is a mandatory manual review item
```

## 6. Zero-copy and alignment

Anchor's `#[account(zero_copy)]` memory-maps account data directly as a struct. Fast but dangerous.

### Alignment requirements

```rust
#[account(zero_copy)]
#[repr(C)]  // required for zero-copy
pub struct BigState {
    pub authority: Pubkey,  // 32 bytes, aligned to 1
    pub value: u64,         // 8 bytes, aligned to 8
    pub flag: bool,         // 1 byte, aligned to 1
    // implicit padding: 7 bytes to align next field
    pub data: [u64; 100],   // 800 bytes, aligned to 8
}
```

**The trap:** if `repr(C)` is missing or if fields are ordered poorly, the struct layout won't match the account data layout, causing misaligned reads.

### Initialization issues

```rust
// zero_copy accounts start as all zeros (from account creation)
// If your struct has fields where 0 is a valid/meaningful value,
// you must explicitly initialize them or you get zero-initialized state

// Example: if authority is Pubkey::default() (all zeros), any check of
// has_one = authority will pass for the zero address
```

### Audit checklist

```bash
grep -rn "zero_copy\|AccountLoader" programs/*/src/
grep -rn "repr(C)" programs/*/src/
# Verify every zero_copy struct has repr(C) and correct field alignment
```

## 7. Error handling anti-patterns

### unwrap() and expect()

```rust
// BAD: panics on None/Err — DoS vector
let value = some_option.unwrap();
let data = result.expect("should not fail");

// GOOD: propagate as program error
let value = some_option.ok_or(MyError::MissingValue)?;
let data = result.map_err(|_| MyError::DeserializationFailed)?;
```

### Silent error swallowing

```rust
// BAD: ignores the error entirely
let _ = do_something_important();

// BAD: ok() discards the error
let maybe = risky_operation().ok();

// These can hide failed CPI calls, failed state updates, etc.
```

### Audit checklist

```bash
grep -rn "\.unwrap()" programs/*/src/
grep -rn "\.expect(" programs/*/src/
grep -rn "let _ =" programs/*/src/
grep -rn "\.ok()" programs/*/src/ | grep -v "ok_or"
```

## 8. String and Vec allocation traps

### Heap exhaustion

The sBPF heap is 32KB by default. Large Vec or String allocations can fail:

```rust
// DANGER: user-controlled size → heap exhaustion
let mut buf = vec![0u8; user_supplied_length as usize];

// DANGER: growing a Vec in a loop
let mut results = Vec::new();
for account in ctx.remaining_accounts.iter() {
    results.push(process(account)?);  // unbounded growth
}
```

### Audit checklist

```bash
grep -rn "Vec::new\|Vec::with_capacity\|vec!\[" programs/*/src/
grep -rn "String::new\|String::from\|format!" programs/*/src/
# Check if sizes are bounded
```

## 9. Feature flags and conditional compilation

### The cfg trap

```rust
#[cfg(not(feature = "production"))]
fn verify_authority(ctx: &Context) -> Result<()> {
    Ok(())  // skip auth in dev!
}

#[cfg(feature = "production")]
fn verify_authority(ctx: &Context) -> Result<()> {
    require!(ctx.accounts.authority.is_signer);
    Ok(())
}
```

If the program is accidentally deployed without the `production` feature → no auth checks.

### Audit checklist

```bash
grep -rn "#\[cfg(" programs/*/src/
grep -rn "feature\s*=" programs/*/Cargo.toml
# Verify which features are enabled in the build profile
# Check Anchor.toml for [programs.mainnet] features
```
