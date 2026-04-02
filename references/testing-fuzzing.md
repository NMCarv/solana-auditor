# Testing and Fuzzing — Trident, LiteSVM, Mollusk, proptest

Operational guide for testing Solana programs as a security auditor. Covers tool setup, harness templates, and what to fuzz.

## Table of Contents
1. [Testing philosophy for auditors](#1-testing-philosophy-for-auditors)
2. [Anchor test framework](#2-anchor-test-framework)
3. [LiteSVM — lightweight local validator](#3-litesvm--lightweight-local-validator)
4. [Mollusk — unit-level instruction testing](#4-mollusk--unit-level-instruction-testing)
5. [Trident — Anchor fuzzer](#5-trident--anchor-fuzzer)
6. [proptest — property-based testing](#6-proptest--property-based-testing)
7. [Exploit PoC templates](#7-exploit-poc-templates)
8. [Invariant design](#8-invariant-design)

---

## 1. Testing philosophy for auditors

Auditor testing has different goals than developer testing:

**Developer testing:** "Does my code work correctly for expected inputs?"
**Auditor testing:** "What inputs break the program's invariants?"

Priority order:
1. **PoC for confirmed findings** — prove the exploit works, quantify impact
2. **Invariant fuzzing** — discover unknown bugs through account/input permutation
3. **Property testing** — find arithmetic edge cases
4. **Negative testing** — verify that invalid operations fail correctly

The key insight: Solana's attack surface is the **account permutation space**. An instruction that takes 5 accounts has billions of possible account combinations. Fuzzing over this space is where tools like Trident earn their keep.

## 2. Anchor test framework

Standard Anchor tests use TypeScript/JavaScript with `@coral-xyz/anchor`.

### Setup
```bash
# In the project directory
anchor build
anchor test  # runs tests in tests/*.ts
```

### Exploit PoC template (TypeScript)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { MyProgram } from "../target/types/my_program";
import { assert } from "chai";

describe("exploit_poc", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.MyProgram as Program<MyProgram>;

  it("demonstrates [VULNERABILITY_NAME]", async () => {
    // 1. Set up legitimate state
    const authority = anchor.web3.Keypair.generate();
    // ... initialize accounts normally ...

    // 2. Prepare attack
    const attacker = anchor.web3.Keypair.generate();
    // ... create malicious accounts or conditions ...

    // 3. Execute exploit
    try {
      await program.methods
        .vulnerableInstruction(/* args */)
        .accounts({
          // Pass attacker-controlled accounts
          authority: attacker.publicKey,  // wrong authority
          // ... other accounts ...
        })
        .signers([attacker])
        .rpc();

      // 4. If we get here, the exploit succeeded
      // Verify the impact
      const state = await program.account.myState.fetch(stateAddress);
      assert.notEqual(state.value, expectedValue, "State was corrupted");
      console.log("EXPLOIT SUCCEEDED: [describe impact]");
    } catch (e) {
      // If the program correctly rejects: exploit failed
      console.log("Exploit blocked:", e.message);
      assert.fail("Expected exploit to succeed but it was blocked");
    }
  });
});
```

### Common test patterns for auditing

```typescript
// Test: duplicate mutable accounts
it("should reject duplicate mutable accounts", async () => {
  const sameAccount = /* token account */;
  try {
    await program.methods.transfer(amount).accounts({
      from: sameAccount,
      to: sameAccount,  // same account!
    }).rpc();
    assert.fail("Should have rejected duplicate accounts");
  } catch (e) {
    // Expected: program should reject
  }
});

// Test: wrong mint
it("should reject wrong token mint", async () => {
  const fakeMint = await createMint(/* different mint */);
  const fakeTokenAccount = await createTokenAccount(fakeMint);
  try {
    await program.methods.deposit(amount).accounts({
      userToken: fakeTokenAccount,  // wrong mint
    }).rpc();
    assert.fail("Should have rejected wrong mint");
  } catch (e) {
    // Expected
  }
});

// Test: non-signer calling admin function
it("should reject unauthorized admin calls", async () => {
  const attacker = Keypair.generate();
  try {
    await program.methods.updateConfig(newParams).accounts({
      authority: attacker.publicKey,
      config: configAddress,
    }).signers([attacker]).rpc();
    assert.fail("Should have rejected unauthorized call");
  } catch (e) {
    // Expected
  }
});
```

## 3. LiteSVM — lightweight local validator

LiteSVM is a fast, minimal SVM implementation for testing. Much faster than starting a full local validator.

### Setup
```toml
# Cargo.toml (dev-dependencies)
[dev-dependencies]
litesvm = "0.3"
solana-sdk = "2.0"
```

### Basic harness
```rust
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};

#[test]
fn test_exploit_with_litesvm() {
    let mut svm = LiteSVM::new();

    // Deploy program
    let program_id = Pubkey::new_unique();
    let program_bytes = std::fs::read("target/deploy/my_program.so").unwrap();
    svm.add_program(program_id, &program_bytes);

    // Create accounts
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();

    // Build exploit instruction
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),  // signer
            // ... other accounts
        ],
        data: vec![/* instruction data */],
    };

    // Execute
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    // Analyze result: did it succeed when it shouldn't?
}
```

### Advantages for auditing
- **Speed:** ~1000x faster than local validator for simple tests
- **Determinism:** no background processes, no slot progression unless you advance
- **Control:** set account state directly, no transaction overhead for setup
- **Isolation:** each test starts clean

### When to use LiteSVM vs Anchor tests
- **LiteSVM:** Rust-based PoCs, fuzzing harnesses, raw instruction testing, testing native programs
- **Anchor tests:** TypeScript PoCs, testing Anchor IDL interactions, integration tests

## 4. Mollusk — unit-level instruction testing

Mollusk processes a single instruction in isolation — no transaction wrapping, no blockhash. Even lighter than LiteSVM.

### Setup
```toml
[dev-dependencies]
mollusk-svm = "0.1"
```

### Basic harness
```rust
use mollusk_svm::Mollusk;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

#[test]
fn test_instruction_level() {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, "target/deploy/my_program");

    // Create input accounts with specific state
    let authority = Pubkey::new_unique();
    let state_account = Pubkey::new_unique();

    let accounts = vec![
        (authority, Account {
            lamports: 1_000_000,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        }),
        (state_account, Account {
            lamports: 5_000_000,
            data: /* serialized state data */,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        }),
    ];

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(state_account, false),
        ],
        data: /* instruction data */,
    };

    let result = mollusk.process_instruction(&instruction, &accounts);

    // Check result
    match result {
        Ok(accounts_after) => {
            // Verify state changes
        },
        Err(e) => {
            // Should it have failed?
        }
    }
}
```

### Advantages
- **Fastest possible:** no transaction, no blockhash, single instruction
- **Direct state manipulation:** set account data byte-by-byte
- **Perfect for unit testing specific vulnerability patterns**

## 5. Trident — Anchor fuzzer

Trident is purpose-built for fuzzing Anchor programs. It generates random instruction sequences with random accounts and looks for invariant violations.

### Setup
```bash
# Install Trident
cargo install trident-cli

# Initialize in project
cd my-anchor-project
trident init
```

### Configuration (Trident.toml)
```toml
[fuzz]
fuzzing_with_stats = true
allow_duplicate_txs = false

[[fuzz.programs]]
program_name = "my_program"

[fuzz.instructions]
# Fuzz all instructions by default
# Or specify which to fuzz and their account constraints
```

### Fuzz harness template
```rust
// trident-tests/fuzz_tests/fuzz_0/test_fuzz.rs
use trident_client::*;
use my_program::state::*;

impl FuzzDataBuilder<my_program::instruction::Deposit> for FuzzAccounts {
    fn build(
        &self,
        client: &mut impl FuzzClient,
        fuzz_accounts: &mut FuzzAccounts,
    ) -> Result<Instruction> {
        // Trident will fuzz the parameters and account combinations
        let user = fuzz_accounts.user.get_or_create(client);
        let vault = fuzz_accounts.vault.get_or_create(client);

        Ok(Instruction {
            program_id: my_program::ID,
            accounts: vec![/* constructed from fuzz_accounts */],
            data: /* fuzzed instruction data */,
        })
    }
}

// Define invariants
#[invariant]
fn total_supply_invariant(pre: &Snapshot, post: &Snapshot) -> bool {
    // Total tokens in system should not change (only redistribute)
    let pre_total = pre.vault_balance + pre.user_balance;
    let post_total = post.vault_balance + post.user_balance;
    pre_total == post_total
}
```

### What to fuzz

1. **Account permutations:** pass wrong accounts, duplicate accounts, attacker-owned accounts
2. **Instruction ordering:** random sequences of instructions (init → deposit → withdraw → attack)
3. **Boundary values:** u64::MAX, 0, 1, amounts near overflow thresholds
4. **Concurrent operations:** interleave different users' operations

### Running
```bash
trident fuzz run-harnessed fuzz_0
# Runs until crash or timeout
# Crashes are saved in trident-tests/fuzz_tests/fuzzing/hfuzz_workspace/
```

## 6. proptest — property-based testing

proptest generates random inputs to test properties (invariants) of pure functions. Ideal for arithmetic code.

### Setup
```toml
[dev-dependencies]
proptest = "1.4"
```

### Harness template
```rust
use proptest::prelude::*;

// Test fee calculation properties
proptest! {
    #[test]
    fn fee_never_exceeds_amount(
        amount in 0u64..=u64::MAX,
        fee_bps in 0u16..=10000u16,
    ) {
        let fee = calculate_fee(amount, fee_bps as u64);
        prop_assert!(fee <= amount, "Fee {} exceeded amount {}", fee, amount);
    }

    #[test]
    fn deposit_withdraw_roundtrip(
        deposit_amount in 1u64..=1_000_000_000u64,
        shares_supply in 1u64..=1_000_000_000u64,
        total_deposits in 1u64..=1_000_000_000u64,
    ) {
        // Deposit amount → shares → back to amount should not create value
        let shares = deposit_to_shares(deposit_amount, shares_supply, total_deposits);
        let withdrawn = shares_to_withdraw(shares, shares_supply + shares, total_deposits + deposit_amount);
        prop_assert!(
            withdrawn <= deposit_amount,
            "Roundtrip created value: deposited {}, withdrew {}",
            deposit_amount, withdrawn
        );
    }

    #[test]
    fn no_overflow_in_interest_calculation(
        principal in 0u64..=u64::MAX / 2,
        rate_bps in 0u64..=50000u64,
        time_seconds in 0u64..=31_536_000u64,  // max 1 year
    ) {
        // Should not panic
        let result = calculate_interest(principal, rate_bps, time_seconds);
        prop_assert!(result.is_ok(), "Overflow for principal={}, rate={}, time={}",
            principal, rate_bps, time_seconds);
    }
}
```

### What to property-test

1. **Fee calculations:** fee ≤ amount, fee proportional to rate, no overflow
2. **Share/token conversions:** roundtrip doesn't create value, no division by zero
3. **Interest accrual:** no overflow, correct direction, bounded
4. **Price calculations:** no precision loss > threshold, monotonic where expected
5. **Liquidation math:** health factor computed correctly, no edge case where unhealthy account appears healthy

## 7. Exploit PoC templates

### Template: Missing signer check PoC
```typescript
it("exploit: unauthorized config change", async () => {
  // Setup: create legitimate config
  await program.methods.initialize(params).accounts({
    authority: admin.publicKey,
    config: configPda,
  }).signers([admin]).rpc();

  // Attack: call update with attacker signer
  const attacker = Keypair.generate();
  await airdrop(attacker.publicKey);

  const tx = await program.methods.updateConfig(maliciousParams).accounts({
    authority: attacker.publicKey,
    config: configPda,
  }).signers([attacker]).rpc();

  // Verify impact
  const config = await program.account.config.fetch(configPda);
  assert.deepEqual(config.params, maliciousParams, "Config was modified by attacker");
});
```

### Template: Duplicate mutable account PoC
```typescript
it("exploit: double-count via duplicate accounts", async () => {
  const userToken = await createTokenAccount(user, mint, 1000);

  // Attack: pass same account as both source and destination
  const tx = await program.methods.transfer(new BN(500)).accounts({
    from: userToken,
    to: userToken,  // same account!
    authority: user.publicKey,
  }).signers([user]).rpc();

  const balance = await getTokenBalance(userToken);
  // If balance > 1000, the duplicate was not caught
});
```

### Template: Flash loan attack PoC
```typescript
it("exploit: flash loan oracle manipulation", async () => {
  // 1. Flash borrow large amount
  const flashBorrowIx = await flashLoanProgram.methods.borrow(largeAmount).instruction();

  // 2. Swap to manipulate price
  const swapIx = await dex.methods.swap(largeAmount, tokenA, tokenB).instruction();

  // 3. Exploit the manipulated price
  const exploitIx = await targetProgram.methods.borrow(/* using inflated collateral */).instruction();

  // 4. Swap back
  const swapBackIx = await dex.methods.swap(amount, tokenB, tokenA).instruction();

  // 5. Repay flash loan
  const repayIx = await flashLoanProgram.methods.repay(largeAmount).instruction();

  // All in one atomic transaction
  const tx = new Transaction().add(flashBorrowIx, swapIx, exploitIx, swapBackIx, repayIx);
  await sendTransaction(tx);
});
```

## 8. Invariant design

The most important part of fuzzing is choosing the right invariants. Here's a framework:

### Conservation invariants
- Total tokens in system = constant (no creation/destruction outside mint/burn)
- Total shares ≤ total deposits (no share inflation without deposits)
- Sum of user balances = vault balance

### Monotonicity invariants
- Interest accrual only increases debt
- Fees only decrease user balances
- Collateral ratio can only worsen via borrowing (not via oracle update alone)

### Access control invariants
- Only admin can modify config
- Only position owner can withdraw
- Permissionless instructions cannot transfer ownership

### Safety invariants
- No account has negative balance (underflow)
- No amount exceeds vault balance (overdraft)
- Health factor computation is consistent with liquidation threshold
- Closed accounts stay closed (no revival)

### Fairness invariants
- Identical operations produce identical results regardless of ordering
- First depositor doesn't get advantage over later depositors
- Withdrawal amount ≤ deposit amount (no value creation through rounding)
