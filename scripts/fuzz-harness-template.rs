// Trident Fuzz Harness Template
// Copy this into trident-tests/fuzz_tests/fuzz_0/test_fuzz.rs
// Customize for the target program's instructions and accounts.

use trident_client::prelude::*;
use anchor_lang::prelude::*;

// Import target program
// use my_program;

// =============================================================================
// Account permutation strategy
// =============================================================================
// The core value of Solana fuzzing: test what happens when attackers substitute
// accounts. For each instruction, Trident will generate:
// - Valid accounts (happy path)
// - Wrong-owner accounts
// - Wrong-type accounts (type cosplay)
// - Duplicate accounts (same account in two slots)
// - Attacker-controlled accounts
// - Zero-balance accounts
// - Uninitialized accounts

// =============================================================================
// Invariants to check
// =============================================================================
// Define these based on the program's economic model. Common patterns:

/// Conservation: total value in system should not change except through
/// explicit mint/burn operations
fn check_conservation_invariant(
    pre_vault_balance: u64,
    pre_user_balance: u64,
    post_vault_balance: u64,
    post_user_balance: u64,
) -> bool {
    let pre_total = pre_vault_balance.checked_add(pre_user_balance);
    let post_total = post_vault_balance.checked_add(post_user_balance);
    match (pre_total, post_total) {
        (Some(pre), Some(post)) => pre == post,
        _ => false, // overflow = invariant violation
    }
}

/// No value creation: withdrawing should never yield more than deposited
fn check_no_value_creation(
    deposited: u64,
    withdrawn: u64,
) -> bool {
    withdrawn <= deposited
}

/// Authority integrity: only authorized signers can modify state
fn check_authority_invariant(
    expected_authority: Pubkey,
    actual_signer: Pubkey,
    state_was_modified: bool,
) -> bool {
    if state_was_modified {
        expected_authority == actual_signer
    } else {
        true // no modification, no concern
    }
}

// =============================================================================
// Fuzz instruction builders
// =============================================================================
// Implement FuzzInstruction for each instruction you want to fuzz.
// Trident will generate random sequences of these instructions.

// Example structure (customize for your program):
//
// #[derive(Arbitrary)]
// pub struct FuzzDeposit {
//     pub amount: u64,
//     // Trident fuzzes account selection automatically
// }
//
// impl FuzzInstruction for FuzzDeposit {
//     fn build(&self, ctx: &mut FuzzContext) -> Option<Instruction> {
//         // Build the instruction with fuzzed accounts
//         Some(Instruction {
//             program_id: my_program::ID,
//             accounts: vec![
//                 AccountMeta::new(ctx.pick_account("user"), true),
//                 AccountMeta::new(ctx.pick_account("vault"), false),
//                 AccountMeta::new(ctx.pick_account("user_token"), false),
//                 AccountMeta::new_readonly(ctx.pick_account("token_program"), false),
//             ],
//             data: my_program::instruction::Deposit {
//                 amount: self.amount,
//             }.data(),
//         })
//     }
//
//     fn check(&self, pre: &Snapshot, post: &Snapshot) -> Result<()> {
//         // Check invariants after instruction execution
//         assert!(check_conservation_invariant(
//             pre.vault_balance,
//             pre.user_balance,
//             post.vault_balance,
//             post.user_balance,
//         ));
//         Ok(())
//     }
// }

// =============================================================================
// Account generation strategies
// =============================================================================
// For maximum coverage, generate accounts with these properties:

// 1. Normal accounts (expected state)
// 2. Empty accounts (zero data, minimum lamports)
// 3. Accounts owned by wrong program
// 4. Accounts with valid discriminator but wrong data
// 5. Accounts with data size mismatch
// 6. Token accounts with wrong mint
// 7. Token accounts with wrong authority
// 8. PDAs with non-canonical bumps (if program accepts user bump)
// 9. The SAME account passed in multiple positions

// =============================================================================
// Running the fuzzer
// =============================================================================
// trident fuzz run-harnessed fuzz_0
//
// Options:
//   --timeout 300           # seconds per run
//   --iterations 1000000    # max iterations
//   --corpus-dir ./corpus   # save interesting inputs
//
// Crashes are saved in:
//   trident-tests/fuzz_tests/fuzzing/hfuzz_workspace/fuzz_0/
//
// To reproduce a crash:
//   trident fuzz run-harnessed fuzz_0 --input <crash-file>
