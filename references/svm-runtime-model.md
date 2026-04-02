# SVM Runtime Model — Internals for Security Auditors

Understanding the Solana Virtual Machine at the level needed to find bugs that surface analysis misses.

## Table of Contents
1. [Execution model](#1-execution-model)
2. [Account model deep dive](#2-account-model-deep-dive)
3. [Transaction anatomy](#3-transaction-anatomy)
4. [CPI mechanics](#4-cpi-mechanics)
5. [Memory model and sBPF constraints](#5-memory-model-and-sbpf-constraints)
6. [Compute budget and resource limits](#6-compute-budget-and-resource-limits)
7. [Sysvar access patterns](#7-sysvar-access-patterns)
8. [Program deployment and upgradeability](#8-program-deployment-and-upgradeability)

---

## 1. Execution model

Solana programs are compiled to **sBPF** (Solana Berkeley Packet Filter) bytecode and executed by the runtime in a sandboxed VM. Key properties:

**Statelessness:** Programs are pure code. They have no persistent memory between invocations. ALL state lives in accounts. This means every instruction starts from scratch — the program reads accounts, processes logic, writes accounts.

**Determinism:** The same inputs must produce the same outputs. This is why floats are discouraged — sBPF float support is limited and non-deterministic across architectures.

**Parallelism:** Solana executes non-conflicting transactions in parallel. Two transactions conflict if they both write to the same account. The runtime enforces this through the transaction's account locks: read-only accounts can be shared, writable accounts are exclusive.

**Security implication:** The parallelism model means your program CANNOT assume ordering between transactions. Two transactions that both modify the same account will be serialized, but the order is non-deterministic. Race conditions between transactions are a design concern, not a bug class (the runtime handles it). Race conditions WITHIN a single transaction's instruction sequence are your problem.

**Atomic transactions:** All instructions in a transaction succeed or all fail. No partial execution. This is a double-edged sword: it enables flash loan attacks (borrow → exploit → repay, all atomic) but also means you can't leave state partially updated.

## 2. Account model deep dive

Every account on Solana has:

```
AccountInfo {
    key: &Pubkey,           // address
    is_signer: bool,        // signed this transaction?
    is_writable: bool,      // marked writable in transaction?
    lamports: &mut u64,     // balance (mutable via Rc<RefCell>)
    data: &mut [u8],        // arbitrary bytes (mutable via Rc<RefCell>)
    owner: &Pubkey,         // program that owns this account
    executable: bool,       // is this a program?
    rent_epoch: u64,        // deprecated but present
}
```

### Ownership rules (enforced by runtime)

1. **Only the owning program can modify `data`** — the runtime rejects writes from non-owners
2. **Only the owning program can debit `lamports`** — anyone can credit (add lamports)
3. **Only the System Program can assign a new `owner`** — ownership transfer requires System Program CPI
4. **Only the System Program can allocate `data` space** — initial allocation
5. **`is_signer` and `is_writable`** are set by the transaction and verified by the runtime — programs cannot forge them

### Security implications of ownership

The ownership model is WHY owner checks matter. Consider:
- Attacker creates account A with arbitrary data, owned by System Program
- Your program reads A assuming it's a valid state account
- If you don't check that A.owner == your_program_id, you're reading attacker-crafted data

Anchor's `Account<'info, T>` checks owner + discriminator automatically. Every use of raw `AccountInfo` or `UncheckedAccount` for state access is an owner check you must do manually.

### Account data layout

Programs choose their own data format. Conventions:
- **Anchor:** 8-byte discriminator (SHA-256 hash of `account:<TypeName>`) + Borsh-serialized fields
- **SPL Token:** Fixed layout defined by SPL standard (no discriminator, relies on owner = Token Program)
- **Native programs:** Borsh or custom binary layout

The discriminator prevents type confusion within a single program. But it doesn't prevent:
- Cross-program confusion (different programs may use same discriminator by coincidence)
- Accounts from a different Anchor program with same type name
- Raw accounts without discriminators

### Rent and account lifecycle

Accounts must maintain a minimum lamport balance for rent exemption (based on data size). If lamports drop below this threshold, the account can be garbage-collected by the runtime.

**Security-relevant behavior:**
- An account "closed" by draining lamports to zero can be recreated at the same address in the same transaction
- If the closing instruction doesn't zero the data AND reassign owner, a new account at that address inherits old bytes
- Anchor's `close` constraint handles this correctly (zeros discriminator, drains lamports, reassigns to System Program)

## 3. Transaction anatomy

```
Transaction {
    signatures: [Signature],
    message: {
        header: { num_required_sigs, num_readonly_signed, num_readonly_unsigned },
        account_keys: [Pubkey],       // ALL accounts referenced
        recent_blockhash: Hash,
        instructions: [CompiledInstruction {
            program_id_index: u8,     // index into account_keys
            accounts: [u8],           // indices into account_keys
            data: [u8],               // opaque instruction data
        }]
    }
}
```

### What the attacker controls

The attacker constructs the entire transaction:
- **Which accounts** are passed (in any order, any account)
- **Which accounts are signers** (they can sign for any keypair they hold)
- **Which accounts are writable** (they declare writability)
- **Instruction data** (arbitrary bytes)
- **Instruction ordering** (multiple instructions in one tx)

The attacker does NOT control:
- Whether an account is actually owned by a specific program (on-chain truth)
- Whether an account's data matches expectations (on-chain truth)
- The program's code (unless they control the upgrade authority)

This is the fundamental insight: **everything the program receives as input is attacker-controlled, except on-chain state that the runtime guarantees** (ownership, signer verification, account existence).

## 4. CPI mechanics

Cross-Program Invocation (CPI) is how programs call other programs.

```rust
// Basic CPI
invoke(
    &instruction,
    &[account1, account2, ...],
)?;

// CPI with PDA signer (program "signs" for its PDA)
invoke_signed(
    &instruction,
    &[account1, account2, ...],
    &[&[seed1, seed2, &bump_bytes]],
)?;
```

### Privilege propagation rules

1. **Signer privilege extends:** if account A is a signer in the outer instruction and passed to CPI, A is still a signer in the callee
2. **Writable privilege extends:** same as signer
3. **Privileges cannot be escalated:** CPI cannot make a non-signer into a signer (except PDA signing)
4. **PDA signing is program-scoped:** a program can only sign for PDAs derived from its own program ID

### CPI depth and reentrancy

- Max CPI depth: 4 levels
- **Direct self-recursion:** allowed (program A calls program A)
- **Indirect reentrancy:** blocked at runtime (A → B → A is rejected)
- Cross-CPI stack sharing: caller and callee share the same compute budget

### Security implications

**Stale state after CPI:** When program A calls program B, B may modify accounts that A already deserialized. After CPI returns, A's in-memory copies are stale. Anchor does NOT auto-refresh.

**PDA signing security:** The seeds passed to `invoke_signed` must exactly derive the PDA. If the seeds are wrong, the runtime rejects. But if your seed design is bad (collisions, insufficient entropy), the attacker may derive a valid PDA for the wrong logical entity.

**Account aliasing in CPI:** The same account can appear in both the outer instruction and the CPI instruction's account list. Mutations by the callee are visible to the caller only through re-reading the account data.

## 5. Memory model and sBPF constraints

### sBPF VM characteristics

- **Stack size:** 4KB per call frame. Deep recursion or large stack allocations fail.
- **Heap size:** 32KB default (can be increased with `request_heap_frame`). Heap is bump-allocated — no free/realloc.
- **No standard allocator:** `Vec`, `String`, and `HashMap` work but allocate from the limited heap.
- **No filesystem, no network, no threads** — the VM is fully sandboxed.

### Memory-safety implications

Programs compiled to sBPF from Rust retain Rust's memory safety guarantees in safe code. But:

- `unsafe` blocks bypass Rust's guarantees and sBPF provides no additional safety net
- `zero_copy` (memory-mapped) account access reinterprets raw bytes as structs — alignment must be correct
- Stack overflow is a runtime error (program aborts), not a memory corruption — but it's still a DoS vector
- The 32KB heap means allocating large vectors or strings can fail unexpectedly

### Serialization boundaries

Account data crosses a serialization boundary between the runtime and the program:
1. Runtime provides raw `&[u8]` slices backed by the account's data
2. Program deserializes (Borsh, zero-copy, or custom)
3. Program modifies the deserialized struct
4. Anchor serializes back on instruction exit

Bugs at this boundary:
- Reading past the end of account data (if data is smaller than expected struct)
- Writing past allocated space (if account was allocated too small)
- Misaligned access on zero-copy structs

## 6. Compute budget and resource limits

| Resource | Default limit |
|----------|--------------|
| Compute units | 200,000 per instruction (1,400,000 per tx with budget request) |
| Stack depth | 64 frames |
| CPI depth | 4 levels |
| Log data | 10KB per instruction |
| Account data | 10MB per account (realloc up to 10KB per instruction) |
| Instruction data | ~1232 bytes (limited by transaction size) |
| Accounts per tx | 64 (including programs) |

### Security relevance of compute limits

- **Compute exhaustion DoS:** if an attacker can force your program into a compute-expensive path on a required operation (e.g., liquidation), they can prevent that operation
- **Unbounded loops:** iterating over user-controlled data without bounds can exceed compute limits
- **Realloc limits:** account data can only grow 10KB per instruction, so realloc-dependent operations can fail if the account grew too much

## 7. Sysvar access patterns

Sysvars are special accounts providing cluster state:

| Sysvar | Security relevance |
|--------|--------------------|
| Clock | Timestamps and slots. Clock.unix_timestamp is NOT precise — it's leader-set. Don't use for tight deadlines. |
| Rent | Rent exemption calculations. Minimum balance depends on data size. |
| SlotHashes | Recent slot hashes. Occasionally used in randomness schemes (weak — manipulable by validators). |
| Instructions | Introspection sysvar. Lets a program read other instructions in the same transaction. Used for flash loan detection, but can be gamed. |
| EpochSchedule | Epoch boundaries. Rarely security-relevant. |

**Critical: sysvar account validation.** The Wormhole exploit happened because the program accepted a FAKE sysvar account. Always validate sysvar addresses:

```rust
// Anchor handles this:
pub clock: Sysvar<'info, Clock>,

// Native: must check the address
if *sysvar_account.key != solana_program::sysvar::clock::ID {
    return Err(ProgramError::InvalidArgument);
}
```

## 8. Program deployment and upgradeability

Solana programs are stored in special accounts with `executable: true`. The actual code lives in a separate ProgramData account.

**Upgrade mechanism:**
1. The upgrade authority calls BPF Loader's upgrade instruction
2. New bytecode replaces old bytecode in the ProgramData account
3. The program ID stays the same — all existing accounts still reference it
4. Next invocation uses the new code

**Security implications:**
- Upgrade authority has god-mode over the program. Compromised authority = complete control.
- Programs can be made immutable by setting upgrade authority to `None`
- There's no built-in timelock — upgrades are instant
- Verified builds (anchor verify) let users check that deployed code matches published source

**What to check:**
```bash
# Who controls the upgrade?
solana program show <PROGRAM_ID>

# Is it a multisig?
# Look up the authority address — is it a Squads multisig, Realms DAO, or EOA?

# Are verified builds published?
anchor verify <PROGRAM_ID> --provider.cluster mainnet
```
