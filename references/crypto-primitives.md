# Cryptographic Primitives — From Ed25519 to ZK Proofs

Deep reference for auditing cryptographic usage in Solana programs. Covers the primitives themselves, common misuse patterns, and what to look for in code.

## Table of Contents
1. [Ed25519 and signatures on Solana](#1-ed25519-and-signatures-on-solana)
2. [SHA-256 and hashing](#2-sha-256-and-hashing)
3. [PDA derivation internals](#3-pda-derivation-internals)
4. [Groth16 proof verification](#4-groth16-proof-verification)
5. [PLONK and universal SNARKs](#5-plonk-and-universal-snarks)
6. [Bulletproofs and range proofs](#6-bulletproofs-and-range-proofs)
7. [STARKs on Solana](#7-starks-on-solana)
8. [Signature verification via sysvar introspection](#8-signature-verification-via-sysvar-introspection)
9. [Common cryptographic misuse patterns](#9-common-cryptographic-misuse-patterns)

---

## 1. Ed25519 and signatures on Solana

### How Solana uses Ed25519

Solana uses Ed25519 (Curve25519 Edwards form) for all keypair operations:
- Transaction signing: every signer produces an Ed25519 signature
- The runtime verifies signatures before executing any instruction
- Programs themselves generally don't verify signatures — the runtime already did

**Key properties of Ed25519:**
- 32-byte public keys, 64-byte signatures
- Deterministic: same message + key → same signature (uses SHA-512 internally for nonce derivation)
- Not malleable in the strict sense (unlike ECDSA), but cofactor considerations exist
- Batch-verifiable

### Ed25519 precompile program

Solana provides a native Ed25519 signature verification precompile at `Ed25519Program`. Programs can verify arbitrary Ed25519 signatures (not just transaction signers) by:

1. Including an Ed25519Program instruction in the transaction with the signature data
2. Using the Instructions sysvar to introspect and verify the signature was checked

**Security pitfalls:**
```rust
// The Ed25519 precompile instruction must be in the SAME transaction
// The program reads the Instructions sysvar to verify it exists

// DANGER: must verify the instruction index and program ID
// Wormhole was exploited because it accepted a fake sysvar account
// instead of validating it was the real Instructions sysvar
```

### Signature malleability considerations

Ed25519 as specified by RFC 8032 rejects non-canonical encodings, but:
- Some implementations accept both `s` and `-s` (low-S/high-S)
- Solana's runtime uses `ed25519-dalek` which checks for canonical encoding
- If a program implements custom verification, it must replicate these checks

**Audit check:** Does the program use the Ed25519 precompile correctly, or does it implement custom signature verification? Custom = high risk.

## 2. SHA-256 and hashing

### Usage in Solana

- **Account discriminators:** Anchor uses `SHA-256("account:<TypeName>")[..8]`
- **PDA derivation:** `SHA-256(seeds || program_id || "ProgramDerivedAddress")`
- **Merkle proofs:** many programs verify membership via SHA-256 Merkle trees
- **Hash commitments:** commit-reveal schemes for randomness, auctions

### Security considerations

**Preimage resistance:** SHA-256 has 256-bit preimage resistance. Safe for all current applications.

**Collision resistance:** 128-bit collision resistance. Relevant when two different inputs could produce the same hash (discriminator collisions, Merkle tree second-preimage attacks).

**Length extension attacks:** SHA-256 is vulnerable to length extension. If a program uses `SHA-256(secret || message)` as a MAC, an attacker can compute `SHA-256(secret || message || padding || extension)` without knowing the secret. Use HMAC instead.

**Discriminator collisions:** The 8-byte (64-bit) Anchor discriminator has ~2^32 collision resistance (birthday bound). For programs with many account types, this is theoretically concerning but practically safe for < 100 types.

### Merkle proof verification

```rust
// Common pattern: verify a leaf is in a Merkle tree
fn verify_proof(root: [u8; 32], leaf: [u8; 32], proof: Vec<[u8; 32]>) -> bool {
    let mut current = leaf;
    for node in proof {
        current = if current <= node {
            hash(current, node)
        } else {
            hash(node, current)
        };
    }
    current == root
}

// DANGER: second-preimage attacks
// If an internal node has the same format as a leaf, attacker can submit
// an internal node as a leaf. Fix: domain-separate leaves from internal nodes.
// e.g., leaf = hash(0x00 || data), node = hash(0x01 || left || right)
```

### Audit checklist

```bash
grep -rn "hash\|sha256\|Sha256\|keccak" programs/*/src/
grep -rn "merkle\|proof\|verify_proof" programs/*/src/
# Check for length extension vulnerability (hash(secret || data))
# Check for domain separation in Merkle trees
```

## 3. PDA derivation internals

### How PDAs work

A PDA (Program Derived Address) is an address that does NOT lie on the Ed25519 curve. This means no private key exists for it — only the program can "sign" for it via `invoke_signed`.

**Derivation algorithm:**
```
for bump in (0..=255).rev() {
    candidate = SHA-256(seeds || [bump] || program_id || "ProgramDerivedAddress")
    if candidate is NOT on the Ed25519 curve:
        return (candidate, bump)  // this is the PDA with canonical bump
}
// If all 256 bumps produce on-curve points: derivation fails (astronomically unlikely)
```

`find_program_address` returns the canonical bump (the highest bump that works). `create_program_address` takes a specific bump.

### Security-critical details

**Canonical bump:** `find_program_address` tries bumps from 255 down. The first (highest) working bump is "canonical." If a program accepts a user-supplied bump, the attacker might use a non-canonical bump to derive a different PDA.

```rust
// BAD: user supplies bump
let (pda, _) = Pubkey::create_program_address(
    &[b"vault", &user_key, &[user_supplied_bump]],
    program_id
)?;

// GOOD: derive canonical or use stored bump
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", &user_key],
    program_id
);
// Store bump on first use, verify stored bump on subsequent calls
```

**Seed collision:** If seeds don't uniquely identify the entity, different logical entities share a PDA.

```rust
// BAD: only uses "vault" — one PDA for the entire program
seeds = [b"vault"]

// GOOD: includes user-specific and context-specific seeds
seeds = [b"vault", user.key().as_ref(), mint.key().as_ref()]
```

**PDA authority scope:** A PDA derived from program A should never be used as authority in an unrelated context for program B. The PDA's security is scoped to program A's seed validation.

### Audit checklist

```bash
grep -rn "seeds\s*=" programs/*/src/
grep -rn "find_program_address\|create_program_address" programs/*/src/
# For each PDA:
# 1. Are seeds sufficiently unique?
# 2. Is the bump canonical (or stored at init)?
# 3. Is the PDA used only within its intended authority scope?
```

## 4. Groth16 proof verification

### What is Groth16?

Groth16 is a zk-SNARK proving system: succinct, non-interactive zero-knowledge proofs. The prover produces a short proof (~192 bytes for BN254) that a verifier can check in constant time without learning the witness (private inputs).

**Solana relevance:** Groth16 is used in:
- **Light Protocol:** compressed accounts with zero-knowledge proofs
- **ZK Compression:** Solana's native compressed state
- **Privacy protocols:** shielded transfers, anonymous credentials
- Solana has a native **alt_bn128** precompile for pairing checks

### Trusted setup

Groth16 requires a circuit-specific trusted setup (structured reference string / CRS). If the setup ceremony is compromised (toxic waste not destroyed), fake proofs can be created.

**Audit questions:**
1. Was a multi-party computation (MPC) ceremony used for setup?
2. How many participants? (more = harder to collude)
3. Is the ceremony verifiable?
4. Can the setup be updated (Groth16: no, unlike PLONK)?

### Verification in Solana programs

```rust
// Using the alt_bn128 precompile for pairing checks
// Groth16 verification = one pairing check:
// e(A, B) = e(α, β) · e(vk_input, γ) · e(C, δ)

// Programs typically:
// 1. Receive proof (A, B, C) and public inputs from the instruction
// 2. Compute the linear combination of public inputs with verification key
// 3. Call the alt_bn128_pairing precompile
// 4. Check the result is the identity element
```

### Security concerns

- **Proof malleability:** Groth16 proofs are malleable — given a valid proof, one can create a different valid proof for the same statement. If the program uses proofs as unique identifiers or replay protection, this is exploitable.
- **Public input validation:** The verifier must validate that public inputs are in the correct field (Fr for BN254). Inputs outside the field can cause the verification to accept invalid proofs.
- **Subgroup checks:** Points (A, B, C) must be in the correct subgroup of the curve. Missing subgroup checks → small-subgroup attacks.
- **Curve security:** BN254 has ~100-bit security (recent discrete log improvements). For long-term security, some protocols are moving to BLS12-381 (~128-bit).

### Audit checklist

```bash
grep -rn "alt_bn128\|pairing\|groth16\|bn254\|bls12" programs/*/src/
grep -rn "proof\|verify.*proof\|zk\|zero.knowledge" programs/*/src/
# Check: are public inputs validated (field membership)?
# Check: are proof points checked for subgroup membership?
# Check: is proof replay protection implemented?
# Check: trusted setup documentation
```

## 5. PLONK and universal SNARKs

### What is PLONK?

PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge) is a universal SNARK — one trusted setup works for any circuit (up to a size bound), unlike Groth16's circuit-specific setup.

**Variants relevant to Solana:**
- **TurboPLONK / UltraPLONK:** custom gates, lookup tables, faster proving
- **Halo2 (by Zcash/ECC):** PLONK variant with recursive proof composition, no trusted setup (using IPA commitment)
- **fflonk:** optimized PLONK variant (used by Polygon zkEVM)

### Security concerns specific to PLONK

- **KZG commitment scheme (standard PLONK):** requires trusted setup (universal, not circuit-specific). Ethereum's Powers of Tau ceremony is often reused.
- **IPA commitment (Halo2):** no trusted setup, but larger proofs and slower verification
- **Lookup arguments:** custom lookup tables must be committed correctly; a malicious prover could exploit incorrectly-constructed lookup tables
- **Circuit correctness:** the constraint system itself must correctly encode the intended computation. An under-constrained circuit accepts invalid witnesses.

### Audit approach

For PLONK-based programs:
1. Verify the constraint system matches the specification
2. Check that ALL witness values are constrained (under-constrained = soundness bug)
3. Verify commitment scheme parameters (trusted setup, or IPA parameters)
4. Check that verification key is hardcoded or derived from trusted source
5. Test with invalid proofs to ensure rejection

## 6. Bulletproofs and range proofs

### What are Bulletproofs?

Bulletproofs are short non-interactive zero-knowledge proofs, particularly efficient for range proofs (proving a value lies in [0, 2^n) without revealing it). No trusted setup required.

**Solana relevance:**
- **SPL Confidential Transfers (Token-2022):** uses Bulletproofs-style range proofs to prove encrypted transfer amounts are non-negative
- **Privacy protocols:** balance proofs, credential ranges

### Security concerns

- **Range proof soundness:** the proof must actually constrain the value to the claimed range. Incorrect implementation can accept values outside the range (allowing negative amounts → money creation).
- **Pedersen commitment binding:** Bulletproofs use Pedersen commitments. The commitment scheme is computationally binding (under discrete log assumption) but perfectly hiding. If the discrete log is broken, commitments can be opened to different values.
- **Batch verification:** Bulletproofs can be batch-verified for efficiency, but the batch verification must use fresh random challenges. Reusing challenges → forgery.
- **Inner product argument:** the core of Bulletproofs. Verification must check all rounds correctly.

### Audit checklist for confidential transfers

```bash
grep -rn "confidential\|bulletproof\|range_proof\|pedersen" programs/*/src/
# If using Token-2022 confidential transfers:
# - Verify the program correctly handles encrypted balances
# - Check that proof verification is not skipped or shortcutted
# - Verify that the encryption and commitment schemes use consistent parameters
```

## 7. STARKs on Solana

### What are STARKs?

STARKs (Scalable Transparent ARguments of Knowledge) are proof systems that:
- Need no trusted setup (transparent)
- Use hash functions instead of elliptic curves (quantum-resistant)
- Have larger proofs than SNARKs but faster proving

**Solana relevance:**
- **Cairo/Starknet bridges:** verifying STARK proofs on Solana for cross-chain state
- **ZK coprocessors:** offchain computation with on-chain STARK verification
- **Future:** Solana considering native STARK verification support

### Security concerns

- **Hash function choice:** STARK security depends on the collision resistance of the hash function. Common: Poseidon (algebraic, efficient in circuits), Rescue, SHA-256.
- **FRI protocol:** the core of STARK verification (Fast Reed-Solomon Interactive Oracle Proof). The number of FRI queries determines soundness. Too few queries = insufficient security bits.
- **Grinding attacks:** the prover may try many nonces to find proofs that pass with fewer queries. The soundness analysis must account for grinding.
- **Fiat-Shamir transform:** STARKs are made non-interactive via Fiat-Shamir. The hash used for Fiat-Shamir must include all protocol messages — missing a message = weak Fiat-Shamir → forgery.

### Audit approach for STARK verifiers

1. Verify FRI parameters (number of queries, expansion factor, folding)
2. Check Fiat-Shamir transcript includes all prover messages
3. Verify the AIR (Algebraic Intermediate Representation) constraints
4. Check that public inputs are committed in the transcript
5. Test with invalid proofs — verifier must reject

## 8. Signature verification via sysvar introspection

### The Ed25519Program + Instructions sysvar pattern

Many Solana programs need to verify signatures not from transaction signers (e.g., off-chain oracle signatures, gasless relay signatures). The pattern:

```
Transaction:
  Instruction 0: Ed25519Program.verify(pubkey, message, signature)
  Instruction 1: YourProgram.process(...)
    → reads Instructions sysvar
    → checks that instruction 0 was Ed25519Program.verify with expected params
```

### Security pitfalls (the Wormhole class)

```rust
// CRITICAL: validate the Instructions sysvar is the REAL sysvar
// Wormhole accepted a fake account as the Instructions sysvar

// BAD:
let instructions_sysvar = &ctx.accounts.instructions;  // unchecked!

// GOOD:
let instructions_sysvar = &ctx.accounts.instructions;
require!(
    *instructions_sysvar.key == solana_program::sysvar::instructions::ID,
    MyError::InvalidSysvar
);

// ALSO GOOD (Anchor handles this):
pub instructions: Sysvar<'info, Instructions>,
```

**Additional checks:**
1. Verify the instruction at the expected index is actually `Ed25519Program`
2. Verify the pubkey in the Ed25519 instruction matches the expected signer
3. Verify the message matches what your program expects
4. Verify there isn't a SECOND Ed25519 instruction that could confuse parsing

### Secp256k1 recovery precompile

Solana also has a Secp256k1 recovery precompile (for Ethereum-compatible signatures). Same introspection pattern, same pitfalls.

```bash
grep -rn "ed25519_program\|Ed25519\|secp256k1\|Secp256k1" programs/*/src/
grep -rn "instructions.*sysvar\|sysvar.*instructions\|load_instruction_at" programs/*/src/
```

## 9. Common cryptographic misuse patterns

### Pattern 1: Homemade randomness
```rust
// BAD: using Clock sysvar for randomness
let random = Clock::get()?.unix_timestamp as u64 % range;
// Validators know the timestamp before the transaction executes

// BAD: using SlotHashes for randomness
// Validators can influence recent hashes

// BETTER: VRF (Switchboard, Orao) or commit-reveal scheme
// BEST: drand or verifiable delay functions
```

### Pattern 2: Missing domain separation
```rust
// BAD: same hash used for different purposes
let auth_hash = hash(user_key);      // for authentication
let data_hash = hash(user_key);      // for data lookup
// These are identical! Cross-purpose confusion.

// GOOD: domain-separate
let auth_hash = hash(b"AUTH" + user_key);
let data_hash = hash(b"DATA" + user_key);
```

### Pattern 3: Nonce reuse in encryption
```rust
// If a program uses encryption (rare on Solana, but seen in privacy protocols):
// Nonce reuse with AES-GCM or ChaCha20-Poly1305 = catastrophic
// Two ciphertexts with same nonce → XOR reveals plaintext
```

### Pattern 4: Timing-unsafe comparisons
```rust
// BAD: short-circuiting comparison on secrets
if computed_hash == expected_hash { ... }
// This leaks information about which byte differs first

// GOOD: constant-time comparison
use subtle::ConstantTimeEq;
if computed_hash.ct_eq(&expected_hash).into() { ... }
```

### Master audit checklist for crypto

```bash
# All crypto-related code
grep -rn "hash\|sign\|verify\|encrypt\|decrypt\|proof\|zk\|random\|nonce" programs/*/src/

# Specific concerns
grep -rn "Clock.*rand\|slot.*rand\|random" programs/*/src/  # bad randomness
grep -rn "==.*hash\|hash.*==" programs/*/src/  # timing-unsafe comparison
grep -rn "Ed25519\|secp256k1\|instructions.*sysvar" programs/*/src/  # sig verification
grep -rn "alt_bn128\|pairing\|groth16" programs/*/src/  # ZK proofs
```
