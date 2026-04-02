# Supply Chain & Social Engineering (§19)

Dependency poisoning, insider threats, phishing, client-side leaks, and wallet simulation blind spots.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §19 — Social engineering and supply chain attacks

**What:** Attacks that compromise the human or toolchain layer rather than the smart contract itself. This includes compromised npm/crate dependencies, malicious developer hires, phishing of team members, and exploitation of CI/CD pipelines.

**Why this belongs in a smart contract audit:** Because the most expensive Solana exploits of 2024-2026 were NOT smart contract bugs. Slope ($4.5M), @solana/web3.js (unknown), Solareum (unknown), and arguably Resolv ($25M) all involved infrastructure and supply chain compromise. An auditor who only reviews on-chain code misses the most likely attack vectors.

**Sub-classes:**
- **Dependency poisoning:** malicious versions of legitimate packages published to npm/crates.io (e.g., @solana/web3.js backdoor)
- **Insider threat:** compromised or malicious team member with access to keys, repos, or infrastructure (e.g., Solareum's alleged DPRK developer)
- **Phishing/social engineering:** team members targeted to reveal keys, seed phrases, or access credentials
- **Client-side secret leakage:** wallet or frontend code that logs, transmits, or stores secrets (e.g., Slope's Sentry integration)
- **CI/CD compromise:** build pipeline manipulation that injects malicious code into deployments
- **Nation-state insider threat (NEW — Solareum 2025):** state-sponsored actors (confirmed DPRK) infiltrating DeFi teams as developers. They gain access to repos, infrastructure, and user-facing systems, then exploit private keys or inject backdoors. This is not hypothetical — it has happened on Solana.
- **Wallet simulation blind spots (NEW — Dec 2025):** Solana's account ownership model allows transactions that reassign account control without moving tokens. Wallet UIs that only simulate token transfers show these as "safe." Phishing attacks craft ownership-transfer transactions that look benign in simulation. Protocols requiring complex user signatures inherit this risk.

**Detection (for protocol-level audits):**
```bash
# Dependency hygiene
npm audit 2>&1 || cargo audit 2>&1
# Check: are dependencies version-pinned with lockfiles?
grep -rn "\"\\^" package.json  # caret ranges = auto-update risk
# Check: is there a lockfile (package-lock.json, Cargo.lock) committed?

# Secret handling in client code (if in scope)
grep -rn "mnemonic\|seed_phrase\|private_key\|secret_key" src/ | grep -v test
grep -rn "console.log\|sentry\|datadog\|logger" src/ | grep -i "key\|secret\|seed"

# Build verification
# Check: does the protocol publish verified builds?
# Check: can the deployed binary be matched to audited source?
anchor verify <PROGRAM_ID> --provider.cluster mainnet
```

**Audit recommendations:**
- Flag any protocol where deployed code cannot be verified against audited source
- Check if the project uses dependency version pinning and integrity hashes
- Review client-side code for secret leakage if the frontend is in scope
- Ask about team OPSEC: multisig for deploys, hardware wallets for authority keys, access controls on cloud infrastructure
- Flag protocols where user transactions include non-obvious instructions (ownership transfers, delegation) that wallet simulations may not surface
- For teams: ask about developer vetting processes, especially for remote hires with access to infrastructure or keys

**Severity:** VARIES — can be CRITICAL. Slope drained 9,200 wallets. Supply chain attacks scale to every user of the compromised dependency. Nation-state actors are confirmed active in the Solana ecosystem.
