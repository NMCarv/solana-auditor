# Economic & Oracle Manipulation (§16)

Oracle attacks, flash loans, slow poisoning, fake token collateral, and composability cascades.
For the condensed lookup table, see `../cheatsheet.md`.

---

## §16 — Economic / oracle manipulation

**What:** The program's economic design can be exploited through oracle manipulation, flash loans, or market condition gaming — even if the code is technically correct.

**Sub-classes:**
- **Stale oracle prices:** price feed hasn't updated, attacker trades against known-stale price
- **Single-source oracle:** one oracle = one point of manipulation
- **Flash loan attacks:** borrow → manipulate → profit → repay in one tx
- **Price impact ignorance:** AMM price after a large swap differs from spot price
- **Liquidity assumptions:** protocol assumes liquidity that doesn't exist
- **Sandwich attacks:** front-run user tx, extract value, back-run
- **Slow oracle poisoning (NEW — Drift 2026):** attacker builds fake but stable price history over weeks by wash-trading a worthless token with ~$500 of liquidity. After weeks of fabricated history, the token passes all TWAP, confidence, and staleness checks. This evades every fast-manipulation defense. Detection requires checking oracle history depth vs. actual market depth/liquidity.
- **Fake token as collateral (NEW — Drift, Cetus):** attacker creates a worthless token, manufactures its price via oracle poisoning or AMM math exploits, then uses it as collateral to borrow real assets. Programs that accept arbitrary mints as collateral without minimum liquidity/history requirements are vulnerable.
- **Composability cascade (NEW — Resolv 2026):** a single protocol's token depeg cascades through all protocols that integrated it. Resolv's USR depeg caused bad debt across 15+ Morpho vaults. Automated liquidity services continued operating hours after the exploit. Auditors should assess: what happens to THIS protocol if any upstream token it depends on loses its peg?

**Detection:**
```bash
grep -rn "price\|oracle\|pyth\|switchboard\|chainlink" programs/*/src/
# Check: is staleness validated?
grep -rn "timestamp\|slot\|stale\|max_age" programs/*/src/
# Check: TWAP vs spot price
# Check: confidence interval handling

# Slow oracle poisoning / fake token collateral
# Check: does the program accept arbitrary mints as collateral?
grep -rn "collateral.*mint\|deposit_mint\|accepted_mint" programs/*/src/
# Check: is there a minimum oracle history depth or liquidity requirement?
# Check: is there an allowlist of accepted collateral tokens?
# Check: can admin list new collateral tokens without timelock?
```

**Fix:**
- Validate oracle staleness (max age in slots or seconds)
- Use TWAP or confidence intervals, not raw spot prices
- Implement slippage protection
- Consider flash loan resistance (check if position existed before current tx)
- Use multiple oracle sources with fallback logic
- For collateral: require minimum oracle history depth AND minimum on-chain liquidity
- For collateral: use an allowlist with timelocked additions, not permissionless listing
- For composability: assess upstream token peg dependencies and implement circuit breakers

**Severity:** VARIES — can be CRITICAL (Mango: $110M, Drift: $285M) or LOW (minor MEV).
