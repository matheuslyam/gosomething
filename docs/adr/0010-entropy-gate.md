# ADR 0010: entropy double verification (phase 2)

## Status

Accepted.

## Context

Phase 1 named patterns cannot see prefixless secrets (AWS secret without
label, bare base64 runs, unquoted dotenv values, long hex). Raw entropy
over bundle text is a false-positive factory (hashes, UUIDs, prose), so
the approved design is shape-first, entropy-second, always-on, zero FP.

## Decision

`internal/secrets/entropy.go`: four prefixless collectors (AWS-40,
base64≥32, `KEY=value` dotenv, hex-32+) confirm via per-character Shannon
entropy; single `HighEntropy` finding name; named patterns always win
overlapping spans (no double report); masking/`--reveal`/JSON unchanged.

Measured thresholds (TestEntropyCalibration locks each with ≥0.3 margin):

| Rule | T | minPos | maxNeg |
|---|---|---|---|
| aws40 | 4.4 | 4.503 | 3.322 |
| base64 | 4.2 | 4.414 | 3.322 |
| dotenv | 4.4 | 4.534 | 4.000 |
| hex | 3.0 | 3.533 | 2.156 |

## Consequences

Two calibration-proven deviations from the naive design (both fail loud
if reverted):

1. **Weak context required** for aws40/base64/hex (dotenv carries its own
   `KEY=` shape). Proof: bare random-40 (H~4.8) and bare base64-English
   (H~5.0) overlap fully — no threshold separates them, so bare matching
   at zero FP is impossible. Context is measured OUTSIDE the candidate
   span (base64 `==` padding must not fake an assignment signal).
2. **Known residuals fire by design**: high-entropy English beside an
   assignment, and md5-with-assignment, are indistinguishable from tokens
   without decoding (Shannon is order-blind). Asserted firing in tests,
   never smuggled into the silence set. A base64-decode oracle is future
   work, not this phase.

Corpus: deterministic (`math/rand` fixed per-test seeds, no committed
secrets — push-protection convention), 24 positives / 34 negatives
(21 shape-valid lock + 13 line-level). Hex relies on context because an
md5/UUID has exactly a token's entropy. Unquoted dotenv values under ~28
chars stay silent (floor 12 + T 4.4 implies effective ~28+).

Discarded: single pooled threshold (WHY: English-60 at 4.97 sits inside
the positive band — pooled locking can never go green); entropy as
primary detector (WHY: FP factory); per-class finding names (WHY: same
triage action, prefix visible in mask).
