# Pulse: Scoring Model Review

Date: 2026-09-26
Author: Robert Perez (question), researched with Claude
Status: Recommendation, not built. Hand to Claude Code once you pick a path.

> Robert asked: should the score go above 100 (say 0-999) to be more accurate? Short answer: the ceiling is not the problem, the floor is. Fix the math first; add a bigger second number only if you want it.

---

## What Pulse does today

In `pulse/reports/reporter.py`:
- Start every system at 100 (perfect health).
- Subtract a flat amount per finding: Critical minus 25, High minus 15, Medium minus 8, Low minus 3.
- Floor at 0. Letter grade is a band: 90+ A, 75+ B, 50+ C, 25+ D, under 25 F.
- The newer `calculate_score_from_findings` counts each rule once (good), so 50 brute-force events count as one deduction, not fifty.

## The problem, stated plainly

The flat-subtraction model saturates at the bottom. Four criticals subtract 100 points, so the score is 0 and the grade is F. But a host with forty criticals also lands at 0 and F. Once you bottom out, the number stops carrying information. Two very different situations look identical.

Worked example with today's model (per unique rule):

| Active criticals | Score today | Grade |
|---|---|---|
| 1 | 75 | B |
| 2 | 50 | C |
| 3 | 25 | D |
| 4 | 0 | F |
| 8 | 0 | F |
| 40 | 0 | F |

Rows 4, 8, and 40 are the same score. That is the accuracy gap. Raising the max to 999 does not fix it by itself, because the flat subtraction would still crater a busy host to the floor.

## What the established tools do

- **SecurityScorecard**: 0-100 with A-F letters, same shape as Pulse. It weights findings by severity and by quantity on a logarithmic scale with recency, so more findings always move the score and it does not slam to 0. Their published line: an F-grade org is about 13.8x more likely to be breached than an A.
- **BitSight**: a credit-score-style scale, 250-900, higher is better, three bands (Advanced / Intermediate / Basic). This scale exists to compare one company against a whole population of other companies (a percentile idea). Pulse scores one team's own hosts, not a population, so a credit-style scale adds confusion without adding accuracy for a no-SOC user.
- **FICO credit score**: 300-850. Same point as BitSight: a wide band is for ranking many entities against each other.
- **CVSS**: 0-10, and it rates the severity of one vulnerability, not the health of a system. Useful as a per-finding weight, not as the whole score.

Takeaway: a bigger number is for comparing many things against each other. Pulse's job is to score your own machines and be readable by a junior. So keep the friendly 0-100 grade, and fix why it lies at the bottom.

## Recommendation

Do these in order. Step 1 is the high-value, low-risk fix. Step 2 is optional and satisfies the "bigger number" instinct without breaking the grade.

### Step 1 — Keep 0-100 and A-F, switch to diminishing returns

Instead of subtracting a flat chunk per finding, multiply the remaining health down. Each finding removes a share of what is left, so the score approaches 0 but almost never hits it, and every extra finding still moves the number.

Give each severity a "keep factor" (how much health survives one finding of that severity):

| Severity | Keep factor |
|---|---|
| Critical | 0.72 |
| High | 0.85 |
| Medium | 0.93 |
| Low | 0.97 |

Score = 100 × (product of keep factors for every unique active finding), rounded.

Same worked example, new model:

| Active criticals | New score | Grade |
|---|---|---|
| 1 | 72 | C |
| 2 | 52 | C |
| 3 | 37 | D |
| 4 | 27 | D |
| 8 | 7 | F |
| 40 | ~0 | F |

Now the grade tracks reality: one critical is a bad-but-recoverable C, a handful is a D, many is a deep F, and 8 vs 40 are clearly different scores. Tune the keep factors to taste; lower factor means harsher.

Two more accuracy wins to fold in, both cheap:
- **Recency**: weight a finding by age. A critical from an hour ago should hurt more than one from three weeks ago that is being worked. Multiply its effect by a decay (for example, full weight for 7 days, then fade).
- **Status**: an open, unreviewed finding should weigh full; one already marked resolved should weigh little (say 20%). You already track workflow state, so this is wiring, not new data.

### Step 2 (optional) — Add a separate "exposure" score that climbs

Keep the 0-100 grade for the at-a-glance view. Add a second number that goes up as active threats pile up. Health has a ceiling; threat does not, so this is where a big scale fits.

Exposure = sum over active findings of: severity points × recency weight × status weight.

Suggested severity points (CVSS-flavored): Critical 100, High 40, Medium 15, Low 5. Leave it unbounded internally for accurate trend charts; if you like the look, display it capped at 999 with a "999+" style overflow. Higher is worse.

Why two numbers: the grade answers "how healthy am I" for the exec and the dashboard hero; exposure answers "how much is hitting me right now" for the analyst and the trend line. They are different questions, and one number cannot do both jobs well. This is the honest version of your 0-999 idea.

## What not to do

- Do not just raise 100 to 999 on the current flat-subtraction math. You would keep the saturation bug and lose the intuitive grade.
- Do not flip health to bigger-is-better up to 999. "More than 100% healthy" makes no sense to a user. Bigger-is-better belongs to the exposure score, not health.
- Do not adopt a credit-style percentile scale. That is for ranking many companies; Pulse scores one team's own hosts.

## Suggested build path

1. Change `calculate_score_from_findings` in `pulse/reports/reporter.py` to the multiplicative keep-factor model. Keep the A-F bands and the return shape so nothing downstream breaks.
2. Add recency and status weighting to each finding's effect.
3. Update the tests that pin the old flat numbers (there will be several) and add cases for the 8-vs-40 distinction so the saturation fix is locked in.
4. Optional: add an `exposure` field to the score result and surface it as a second stat on the dashboard and a second trend line.

## Sources

- [How SecurityScorecard calculates your scores](https://support.securityscorecard.com/hc/en-us/articles/8366223642651-How-SecurityScorecard-calculates-your-scores)
- [What is a BitSight Security Rating? (250-900 scale)](https://help.bitsighttech.com/hc/en-us/articles/231352528-What-is-a-Bitsight-Security-Rating)
- [Cybersecurity posture rating explained — Panorays](https://panorays.com/cyber-posture-rating-explained/)
- [Cybersecurity rating scales explained — FortifyData](https://fortifydata.com/insights/cybersecurity-rating-scale-explained)
