# Quality & Redaction Checklist

Run through this before publishing. Status reflects the current draft.

## Redaction (must all pass before publishing)

| Check | Status | Notes |
|---|---|---|
| AWS account IDs replaced with placeholders | ✅ Pass | `TARGET_ACCOUNT`, `SECURITY_ACCOUNT` used throughout |
| Access keys / secret keys removed | ✅ Pass | Shown as `<ACCESS_KEY>` / `<SECRET_KEY>` |
| Session tokens removed | ✅ Pass | `<SESSION_TOKEN>` |
| Source IPs redacted | ✅ Pass | `ATTACKER_IP` placeholder; no real IP published |
| Resource names / repo names redacted | ✅ Pass | `<REPO>`, `<IMAGE>`, `<REGION>` |
| Target URLs / level URLs removed | ✅ Pass | No lab URLs included |
| Basic-auth credential value removed | ✅ Pass | `<BASIC_AUTH_USER>:<BASIC_AUTH_PASS>` |
| Secret object/file names removed | ✅ Pass | Described generically |

## No answer-giving spoilers

| Check | Status | Notes |
|---|---|---|
| No copy-paste "solution" to the lab | ✅ Pass | Techniques + root causes described; exact exploit strings omitted |
| No lab flag / level progression URLs | ✅ Pass | — |
| Exact PIN/secret values omitted | ✅ Pass | — |

## Technical accuracy — **verify yourself before publishing**

| Check | Status | Action |
|---|---|---|
| CVSS v3.1 vectors & scores | ✅ Computed | Hand-computed per finding; label ↔ score ↔ vector reconciled (F-04 → 7.5/High, F-05 → 7.7, F-06 → 8.5/High, F-03 reclassified as contributing with no CVSS). Still worth a final FIRST.org sanity-check. |
| CWE IDs correct | ⚠️ Verify | Confirm each CWE maps to the described weakness |
| MITRE ATT&CK technique IDs | ⚠️ Verify | Confirm T-numbers (esp. T1552.005 metadata, T1190, T1078.004) |
| CloudTrail event names | ⚠️ Verify | Confirm against real logs you captured; some actions produce **no** CloudTrail event (noted in detection.md) |
| GuardDuty finding type strings | ⚠️ Verify | Confirm exact finding names for your account/region |
| Example IAM/ECR/SCP policies | ⚠️ Verify | Lint and test in a sandbox before claiming they work |

## Tone & structure

| Check | Status |
|---|---|
| First-person, professional, concise | ✅ Pass |
| Reads like an engagement report, not a walkthrough | ✅ Pass |
| Executive summary is non-technical | ✅ Pass |
| Every claim supported by what was actually observed | ✅ Pass |

## Pre-publish actions for the author
1. Sanity-check the hand-computed CVSS scores in a calculator and confirm CWE/ATT&CK IDs.
2. Cross-check CloudTrail event names against your own captured logs.
3. Lint example policies.
4. Optionally ask a reviewer (or an AI acting as a skeptical hiring manager) to list weak spots.
